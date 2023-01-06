/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "faultinjector.h"
#include "utils.h"

#include <iostream>

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>

#include <tob/ebpf/ebpf_utils.h>
#include <tob/ebpf/ievent.h>
#include <tob/ebpf/llvm_utils.h>

namespace tob::ebpfault {

namespace {

//
// Register list. Make sure that the order is the same as the
// struct pt_regs definition!
//

const std::vector<std::string> kRegisterList {
#if __x86_64__
  "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax",
      "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss"

#elif __arm__ || __aarch64__
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
      "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21",
      "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29", "r30", "sp", "pc",
      "pstate"

#else
#error Unsupported architecture
#endif
};

} // namespace

struct FaultInjector::PrivateData final {
  PrivateData(ebpf::PerfEventArray &perf_event_array_)
      : perf_event_array(perf_event_array_) {}

  ebpf::PerfEventArray &perf_event_array;
  std::uint32_t event_data_size{0U};

  ProcessIDFilter filter;
  Configuration::SyscallFault config;

  llvm::LLVMContext context;
  std::unique_ptr<llvm::Module> module;

  ebpf::IEvent::Ref kprobe_event;
  utils::UniqueFd program_fd;
};

StringErrorOr<FaultInjector::Ref>
FaultInjector::create(ebpf::PerfEventArray &perf_event_array,
                      const Configuration::SyscallFault &config,
                      const ProcessIDFilter &filter) {

  try {
    return Ref(new FaultInjector(perf_event_array, config, filter));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

FaultInjector::~FaultInjector() {}

std::uint64_t FaultInjector::eventIdentifier() const {
  return static_cast<std::uint64_t>(d->kprobe_event->fd());
}

std::vector<FaultInjector::EventData>
FaultInjector::parseEventData(utils::BufferReader &buffer_reader,
                              ebpf::PerfEventArray::BufferList &&buffer_list) {

  std::vector<FaultInjector::EventData> event_data_list;

  for (const auto &buffer : buffer_list) {
    buffer_reader.reset(buffer);
    buffer_reader.skipBytes(tob::ebpf::kPerfEventHeaderSize +
                            sizeof(std::uint32_t));

    EventData event_data{};

    try {
      event_data.timestamp = buffer_reader.u64();
      event_data.event_id = buffer_reader.u64();
      event_data.process_id = buffer_reader.u32();
      event_data.thread_id = buffer_reader.u32();
      event_data.injected_error = buffer_reader.u64();

      for (const auto &register_name : kRegisterList) {
        auto register_value = buffer_reader.u64();
        event_data.register_map.insert({register_name, register_value});
      }

      event_data_list.push_back(std::move(event_data));

    } catch (...) {
      std::cerr
          << "Failed to read the current event. Skipping to the next one...\n";
    }

    event_data = {};
  }

  return event_data_list;
}

FaultInjector::FaultInjector(ebpf::PerfEventArray &perf_event_array,
                             const Configuration::SyscallFault &config,
                             const ProcessIDFilter &filter)
    : d(new PrivateData(perf_event_array)) {

  d->config = config;
  d->filter = filter;

  // Make sure the fault settings do not go above 100% probability
  std::uint8_t sum{0U};

  for (const auto &fault : d->config.error_list) {
    sum += fault.probability;
  }

  if (sum == 0U || sum > 100U) {
    throw StringError::create("Fault configuration exceeds 100% probability");
  }

  std::string arch;
#if __x86_64__
  arch = "x64";
#elif __arm__ || __aarch64__
  arch = "arm64";
#else
  throw StringError::create(
      "The current architecture is not valid. Supported: arm or x86_64.");
#endif

  // Create the event first, so we know whether the given system call exists or
  // not
  auto syscall_name = "__" + arch + "_sys_" + d->config.name;

  auto kprobe_event_exp =
      ebpf::IEvent::createKprobe(syscall_name, false, false);

  if (!kprobe_event_exp.succeeded()) {
    throw kprobe_event_exp.error();
  }

  d->kprobe_event = kprobe_event_exp.takeValue();

  // Generate the program, compile it, then load it
  auto program_status = generateBPFProgram();
  if (program_status.failed()) {
    throw program_status.error();
  }

  program_status = loadBPFProgram();
  if (program_status.failed()) {
    throw program_status.error();
  }
}

SuccessOrStringError FaultInjector::generateBPFProgram() {
  d->module =
      ebpf::createLLVMModule(d->context, d->config.name + "_FaultInjector");

  // Get the pt_regs structure for our processor
  auto pt_regs_struct_exp =
      ebpf::getPtRegsStructure(*d->module.get(), "pt_regs");

  if (!pt_regs_struct_exp.succeeded()) {
    return pt_regs_struct_exp.error();
  }

  auto pt_regs_struct = pt_regs_struct_exp.takeValue();

  // Generate the event data structure (timestamp + event_id + (pid/tgid) +
  // injected error + pt_regs)
  std::vector<llvm::Type *> event_data_type_list(
      4U, llvm::Type::getInt64Ty(d->context));

  event_data_type_list.push_back(pt_regs_struct);

  auto event_data_struct =
      llvm::StructType::create(event_data_type_list, "EventData", true);

  if (event_data_struct == nullptr) {
    return StringError::create(
        "Failed to create the event data structure type");
  }

  d->event_data_size = static_cast<std::uint32_t>(
      ebpf::getTypeSize(*d->module.get(), event_data_struct));

  // Create the entry point function
  auto function_type =
      llvm::FunctionType::get(llvm::Type::getInt64Ty(d->context),
                              {pt_regs_struct->getPointerTo()}, false);

  auto function =
      llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
                             "on_" + d->config.name, d->module.get());

  if (function == nullptr) {
    return StringError::create("Failed to create the syscall event function");
  }

  auto section_name = d->config.name + "_section";

  function->setSection(section_name);

  auto kprobe_context = function->arg_begin();
  kprobe_context->setName("ctx");

  auto entry_bb = llvm::BasicBlock::Create(d->context, "entry", function);

  // Allocate space for the event data
  llvm::IRBuilder<> builder(entry_bb);

  auto event_data = builder.CreateAlloca(event_data_struct);

  // Generate the PID filtering logic
  auto bpf_syscall_interface_exp =
      tob::ebpf::BPFSyscallInterface::create(builder);

  if (!bpf_syscall_interface_exp.succeeded()) {
    return bpf_syscall_interface_exp.error();
  }

  auto bpf_syscall_interface = bpf_syscall_interface_exp.takeValue();

  auto current_pid_tgid = bpf_syscall_interface->getCurrentPidTgid();

  auto current_tgid =
      builder.CreateBinOp(llvm::Instruction::And, current_pid_tgid,
                          builder.getInt64(0x00000000FFFFFFFFU));

  for (const auto &process_id : d->filter.process_id_list) {
    auto process_id_value =
        builder.getInt64(static_cast<std::uint64_t>(process_id));

    auto check_pid_condition =
        builder.CreateICmpEQ(process_id_value, current_tgid);

    auto basic_block_name = "pid_condition_" + std::to_string(process_id);

    auto ignore_syscall_bb = llvm::BasicBlock::Create(
        d->context, basic_block_name + "ignore", function);

    basic_block_name = "pid_differs_" + std::to_string(process_id);

    auto fail_syscall_bb = llvm::BasicBlock::Create(
        d->context, basic_block_name + "fail", function);

    if (d->filter.type == ProcessIDFilter::Type::Except) {
      builder.CreateCondBr(check_pid_condition, ignore_syscall_bb,
                           fail_syscall_bb);
    } else {
      builder.CreateCondBr(check_pid_condition, fail_syscall_bb,
                           ignore_syscall_bb);
    }

    builder.SetInsertPoint(fail_syscall_bb);
    auto gen_status = generateFaultSelector(
        builder, *bpf_syscall_interface.get(), event_data, kprobe_context);

    if (gen_status.failed()) {
      return gen_status.error();
    }

    builder.SetInsertPoint(ignore_syscall_bb);
  }

  // Terminate the function
  builder.CreateRet(builder.getInt64(0));

  return {};
}

SuccessOrStringError FaultInjector::generateFaultSelector(
    llvm::IRBuilder<> &builder,
    ebpf::BPFSyscallInterface &bpf_syscall_interface, llvm::Value *event_data,
    llvm::Value *pt_regs) {

  struct FaultRange final {
    std::uint8_t start{0U};
    std::uint8_t end{0U};
    std::uint64_t exit_code{0U};
    bool succeed{false};
  };

  std::vector<FaultRange> fault_range;
  std::uint8_t base{0U};

  for (const auto &fault : d->config.error_list) {
    FaultRange range = {};
    range.start = base;
    range.end = base + fault.probability;
    range.exit_code = fault.exit_code;
    range.succeed = false;

    fault_range.push_back(std::move(range));
    base += fault.probability;
  }

  auto current_basic_block = builder.GetInsertBlock();
  auto current_function = current_basic_block->getParent();

  auto random_u32_value = bpf_syscall_interface.getPrandomU32();

  random_u32_value = builder.CreateBinOp(
      llvm::Instruction::URem, random_u32_value, builder.getInt32(100));

  std::size_t counter{0U};

  for (const auto &fault : fault_range) {
    auto greater_or_equal_cond =
        builder.CreateICmpUGE(random_u32_value, builder.getInt32(fault.start));

    greater_or_equal_cond = builder.CreateIntCast(greater_or_equal_cond,
                                                  builder.getInt32Ty(), false);

    auto less_than_cond = builder.CreateICmpSLT(
        random_u32_value, builder.getInt32(fault.start + fault.end));

    less_than_cond =
        builder.CreateIntCast(less_than_cond, builder.getInt32Ty(), false);

    auto condition_sum = builder.CreateBinOp(
        llvm::Instruction::Add, greater_or_equal_cond, less_than_cond);

    auto inside_range_cond =
        builder.CreateICmpEQ(condition_sum, builder.getInt32(2U));

    auto fail_syscall_bb = llvm::BasicBlock::Create(
        d->context, "fail_syscall_with_" + std::to_string(fault.exit_code),
        current_function);

    auto continue_bb = llvm::BasicBlock::Create(
        d->context, "continue_" + std::to_string(++counter), current_function);

    builder.CreateCondBr(inside_range_cond, fail_syscall_bb, continue_bb);

    builder.SetInsertPoint(fail_syscall_bb);

    // Populate the event data structure (timestamp + event_id + (pid/tgid) +
    // injected error + pt_regs)

    // Timestamp
    auto timestamp = bpf_syscall_interface.ktimeGetNs();

    auto event_data_field_ptr = builder.CreateGEP(
        event_data, {builder.getInt32(0), builder.getInt32(0U)});

    builder.CreateStore(timestamp, event_data_field_ptr);

    // Event identifier
    event_data_field_ptr = builder.CreateGEP(
        event_data, {builder.getInt32(0), builder.getInt32(1U)});

    builder.CreateStore(builder.getInt64(eventIdentifier()),
                        event_data_field_ptr);

    // Thread id + process id
    auto pid_tgid = bpf_syscall_interface.getCurrentPidTgid();

    event_data_field_ptr = builder.CreateGEP(
        event_data, {builder.getInt32(0), builder.getInt32(2U)});

    builder.CreateStore(pid_tgid, event_data_field_ptr);

    // Injected error code
    event_data_field_ptr = builder.CreateGEP(
        event_data, {builder.getInt32(0), builder.getInt32(3U)});

    builder.CreateStore(builder.getInt64(fault.exit_code),
                        event_data_field_ptr);

    // pt_regs structure
    auto &module = *fail_syscall_bb->getModule();

    auto pt_regs_type = module.getTypeByName("pt_regs");
    auto pt_regs_member_count =
        static_cast<std::uint32_t>(pt_regs_type->getNumElements());

    for (std::uint32_t i = 0U; i < pt_regs_member_count; ++i) {
      auto reg_value_ptr = builder.CreateGEP(
          pt_regs, {builder.getInt32(0), builder.getInt32(i)});

      auto reg_value = builder.CreateLoad(reg_value_ptr);

      auto reg_dest_ptr = builder.CreateGEP(
          event_data,
          {builder.getInt32(0), builder.getInt32(4U), builder.getInt32(i)});

      builder.CreateStore(reg_value, reg_dest_ptr);
    }

    bpf_syscall_interface.perfEventOutput(pt_regs, d->perf_event_array.fd(),
                                          event_data, d->event_data_size);

    bpf_syscall_interface.overrideReturn(current_function->arg_begin(),
                                         fault.exit_code);

    builder.CreateRet(builder.getInt64(0));

    builder.SetInsertPoint(continue_bb);
  }

  builder.CreateRet(builder.getInt64(0));

  return {};
}

SuccessOrStringError FaultInjector::loadBPFProgram() {
  // Compile the program
  auto &module = *d->module.get();

  auto bpf_program_map_exp = ebpf::compileModule(module);
  if (!bpf_program_map_exp.succeeded()) {
    return bpf_program_map_exp.error();
  }

  auto bpf_program_map = bpf_program_map_exp.takeValue();

  auto section_name = d->config.name + "_section";
  auto bpf_program_it = bpf_program_map.find(section_name);
  if (bpf_program_it == bpf_program_map.end()) {
    return StringError::create("Failed to compile the BPF function");
  }

  auto &bpf_program = bpf_program_it->second;

  // Load the program
  auto program_fd_exp = ebpf::loadProgram(bpf_program, *d->kprobe_event.get());
  if (!program_fd_exp.succeeded()) {
    throw program_fd_exp.error();
  }

  d->program_fd = program_fd_exp.takeValue();
  return {};
}
} // namespace tob::ebpfault
