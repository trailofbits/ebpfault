/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "faultinjector.h"
#include "utils.h"

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>

#include <tob/ebpf/ebpf_utils.h>
#include <tob/ebpf/llvm_utils.h>

namespace tob::ebpfault {
struct FaultInjector::PrivateData final {
  PrivateData(ebpf::PerfEventArray &perf_event_array_)
      : perf_event_array(perf_event_array_) {}

  ebpf::PerfEventArray &perf_event_array;

  ProcessIDFilter filter;
  Configuration::SyscallFault config;

  llvm::LLVMContext context;
  std::unique_ptr<llvm::Module> module;

  utils::UniqueFd event_fd;
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

  // Create the event first, so we know whether the given system call exists or
  // not
  auto syscall_name = "__x64_sys_" + d->config.name;

  auto event_fd_exp = ebpf::createKprobeEvent(false, syscall_name, 0, -1);
  if (!event_fd_exp.succeeded()) {
    throw event_fd_exp.error();
  }

  d->event_fd = event_fd_exp.takeValue();

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

  // Generate the pt_regs structure
  std::vector<llvm::Type *> type_list(21U, llvm::Type::getInt64Ty(d->context));

  auto pt_regs_struct = llvm::StructType::create(type_list, "pt_regs", true);

  if (pt_regs_struct == nullptr) {
    return StringError::create("Failed to create the pt_regs structure type");
  }

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
  function->arg_begin()->setName("ctx");

  auto entry_bb = llvm::BasicBlock::Create(d->context, "entry", function);

  // Generate the PID filtering logic
  llvm::IRBuilder<> builder(d->context);
  builder.SetInsertPoint(entry_bb);

  auto current_pid_tgid = bpf_get_current_pid_tgid(builder);

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
    auto gen_status = generateFaultSelector(builder);
    if (gen_status.failed()) {
      return gen_status.error();
    }

    builder.SetInsertPoint(ignore_syscall_bb);
  }

  // Terminate the function
  builder.CreateRet(builder.getInt64(0));

  return {};
}

SuccessOrStringError
FaultInjector::generateFaultSelector(llvm::IRBuilder<> &builder) {
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

  auto random_u32_value = bpf_get_prandom_u32(builder);

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

    bpf_override_return(builder, current_function->arg_begin(),
                        builder.getInt64(fault.exit_code));

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
  auto linux_version_code_exp = ebpf::getLinuxKernelVersionCode();
  if (!linux_version_code_exp.succeeded()) {
    return linux_version_code_exp.error();
  }

  auto linux_version_code = linux_version_code_exp.takeValue();

  auto program_fd_exp = ebpf::loadProgram(
      bpf_program, d->event_fd.get(), BPF_PROG_TYPE_KPROBE, linux_version_code);

  if (!program_fd_exp.succeeded()) {
    throw program_fd_exp.error();
  }

  d->program_fd = program_fd_exp.takeValue();
  return {};
}

void FaultInjector::bpf_override_return(llvm::IRBuilder<> &builder,
                                        llvm::Value *context,
                                        llvm::Value *exit_code) {
  // clang-format off
  auto function_type = llvm::FunctionType::get(
    llvm::Type::getInt64Ty(d->context),

    {
      // Context
      llvm::Type::getInt64PtrTy(d->context),

      // New exit code
      llvm::Type::getInt64Ty(d->context)
    },

    false
  );
  // clang-format on

  auto function =
      builder.CreateIntToPtr(builder.getInt64(BPF_FUNC_override_return),
                             llvm::PointerType::getUnqual(function_type));

  builder.CreateCall(function, {context, exit_code});
}

llvm::Value *
FaultInjector::bpf_get_current_pid_tgid(llvm::IRBuilder<> &builder) {
  // clang-format off
  auto function_type = llvm::FunctionType::get(
    llvm::Type::getInt64Ty(d->context),
    { },
    false
  );
  // clang-format on

  auto function =
      builder.CreateIntToPtr(builder.getInt64(BPF_FUNC_get_current_pid_tgid),
                             llvm::PointerType::getUnqual(function_type));

  return builder.CreateCall(function, {});
}

llvm::Value *FaultInjector::bpf_get_prandom_u32(llvm::IRBuilder<> &builder) {
  // clang-format off
  auto function_type = llvm::FunctionType::get(
    llvm::Type::getInt32Ty(d->context),
    { },
    false
  );
  // clang-format on

  auto function =
      builder.CreateIntToPtr(builder.getInt64(BPF_FUNC_get_prandom_u32),
                             llvm::PointerType::getUnqual(function_type));

  return builder.CreateCall(function, {});
}
} // namespace tob::ebpfault
