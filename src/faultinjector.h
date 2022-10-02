/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "configuration.h"

#include <memory>
#include <unordered_set>

#include <llvm/IR/IRBuilder.h>

#include <tob/ebpf/bpfsyscallinterface.h>
#include <tob/ebpf/perfeventarray.h>

#include <tob/error/stringerror.h>

namespace tob::ebpfault {
class FaultInjector final {
public:
  struct ProcessIDFilter final {
    enum class Type { Matching, Except };

    Type type{Type::Matching};
    std::vector<int> process_id_list;
  };

  struct EventData final {
    std::uint64_t timestamp;
    std::uint64_t event_id;
    std::uint32_t process_id;
    std::uint32_t thread_id;
    std::uint64_t injected_error;
    std::uint64_t r15;
    std::uint64_t r14;
    std::uint64_t r13;
    std::uint64_t r12;
    std::uint64_t rbp;
    std::uint64_t rbx;
    std::uint64_t r11;
    std::uint64_t r10;
    std::uint64_t r9;
    std::uint64_t r8;
    std::uint64_t rax;
    std::uint64_t rcx;
    std::uint64_t rdx;
    std::uint64_t rsi;
    std::uint64_t rdi;
    std::uint64_t orig_rax;
    std::uint64_t rip;
    std::uint64_t cs;
    std::uint64_t eflags;
    std::uint64_t rsp;
    std::uint64_t ss;
  };

  using Ref = std::unique_ptr<FaultInjector>;
  static StringErrorOr<Ref> create(ebpf::PerfEventArray &perf_event_array,
                                   const Configuration::SyscallFault &config,
                                   const ProcessIDFilter &filter);

  ~FaultInjector();

  std::uint64_t eventIdentifier() const;

  FaultInjector(const FaultInjector &) = delete;
  FaultInjector &operator=(const FaultInjector &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  FaultInjector(ebpf::PerfEventArray &perf_event_array,
                const Configuration::SyscallFault &config,
                const ProcessIDFilter &filter);

  SuccessOrStringError generateBPFProgram();

  SuccessOrStringError
  generateFaultSelector(llvm::IRBuilder<> &builder,
                        ebpf::BPFSyscallInterface &bpf_syscall_interface,
                        llvm::Value *event_data, llvm::Value *pt_regs);

  SuccessOrStringError loadBPFProgram();
};
} // namespace tob::ebpfault
