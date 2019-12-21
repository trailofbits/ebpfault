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

#include <tob/ebpf/perfeventarray.h>
#include <tob/error/error.h>

namespace tob::ebpfault {
class FaultInjector final {
public:
  struct ProcessIDFilter final {
    enum class Type { Matching, Except };

    Type type{Type::Matching};
    std::vector<int> process_id_list;
  };

  using Ref = std::unique_ptr<FaultInjector>;
  static StringErrorOr<Ref> create(ebpf::PerfEventArray &perf_event_array,
                                   const Configuration::SyscallFault &config,
                                   const ProcessIDFilter &filter);

  ~FaultInjector();

  FaultInjector(const FaultInjector &) = delete;
  FaultInjector &operator=(const FaultInjector &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  FaultInjector(ebpf::PerfEventArray &perf_event_array,
                const Configuration::SyscallFault &config,
                const ProcessIDFilter &filter);

  SuccessOrStringError generateBPFProgram();

  SuccessOrStringError generateFaultSelector(llvm::IRBuilder<> &builder);

  SuccessOrStringError loadBPFProgram();

  void bpf_override_return(llvm::IRBuilder<> &builder, llvm::Value *context,
                           llvm::Value *exit_code);

  llvm::Value *bpf_get_current_pid_tgid(llvm::IRBuilder<> &builder);
  llvm::Value *bpf_get_prandom_u32(llvm::IRBuilder<> &builder);
};
} // namespace tob::ebpfault
