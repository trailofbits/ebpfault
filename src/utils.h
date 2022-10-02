/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <tob/error/stringerror.h>

namespace tob::ebpfault {
struct CommandLineParameters final {
  std::string configuration_path;

  bool except_pid_list{false};
  std::optional<std::vector<int>> opt_pid_list;

  std::optional<std::vector<std::string>> opt_exec_command_line;
};

tob::StringErrorOr<CommandLineParameters> parseCommandLine(int argc,
                                                           char *argv[]);

std::string describeFaultValue(std::uint64_t fault_value);
bool configureRlimit();
} // namespace tob::ebpfault
