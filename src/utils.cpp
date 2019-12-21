/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "utils.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <unordered_map>

#include <errno.h>
#include <sys/resource.h>

#include <CLI/CLI.hpp>

namespace tob::ebpfault {
namespace {
extern const std::unordered_map<std::uint64_t, std::string> kValueToErrorMap;
}

tob::StringErrorOr<CommandLineParameters> parseCommandLine(int argc,
                                                           char *argv[]) {
  CLI::App application{"ebpfault - eBPF-based syscall fault injector"};

  CommandLineParameters command_line_params;
  auto except_option = application.add_flag(
      "-x,--except-pid-list", command_line_params.except_pid_list,
      "Affect all processes except the ones in the PID filter");

  application
      .add_option("-c,--config", command_line_params.configuration_path,
                  "Fault configuration")
      ->required()
      ->check(CLI::ExistingFile);

  std::vector<int> pid_list;
  application.add_option("-p,--pid_list", pid_list, "Process ID filter")
      ->delimiter(',');

  std::vector<std::string> exec_command_line;
  auto exec_option =
      application
          .add_option("-e,--exec", exec_command_line, "Program to execute")
          ->delimiter(' ');

  exec_option->excludes(except_option);

  try {
    application.parse(argc, argv);

    if (pid_list.empty() == exec_command_line.empty()) {
      return StringError::create(
          "Missing required option: either -p/--pid_list or -e/--exec");
    }

    if (!pid_list.empty()) {
      command_line_params.opt_pid_list = pid_list;
    } else {
      command_line_params.opt_exec_command_line = exec_command_line;
    }

    return command_line_params;

  } catch (const CLI::RuntimeError &e) {
    std::string message{"A runtime error has occurred"};
    message += e.what();

    return StringError::create(message);

  } catch (const CLI::ParseError &e) {
    std::stringstream message;
    application.exit(e, message, message);

    return StringError::create(message.str());
  }
}

std::string describeFaultValue(std::uint64_t fault_value) {
  auto it = kValueToErrorMap.find(fault_value);
  if (it != kValueToErrorMap.end()) {
    return it->second;
  }

  auto modified_fault_value = fault_value * (-1ULL);

  it = kValueToErrorMap.find(modified_fault_value);
  if (it != kValueToErrorMap.end()) {
    return "-" + it->second;
  }

  std::stringstream stream;
  stream << fault_value << " (0x" << std::hex << fault_value << ")";

  return stream.str();
}

bool configureRlimit() {
  struct rlimit rl = {};
  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;

  auto error = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (error != 0) {
    return false;
  }

  return true;
}

namespace {
// clang-format off
const std::unordered_map<std::uint64_t, std::string> kValueToErrorMap = {
  { 1, "EPERM" },
  { 2, "ENOENT" },
  { 3, "ESRCH" },
  { 4, "EINTR" },
  { 5, "EIO" },
  { 6, "ENXIO" },
  { 7, "E2BIG" },
  { 8, "ENOEXEC" },
  { 9, "EBADF" },
  { 10, "ECHILD" },
  { 11, "EAGAIN" },
  { 12, "ENOMEM" },
  { 13, "EACCES" },
  { 14, "EFAULT" },
  { 15, "ENOTBLK" },
  { 16, "EBUSY" },
  { 17, "EEXIST" },
  { 18, "EXDEV" },
  { 19, "ENODEV" },
  { 20, "ENOTDIR" },
  { 21, "EISDIR" },
  { 22, "EINVAL" },
  { 23, "ENFILE" },
  { 24, "EMFILE" },
  { 25, "ENOTTY" },
  { 26, "ETXTBSY" },
  { 27, "EFBIG" },
  { 28, "ENOSPC" },
  { 29, "ESPIPE" },
  { 30, "EROFS" },
  { 31, "EMLINK" },
  { 32, "EPIPE" },
  { 33, "EDOM" },
  { 34, "ERANGE" },
  { 35, "EDEADLK" },
  { 36, "ENAMETOOLONG" },
  { 37, "ENOLCK" },
  { 38, "ENOSYS" },
  { 39, "ENOTEMPTY" },
  { 40, "ELOOP" },
  { 42, "ENOMSG" },
  { 43, "EIDRM" },
  { 44, "ECHRNG" },
  { 45, "EL2NSYNC" },
  { 46, "EL3HLT" },
  { 47, "EL3RST" },
  { 48, "ELNRNG" },
  { 49, "EUNATCH" },
  { 50, "ENOCSI" },
  { 51, "EL2HLT" },
  { 52, "EBADE" },
  { 53, "EBADR" },
  { 54, "EXFULL" },
  { 55, "ENOANO" },
  { 56, "EBADRQC" },
  { 57, "EBADSLT" },
  { 59, "EBFONT" },
  { 60, "ENOSTR" },
  { 61, "ENODATA" },
  { 62, "ETIME" },
  { 63, "ENOSR" },
  { 64, "ENONET" },
  { 65, "ENOPKG" },
  { 66, "EREMOTE" },
  { 67, "ENOLINK" },
  { 68, "EADV" },
  { 69, "ESRMNT" },
  { 70, "ECOMM" },
  { 71, "EPROTO" },
  { 72, "EMULTIHOP" },
  { 73, "EDOTDOT" },
  { 74, "EBADMSG" },
  { 75, "EOVERFLOW" },
  { 76, "ENOTUNIQ" },
  { 77, "EBADFD" },
  { 78, "EREMCHG" },
  { 79, "ELIBACC" },
  { 80, "ELIBBAD" },
  { 81, "ELIBSCN" },
  { 82, "ELIBMAX" },
  { 83, "ELIBEXEC" },
  { 84, "EILSEQ" },
  { 85, "ERESTART" },
  { 86, "ESTRPIPE" },
  { 87, "EUSERS" },
  { 88, "ENOTSOCK" },
  { 89, "EDESTADDRREQ" },
  { 90, "EMSGSIZE" },
  { 91, "EPROTOTYPE" },
  { 92, "ENOPROTOOPT" },
  { 93, "EPROTONOSUPPORT" },
  { 94, "ESOCKTNOSUPPORT" },
  { 95, "EOPNOTSUPP" },
  { 96, "EPFNOSUPPORT" },
  { 97, "EAFNOSUPPORT" },
  { 98, "EADDRINUSE" },
  { 99, "EADDRNOTAVAIL" },
  { 100, "ENETDOWN" },
  { 101, "ENETUNREACH" },
  { 102, "ENETRESET" },
  { 103, "ECONNABORTED" },
  { 104, "ECONNRESET" },
  { 105, "ENOBUFS" },
  { 106, "EISCONN" },
  { 107, "ENOTCONN" },
  { 108, "ESHUTDOWN" },
  { 109, "ETOOMANYREFS" },
  { 110, "ETIMEDOUT" },
  { 111, "ECONNREFUSED" },
  { 112, "EHOSTDOWN" },
  { 113, "EHOSTUNREACH" },
  { 114, "EALREADY" },
  { 115, "EINPROGRESS" },
  { 116, "ESTALE" },
  { 117, "EUCLEAN" },
  { 118, "ENOTNAM" },
  { 119, "ENAVAIL" },
  { 120, "EISNAM" },
  { 121, "EREMOTEIO" },
  { 122, "EDQUOT" },
  { 123, "ENOMEDIUM" },
  { 124, "EMEDIUMTYPE" },
  { 125, "ECANCELED" },
  { 126, "ENOKEY" },
  { 127, "EKEYEXPIRED" },
  { 128, "EKEYREVOKED" },
  { 129, "EKEYREJECTED" },
  { 130, "EOWNERDEAD" },
  { 131, "ENOTRECOVERABLE" },
  { 132, "ERFKILL" },
  { 133, "EHWPOISON" }
};
// clang-format on
} // namespace
} // namespace tob::ebpfault
