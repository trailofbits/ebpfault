/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "configuration.h"

#include <cstdint>
#include <fstream>
#include <sstream>
#include <unordered_map>

#include <rapidjson/document.h>

#include <tob/error/stringerror.h>

namespace tob::ebpfault {
namespace {
extern const std::unordered_map<std::string, std::uint64_t> kErrnoToValue;

StringErrorOr<std::uint64_t> parseExitCodeValue(const std::string &buffer) {
  if (buffer.empty()) {
    return StringError::create("Error name is empty");
  }

  const char *buffer_ptr{nullptr};
  bool negative_value{false};

  if (buffer.at(0) == '-') {
    buffer_ptr = buffer.c_str() + 1U;
    negative_value = true;

  } else {
    buffer_ptr = buffer.c_str();
  }

  auto it = kErrnoToValue.find(buffer_ptr);
  if (it == kErrnoToValue.end()) {
    return StringError::create("Invalid errno value provided: " + buffer);
  }

  auto value = it->second;
  if (negative_value) {
    value *= -1UL;
  }

  return value;
}
} // namespace

struct Configuration::PrivateData final {
  std::vector<SyscallFault> syscall_fault_list;
};

StringErrorOr<Configuration::Ref>
Configuration::create(const std::string &path) {
  try {
    return Ref(new Configuration(path));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

Configuration::~Configuration() {}

Configuration::IteratorType Configuration::begin() noexcept {
  return d->syscall_fault_list.begin();
}

Configuration::IteratorType Configuration::end() noexcept {
  return d->syscall_fault_list.end();
}

Configuration::ConstIteratorType Configuration::begin() const noexcept {
  return d->syscall_fault_list.begin();
}

Configuration::ConstIteratorType Configuration::end() const noexcept {
  return d->syscall_fault_list.end();
}

Configuration::ConstIteratorType Configuration::cbegin() const noexcept {
  return d->syscall_fault_list.cbegin();
}

Configuration::ConstIteratorType Configuration::cend() const noexcept {
  return d->syscall_fault_list.cend();
}

Configuration::Configuration(const std::string &path) : d(new PrivateData) {
  std::string configuration;

  {
    std::fstream input_file(path);
    if (!input_file) {
      throw StringError::create(
          "Failed to open the following configuration file: " + path);
    }

    std::stringstream buffer;
    buffer << input_file.rdbuf();
    if (!input_file) {
      throw StringError::create(
          "Failed to read the following configuration file: " + path);
    }

    configuration = buffer.str();
  }

  rapidjson::Document document;
  document.Parse(configuration);

  if (document.HasParseError() || !document.IsObject()) {
    throw StringError::create("Invalid configuration format");
  }

  if (!document.HasMember("fault_injectors") ||
      !document["fault_injectors"].IsArray()) {
    throw StringError::create("");
  }

  const auto &fault_injector_list = document["fault_injectors"].GetArray();

  std::vector<SyscallFault> syscall_fault_list;

  for (const auto &fault_injector : fault_injector_list) {
    if (!fault_injector.HasMember("syscall_name") ||
        !fault_injector["syscall_name"].IsString()) {
      throw StringError::create("");
    }

    const auto &syscall_name = fault_injector["syscall_name"].GetString();

    if (!fault_injector.HasMember("error_list") ||
        !fault_injector["error_list"].IsArray()) {
      throw StringError::create("");
    }

    const auto &error_list = fault_injector["error_list"].GetArray();

    SyscallFault syscall_fault = {};
    syscall_fault.name = syscall_name;

    std::size_t probability_sum = 0U;

    for (const auto &error : error_list) {
      if (!error.IsObject()) {
        throw StringError::create("");
      }

      if (!error.HasMember("exit_code")) {
        throw StringError::create("");
      }

      const auto &exit_code = error["exit_code"];
      std::uint64_t exit_code_value = {};

      if (exit_code.IsString()) {
        const auto &exit_code_string = exit_code.GetString();

        auto integer_value_exp = parseExitCodeValue(exit_code_string);
        if (!integer_value_exp.succeeded()) {
          throw integer_value_exp.error();
        }

        exit_code_value = integer_value_exp.takeValue();

      } else if (exit_code.IsNumber()) {
        exit_code_value = static_cast<std::uint64_t>(exit_code.GetInt());

      } else {
        throw StringError::create("");
      }

      if (!error.HasMember("probability") || !error["probability"].IsNumber()) {
        throw StringError::create("");
      }

      auto probability =
          static_cast<std::uint8_t>(error["probability"].GetInt());

      if (probability <= 0 || probability > 100) {
        throw StringError::create("");
      }

      probability_sum += probability;

      if (probability_sum > 100) {
        throw StringError::create("");
      }

      SyscallFault::Error syscall_error = {};
      syscall_error.probability = static_cast<std::uint8_t>(probability);
      syscall_error.exit_code = exit_code_value;

      syscall_fault.error_list.push_back(std::move(syscall_error));
    }

    syscall_fault_list.push_back(std::move(syscall_fault));
  }

  d->syscall_fault_list = std::move(syscall_fault_list);
}

namespace {
const std::unordered_map<std::string, std::uint64_t> kErrnoToValue = {
    {"EPERM", 1},
    {"ENOENT", 2},
    {"ESRCH", 3},
    {"EINTR", 4},
    {"EIO", 5},
    {"ENXIO", 6},
    {"E2BIG", 7},
    {"ENOEXEC", 8},
    {"EBADF", 9},
    {"ECHILD", 10},
    {"EAGAIN", 11},
    {"ENOMEM", 12},
    {"EACCES", 13},
    {"EFAULT", 14},
    {"ENOTBLK", 15},
    {"EBUSY", 16},
    {"EEXIST", 17},
    {"EXDEV", 18},
    {"ENODEV", 19},
    {"ENOTDIR", 20},
    {"EISDIR", 21},
    {"EINVAL", 22},
    {"ENFILE", 23},
    {"EMFILE", 24},
    {"ENOTTY", 25},
    {"ETXTBSY", 26},
    {"EFBIG", 27},
    {"ENOSPC", 28},
    {"ESPIPE", 29},
    {"EROFS", 30},
    {"EMLINK", 31},
    {"EPIPE", 32},
    {"EDOM", 33},
    {"ERANGE", 34},
    {"EDEADLK", 35},
    {"ENAMETOOLONG", 36},
    {"ENOLCK", 37},
    {"ENOSYS", 38},
    {"ENOTEMPTY", 39},
    {"ELOOP", 40},
    {"ENOMSG", 42},
    {"EIDRM", 43},
    {"ECHRNG", 44},
    {"EL2NSYNC", 45},
    {"EL3HLT", 46},
    {"EL3RST", 47},
    {"ELNRNG", 48},
    {"EUNATCH", 49},
    {"ENOCSI", 50},
    {"EL2HLT", 51},
    {"EBADE", 52},
    {"EBADR", 53},
    {"EXFULL", 54},
    {"ENOANO", 55},
    {"EBADRQC", 56},
    {"EBADSLT", 57},
    {"EBFONT", 59},
    {"ENOSTR", 60},
    {"ENODATA", 61},
    {"ETIME", 62},
    {"ENOSR", 63},
    {"ENONET", 64},
    {"ENOPKG", 65},
    {"EREMOTE", 66},
    {"ENOLINK", 67},
    {"EADV", 68},
    {"ESRMNT", 69},
    {"ECOMM", 70},
    {"EPROTO", 71},
    {"EMULTIHOP", 72},
    {"EDOTDOT", 73},
    {"EBADMSG", 74},
    {"EOVERFLOW", 75},
    {"ENOTUNIQ", 76},
    {"EBADFD", 77},
    {"EREMCHG", 78},
    {"ELIBACC", 79},
    {"ELIBBAD", 80},
    {"ELIBSCN", 81},
    {"ELIBMAX", 82},
    {"ELIBEXEC", 83},
    {"EILSEQ", 84},
    {"ERESTART", 85},
    {"ESTRPIPE", 86},
    {"EUSERS", 87},
    {"ENOTSOCK", 88},
    {"EDESTADDRREQ", 89},
    {"EMSGSIZE", 90},
    {"EPROTOTYPE", 91},
    {"ENOPROTOOPT", 92},
    {"EPROTONOSUPPORT", 93},
    {"ESOCKTNOSUPPORT", 94},
    {"EOPNOTSUPP", 95},
    {"EPFNOSUPPORT", 96},
    {"EAFNOSUPPORT", 97},
    {"EADDRINUSE", 98},
    {"EADDRNOTAVAIL", 99},
    {"ENETDOWN", 100},
    {"ENETUNREACH", 101},
    {"ENETRESET", 102},
    {"ECONNABORTED", 103},
    {"ECONNRESET", 104},
    {"ENOBUFS", 105},
    {"EISCONN", 106},
    {"ENOTCONN", 107},
    {"ESHUTDOWN", 108},
    {"ETOOMANYREFS", 109},
    {"ETIMEDOUT", 110},
    {"ECONNREFUSED", 111},
    {"EHOSTDOWN", 112},
    {"EHOSTUNREACH", 113},
    {"EALREADY", 114},
    {"EINPROGRESS", 115},
    {"ESTALE", 116},
    {"EUCLEAN", 117},
    {"ENOTNAM", 118},
    {"ENAVAIL", 119},
    {"EISNAM", 120},
    {"EREMOTEIO", 121},
    {"EDQUOT", 122},
    {"ENOMEDIUM", 123},
    {"EMEDIUMTYPE", 124},
    {"ECANCELED", 125},
    {"ENOKEY", 126},
    {"EKEYEXPIRED", 127},
    {"EKEYREVOKED", 128},
    {"EKEYREJECTED", 129},
    {"EOWNERDEAD", 130},
    {"ENOTRECOVERABLE", 131},
    {"ERFKILL", 132},
    {"EHWPOISON", 133}};
}
} // namespace tob::ebpfault
