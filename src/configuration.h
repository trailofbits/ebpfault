/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <tob/error/stringerror.h>

namespace tob::ebpfault {
class Configuration final {
public:
  struct SyscallFault final {
    struct Error final {
      std::uint64_t exit_code;
      std::uint8_t probability;
    };

    std::string name;
    std::vector<Error> error_list;
  };

  using IteratorType = std::vector<SyscallFault>::iterator;
  using ConstIteratorType = std::vector<SyscallFault>::const_iterator;

  using Ref = std::unique_ptr<Configuration>;
  static StringErrorOr<Ref> create(const std::string &path);

  ~Configuration();

  IteratorType begin() noexcept;
  IteratorType end() noexcept;

  ConstIteratorType begin() const noexcept;
  ConstIteratorType end() const noexcept;

  ConstIteratorType cbegin() const noexcept;
  ConstIteratorType cend() const noexcept;

  Configuration(const Configuration &) = delete;
  Configuration &operator=(const Configuration &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  Configuration(const std::string &path);
};
} // namespace tob::ebpfault
