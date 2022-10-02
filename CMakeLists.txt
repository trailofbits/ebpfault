#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.1)

project("ebpfault")

include("cmake/options.cmake")
include("cmake/settings.cmake")

add_executable(ebpfault
  src/main.cpp

  src/faultinjector.h
  src/faultinjector.cpp

  src/utils.h
  src/utils.cpp

  src/configuration.h
  src/configuration.cpp
)

add_subdirectory("libraries")

target_link_libraries(ebpfault PRIVATE
  ebpfault_cxx_settings

  thirdparty_rapidjson
  thirdparty_cli11

  ebpf
  error
  utils
)

if(EBPFAULT_ENABLE_INSTALL)
  install(TARGETS ebpfault DESTINATION "bin")
endif()
