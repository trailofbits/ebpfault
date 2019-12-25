#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.1)

# This directory also takes care of the toolchain configuration
# so we have to include it before our project() declaration
add_subdirectory("libraries")

project("ebpfault")

include("cmake/options.cmake")

function(ebpfault)
  add_executable(ebpfault
    src/main.cpp

    src/faultinjector.h
    src/faultinjector.cpp

    src/utils.h
    src/utils.cpp

    src/configuration.h
    src/configuration.cpp
  )

  target_link_libraries(ebpfault PRIVATE
    thirdparty_rapidjson
    thirdparty_cli11

    ebpf
    error
    utils
  )

  if(EBPFAULT_ENABLE_INSTALL)
    install(TARGETS ebpfault DESTINATION "bin")
  endif()
endfunction()

ebpfault()
