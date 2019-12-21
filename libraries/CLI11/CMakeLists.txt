#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.1)

function(ebpfaultLibrariesCLI11)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_cli11 INTERFACE)
  target_include_directories(thirdparty_cli11 SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_cli11 INTERFACE
    cxx_target_settings
  )
endfunction()

ebpfaultLibrariesCLI11()
