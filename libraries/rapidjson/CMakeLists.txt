#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.1)

function(ebpfaultLibrariesRapidjson)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_rapidjson INTERFACE)
  target_include_directories(thirdparty_rapidjson SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_rapidjson INTERFACE
    cxx_target_settings
  )

  target_compile_definitions(thirdparty_rapidjson INTERFACE
    RAPIDJSON_HAS_STDSTRING=1
  )
endfunction()

ebpfaultLibrariesRapidjson()
