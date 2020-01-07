#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14)
project("ebpfault")

include("../cmake/version.cmake")

set(EBPFAULT_INSTALL_PATH "" CACHE STRING "This is the path where ebpfault has been installed")
set(PACKAGE_VERSION 1)

string(REPLACE "." ";" EBPFAULT_VERSION_COMPONENTS "${EBPFAULT_VERSION}")
list(GET EBPFAULT_VERSION_COMPONENTS 0 CPACK_PACKAGE_VERSION_MAJOR)
list(GET EBPFAULT_VERSION_COMPONENTS 1 CPACK_PACKAGE_VERSION_MINOR)
list(GET EBPFAULT_VERSION_COMPONENTS 2 CPACK_PACKAGE_VERSION_PATCH)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "ebpfault is an eBPF-based syscall fault injection utility.")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/description.txt")
set(CPACK_PACKAGE_NAME "ebpfault")
set(CPACK_PACKAGE_VENDOR "Trail of Bits")
set(CPACK_PACKAGE_CONTACT "info@trailofbits.com")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://www.trailofbits.com")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${EBPFAULT_VERSION}-${PACKAGE_VERSION}.x86_64")
set(CPACK_PACKAGE_RELOCATABLE ON)

set(CPACK_DEBIAN_PACKAGE_RELEASE "${PACKAGE_VERSION}")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
set(CPACK_DEBIAN_PACKAGE_SECTION "default")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>=2.12)")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "${CPACK_PACKAGE_HOMEPAGE_URL}")

set(CPACK_RPM_PACKAGE_RELEASE_DIST "${PACKAGE_VERSION}")
set(CPACK_RPM_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION_SUMMARY}")
set(CPACK_RPM_PACKAGE_GROUP "default")
set(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.12")

function(ebpfaultPackageGenerator)
  if("${EBPFAULT_INSTALL_PATH}" STREQUAL "")
    message(FATAL_ERROR "The EBPFAULT_INSTALL_PATH parameter is mandatory")
  endif()

  set(executable_path "${EBPFAULT_INSTALL_PATH}/usr/local/bin/ebpfault")

  if(NOT EXISTS "${executable_path}")
    message(FATAL_ERROR "The provided EBPFAULT_INSTALL_PATH parameter is not valid")
  endif()

  install(
    FILES
      "${executable_path}"

    DESTINATION
      "bin"

    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                GROUP_READ GROUP_WRITE GROUP_EXECUTE
                WORLD_READ             WORLD_EXECUTE
  )
endfunction()

set(CPACK_GENERATOR "TGZ")

unset(rpm_executable_path CACHE)
find_program(rpm_executable_path "rpm")
if("${rpm_executable_path}" STREQUAL "rpm_executable_path-NOTFOUND")
  message(WARNING "ebpfault - The RPM package generator requires the 'rpm' tool")
else()
  list(APPEND CPACK_GENERATOR "RPM")
  message(STATUS "ebpfault - The RPM generator has been enabled")
endif()

unset(dpkg_executable_path CACHE)
find_program(dpkg_executable_path "dpkg")
if("${dpkg_executable_path}" STREQUAL "dpkg_executable_path-NOTFOUND")
  message(WARNING "ebpfault - The DEB package generator requires the 'dpkg' tool")
else()
  list(APPEND CPACK_GENERATOR "DEB")
  message(STATUS "ebpfault - The DEB generator has been enabled")
endif()

include(CPack)

ebpfaultPackageGenerator()
