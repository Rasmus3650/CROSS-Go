# Install script for directory: /home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/build/libcross_static.a")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libcross_shared.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libcross_shared.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libcross_shared.so"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/build/libcross_shared.so")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libcross_shared.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libcross_shared.so")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libcross_shared.so")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/sha3.h"
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/csprng_hash.h"
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/restr_arith.h"
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/fp_arith.h"
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/api.h"
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/CROSS.h"
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/pack_unpack.h"
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/fips202.h"
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/keccakf1600.h"
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/parameters.h"
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/seedtree.h"
    "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/../../Reference_Implementation/include/merkle_tree.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/home/kristianlibo/Documents/master/PQC-Master-Thesis/debug_CROSS_submission/Additional_Implementations/Benchmarking/build/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
