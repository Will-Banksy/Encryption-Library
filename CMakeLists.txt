# Minimum required version of cmake
cmake_minimum_required(VERSION 3.5)

# ===

set(ProjectName "EncryptionLibrary")
set(ProjectVersion "1.0")
set(LibraryName "enclib")

set(CMAKE_CXX_STANDARD 20)

set(CMakeFlags "-std=c++20")
set(CMakeDebugFlags "-g")

option(ENCLIB_STATIC "If true, compiles as a static library, else compiles as a shared library" OFF)

# ===

project("${ProjectName}" VERSION "${ProjectVersion}")

# Project root directory and the source directory src/
set(ProjectDir "${PROJECT_SOURCE_DIR}") # PROJECT_SOURCE_DIR is set by calls to project()
set(SourceDir "${ProjectDir}/src")

# ===

set(Libraries "pthread")

set(SourceFiles
	"${SourceDir}/aes/AESEncryption.cpp"

	"${SourceDir}/rand/Rand.cpp"

	"${SourceDir}/uint128/uint128_t.cpp"
)

set(HeaderFiles
	"${SourceDir}/aes/AESEncryption.h"

	"${SourceDir}/rand/Rand.h"

	"${SourceDir}/uint128/uint128_t.h"
	"${SourceDir}/uint128/endianness.h"
	"${SourceDir}/uint128/uint128_t.include"
	"${SourceDir}/uint128/uint128_t_config.include"
	"${SourceDir}/uint128/uint128_t.build"
)

# ===

set(CMAKE_CXX_FLAGS_DEBUG "${CMakeDebugFlags}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMakeFlags}")

message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")

if("${ENCLIB_STATIC}")
	add_library("${LibraryName}" STATIC "${SourceFiles}" "${HeaderFiles}")
else()
	add_library("${LibraryName}" SHARED "${SourceFiles}" "${HeaderFiles}")
endif()

target_include_directories("${LibraryName}" PRIVATE "${SourceDir}")

target_link_libraries("${LibraryName}" PRIVATE "${Libraries}")

install(TARGETS ${LibraryName} DESTINATION "${CMAKE_INSTALL_LIBDIR}")