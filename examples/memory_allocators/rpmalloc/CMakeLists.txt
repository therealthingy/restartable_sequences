cmake_minimum_required(VERSION 3.22)
project(rpmalloc C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)


# -----------------------------------------------------------------------------
# Compile options
# -----------------------------------------------------------------------------
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_definitions(-D_GNU_SOURCE)
endif()

# --  Convenience: set default build type depending on the build directory  --
message(STATUS "")
if (NOT CMAKE_BUILD_TYPE)
    if ("${CMAKE_BINARY_DIR}" MATCHES ".*(D|d)ebug$")
        set(CMAKE_BUILD_TYPE "Debug")
    else()
        set(CMAKE_BUILD_TYPE "RelWithDebInfo")
    endif()
    message(STATUS "No build type selected, defaulting to ** ${CMAKE_BUILD_TYPE} **")
endif()

# --  LTO  --
include(CheckIPOSupported)
check_ipo_supported(RESULT LTO_SUPPORTED)                # NOTE: Probably won't improve link-time optimizations since allocator is already 1 translation unit
if (LTO_SUPPORTED)
    #set_property(TARGET foo PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)         # Enable LTO by default (I.E., 4 all targets (SEE: https://stackoverflow.com/a/47370726))
else()
    message(STATUS "LTO isn't supported")
endif()

# --  Compiler warnings  --
add_compile_options(
    -Wall -Wextra -pedantic
    -Wformat=2
    -Wdouble-promotion
    -Wfloat-equal
    -Winit-self
    -Wundef -Wunused-macros
    -Wswitch-enum -Wswitch-default
    $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes>
#    -Werror -pedantic-errors
)
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(
            -Walloc-zero
            -Wformat-signedness
            -Wduplicated-cond
            -frecord-gcc-switches
#            -march=native -mtune=native                  # ALWAYS optimize 4 local machine (not best idea if library shall be distributed); NOTE: Doesn't work currently w/ clang on Apple Silicone  (SEE: https://discourse.llvm.org/t/why-does-march-native-not-work-on-apple-m1/2733)
    )
endif()

# --  'HAVEs'  --
include(CheckSymbolExists)
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(sched_getaffinity "sched.h" HAVE_SCHED_GETAFFINITY)
list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
add_compile_options(-DHAVE_SCHED_GETAFFINITY=$<BOOL:${HAVE_SCHED_GETAFFINITY}>)


include_directories(src/include/)                        # Own error handling macros, etc.


# -----------------------------------------------------------------------------
# Subdirs containing targets
# -----------------------------------------------------------------------------
add_subdirectory(src/)
add_subdirectory(test/)



message(STATUS "")
message(STATUS "Build type            : ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler exec       : ${CMAKE_C_COMPILER}")
message(STATUS "C++ Compiler exec     : ${CMAKE_CXX_COMPILER}")
message(STATUS "")
