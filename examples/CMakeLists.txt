cmake_minimum_required(VERSION 3.3.2)
project(rseq_examples C)

set(CMAKE_C_STANDARD 11)


# -----------------------------------------------------------------------------
# CMake- / Compile options
# -----------------------------------------------------------------------------
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_definitions(-D_GNU_SOURCE)
endif()

set(CMAKE_BUILD_TYPE "RelWithDebInfo")


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

include_directories(memory_allocators/rpmalloc/src/include/)        # Own error handling macros, etc.


# -  librseq  -
include(FetchContent)
FetchContent_Declare(
    librseq
    GIT_REPOSITORY https://github.com/compudj/librseq.git
    GIT_SHALLOW ON)
FetchContent_MakeAvailable(librseq)
add_library(librseq OBJECT ${librseq_SOURCE_DIR}/src/rseq.c)
target_include_directories(librseq PRIVATE ${librseq_SOURCE_DIR}/include)            # Required 4 lib itself
target_include_directories(librseq SYSTEM INTERFACE ${librseq_SOURCE_DIR}/include)   # Required when linking w/ applications


# --  CMake targets  --
# -  MPSC ring buffer  -
add_executable(rb_demo mpsc_rb_demo.c)
target_link_libraries(rb_demo librseq)

# -  rpmalloc  -
include(ExternalProject)
ExternalProject_Add(rpmalloc
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCACHE_L1=CPU -DCACHE_L1_USE_CID=OFF                                        # (NOTE: `DCACHE_L1_USE_CID=ON` requires Linux 6.3+)
        -DCACHE_L2=OFF
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/memory_allocators/rpmalloc
    BINARY_DIR ${CMAKE_BINARY_DIR}/memory_allocators/rpmalloc
    INSTALL_COMMAND ""
)

# -  jemalloc  -
ExternalProject_Add(jemalloc
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/memory_allocators/jemalloc
    BINARY_DIR ${CMAKE_BINARY_DIR}/memory_allocators/jemalloc
    CONFIGURE_COMMAND cd ${CMAKE_SOURCE_DIR}/memory_allocators/jemalloc  &&  ./autogen.sh  --enable-cpu-cache  &&  cd ${CMAKE_BINARY_DIR}/memory_allocators/jemalloc  &&  ${CMAKE_SOURCE_DIR}/memory_allocators/jemalloc/configure --enable-cpu-cache
    BUILD_COMMAND make -j
    INSTALL_COMMAND ""
)
