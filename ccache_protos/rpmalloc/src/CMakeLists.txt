

# -----------------------------------------------------------------------------
# CMake- / Compile options
# -----------------------------------------------------------------------------
include(CMakeDependentOption)

# -  API  -
# NOTE: We ALWAYS want 2 build `rpmallocwrap`  (I.E., w/ POSIX API  (since our applications don't use `rpmalloc` API functions))
list(APPEND RPMALLOC_COMPILE_OPTIONS
            -DENABLE_OVERRIDE=1     # Exposes standard POSIX API (`malloc`, `free`, ...) (otherwise calls like `malloc()` will invoke libc's implementation;  -> only required 4 applications which don't use rpmalloc's API (`rpxxx`)))
            -DENABLE_PRELOAD=1      # Automatic init & finalization of allocator (necessity when using `ENABLE_OVERRIDE`, otherwise `SIGSEGV`)
)

#option(API_FIRST_CLASS_HEAPS "Enable heap based API (`rpmalloc_heap_*` functions; add small overhead)" OFF)
#list(APPEND RPMALLOC_COMPILE_OPTIONS -DRPMALLOC_FIRST_CLASS_HEAPS=$<BOOL:${API_RPMALLOC_FIRST_CLASS_HEAPS}>)

# TODO: ADD `RPMALLOC_CONFIGURABLE`

# -  ?  -
set(HEAP_ARRAY_SIZE "47" CACHE STRING "Size of heap hashmap")
list(APPEND RPMALLOC_COMPILE_OPTIONS -DHEAP_ARRAY_SIZE=${HEAP_ARRAY_SIZE})

# -  VM  -
set(VM_MAP_DEFAULT_SPAN_COUNT "64" CACHE STRING "Default # of spans 2 map in call 2 map more VM (default values yield 4MiB)")
list(APPEND RPMALLOC_COMPILE_OPTIONS -DDEFAULT_SPAN_MAP_COUNT=${VM_MAP_DEFAULT_SPAN_COUNT})

option(VM_UNMAP_DISABLE "Disable unmapping memory pages (implicitly enables `CACHE_L2_UNLIMITED`)" OFF)
list(APPEND RPMALLOC_COMPILE_OPTIONS -DDISABLE_UNMAP=$<BOOL:${VM_UNMAP}>)

option(VM_RUNTIME_CONFIG_SUPPORT "Enable runtime configurable memory page & span size" OFF)   # NOTE: (page size is determined by system APIs & span size is set 2 64KiB)
list(APPEND RPMALLOC_COMPILE_OPTIONS -DRPMALLOC_CONFIGURABLE=$<BOOL:${VM_RUNTIME_CONFIG_SUPPORT}>)

# -  Cache  -
include(CheckIncludeFiles)
check_include_files("linux/rseq.h" HAVE_RSEQ_H)
include(CheckStructHasMember)
check_struct_has_member("struct rseq" mm_cid linux/rseq.h HAVE_RSEQ_CID_FIELD)

set(CACHE_L1 "THREAD" CACHE STRING "L1 cache")
option(CACHE_L1 "Enable L1 cache" ON)
set_property(CACHE CACHE_L1 PROPERTY STRINGS "OFF;THREAD;CPU")

if (CACHE_L1 STREQUAL "THREAD")
    list(APPEND RPMALLOC_COMPILE_OPTIONS -DENABLE_SPAN_L1_CCACHE=0 -DENABLE_SPAN_L1_TCACHE=1)

elseif (CACHE_L1 STREQUAL "CPU")
    if (NOT HAVE_RSEQ_H)
        message(FATAL_ERROR "Current platform doesn't support CPU caches")
    endif()

    list(APPEND RPMALLOC_COMPILE_OPTIONS -DENABLE_SPAN_L1_CCACHE=1 -DENABLE_SPAN_L1_TCACHE=0)
endif()

cmake_dependent_option(CACHE_L1_USE_CID "Use cid 4 indexing (!!  REQUIRES >= Linux 6.3.0  !!)" OFF "CACHE_L1 STREQUAL \"CPU\"" OFF)    # TODO: USE OG CONDITION "CACHE_L1 STREQUAL \"CPU\";HAVE_RSEQ_CID_FIELD"    (NOTE: MUST always be "executed", oterhwise entry won't disappear once CPU-cache is diabled)
list(APPEND RPMALLOC_COMPILE_OPTIONS -DSPAN_L1_CCACHE_USE_CID=$<BOOL:${CACHE_L1_USE_CID}>)


cmake_dependent_option(CACHE_L1_ADAPTIVE "Enable adaptive thread cache size based on use heuristics" OFF "CACHE_L1 STREQUAL \"THREAD\"" OFF)
list(APPEND RPMALLOC_COMPILE_OPTIONS -DENABLE_ADAPTIVE_SPAN_L1_CACHE=$<BOOL:${CACHE_L1_ADAPTIVE}>)

cmake_dependent_option(CACHE_L2 "Enable global cache shared b/w all threads (requires thread cache)" ON "NOT CACHE_L1 STREQUAL \"OFF\"" OFF)
list(APPEND RPMALLOC_COMPILE_OPTIONS -DENABLE_SPAN_L2_CACHE=$<BOOL:${CACHE_L2}>)

if (CACHE_L2)
    set(CACHE_L2_MULTIPLIER "8" CACHE STRING "Multiplier for global cache")
    list(APPEND RPMALLOC_COMPILE_OPTIONS -DSPAN_L2_CACHE_MULTIPLIER=${CACHE_L2_MULTIPLIER})
else()
    unset(CACHE_L2_MULTIPLIER CACHE)
endif()

cmake_dependent_option(CACHE_L2_UNLIMITED "Enable unlimited global cache (no unmapping until finalization)" OFF "CACHE_L2;NOT VM_UNMAP" OFF)
list(APPEND RPMALLOC_COMPILE_OPTIONS -DENABLE_UNLIMITED_SPAN_L2_CACHE=$<BOOL:${CACHE_L2_UNLIMITED}>)     # MISSING: `ENABLE_UNLIMITED_SPAN_L2_CACHE` `ENABLE_UNLIMITED_THREAD_CACHE`

# -  Debugging  -
cmake_dependent_option(DEBUG_ASSERTS "Enable asserts" ON "CMAKE_BUILD_TYPE STREQUAL \"Debug\"" OFF)
list(APPEND RPMALLOC_COMPILE_OPTIONS -DENABLE_ASSERTS=$<BOOL:${DEBUG_ASSERTS}>)

cmake_dependent_option(DEBUG_VALIDATE_ARGS "Enable validation (of int overflows in calculations) 4 size args to public entry points" ON "CMAKE_BUILD_TYPE STREQUAL \"Debug\"" OFF)
list(APPEND RPMALLOC_COMPILE_OPTIONS -DENABLE_VALIDATE_ARGS=$<BOOL:${DEBUG_VALIDATE_ARGS}>)

cmake_dependent_option(DEBUG_STATISTICS "Enable statistics collection" ON "CMAKE_BUILD_TYPE STREQUAL \"Debug\"" OFF)
list(APPEND RPMALLOC_COMPILE_OPTIONS -DENABLE_STATISTICS=$<BOOL:${DEBUG_STATISTICS}>)


# --  Retrieve dependencies  --
set(RPMALLOC_LINK_FLAGS "")

if (CACHE_L1 STREQUAL "CPU")
    # -  librseq  -
    # Download librseq
    include(FetchContent)
    FetchContent_Declare(
        librseq
        GIT_REPOSITORY https://github.com/compudj/librseq.git
        GIT_SHALLOW ON)
    FetchContent_MakeAvailable(librseq)
    #message(STATUS "librseq dir: ${librseq_SOURCE_DIR}")
    # librseq CMake target
    add_library(librseq OBJECT ${librseq_SOURCE_DIR}/src/rseq.c)
    target_include_directories(librseq PRIVATE ${librseq_SOURCE_DIR}/include)            # Required 4 lib itself
    target_include_directories(librseq SYSTEM INTERFACE ${librseq_SOURCE_DIR}/include)   # Required when linking w/ applications

    # -  Link against librseq  -
    list(APPEND RPMALLOC_LINK_FLAGS librseq)
endif()

# 'Build' artefact name
set(LIB_BASENAME "rpmalloc")
#string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LC)
#if (NOT(CMAKE_BUILD_TYPE_LC MATCHES "^(release|relwithdebinfo|minsizerel|none)$"))
#    set(LIB_BASENAME "${LIB_BASENAME}-${CMAKE_BUILD_TYPE_LC}") #append build type (e.g. '-debug') if not a release version
#endif()


# -----------------------------------------------------------------------------
# CMake targets
# -----------------------------------------------------------------------------
set(RPMALLOC_INCLUDE_DIRS ${rpmalloc_SOURCE_DIR}/include #${rpmalloc_BINARY_DIR}/include
)

add_library(rpmalloc-object OBJECT rpmalloc.c)
target_include_directories(rpmalloc-object PRIVATE ${RPMALLOC_INCLUDE_DIRS})
target_include_directories(rpmalloc-object SYSTEM INTERFACE ${RPMALLOC_INCLUDE_DIRS})
target_compile_options(rpmalloc-object PRIVATE ${RPMALLOC_COMPILE_OPTIONS})
target_link_libraries(rpmalloc-object ${RPMALLOC_LINK_FLAGS})

add_library(rpmalloc-shared SHARED rpmalloc.c)
target_include_directories(rpmalloc-shared PRIVATE ${RPMALLOC_INCLUDE_DIRS})
target_include_directories(rpmalloc-shared SYSTEM INTERFACE ${RPMALLOC_INCLUDE_DIRS})
target_compile_options(rpmalloc-shared PRIVATE ${RPMALLOC_COMPILE_OPTIONS})
target_link_libraries(rpmalloc-shared ${RPMALLOC_LINK_FLAGS})
set_target_properties(rpmalloc-shared PROPERTIES OUTPUT_NAME ${LIB_BASENAME})

add_library(rpmalloc-static STATIC rpmalloc.c)
target_include_directories(rpmalloc-static PRIVATE ${RPMALLOC_INCLUDE_DIRS})
target_include_directories(rpmalloc-static SYSTEM INTERFACE ${RPMALLOC_INCLUDE_DIRS})
target_compile_options(rpmalloc-static PRIVATE ${RPMALLOC_COMPILE_OPTIONS})
target_link_libraries(rpmalloc-static ${RPMALLOC_LINK_FLAGS})
set_target_properties(rpmalloc-static PROPERTIES OUTPUT_NAME ${LIB_BASENAME})

# ADDITIONALLY: Build dedicated object-library 4 tests
set(RPMALLOC_TEST_OBJECT_COMPILE_OPTIONS  -DENABLE_ASSERTS=1 -DENABLE_STATISTICS=1 -DRPMALLOC_FIRST_CLASS_HEAPS=1 -DRPMALLOC_CONFIGURABLE=1)
add_library(rpmalloc_test-object OBJECT rpmalloc.c)
target_include_directories(rpmalloc_test-object PRIVATE ${RPMALLOC_INCLUDE_DIRS})
target_include_directories(rpmalloc_test-object SYSTEM INTERFACE ${RPMALLOC_INCLUDE_DIRS})
target_compile_options(rpmalloc_test-object PRIVATE ${RPMALLOC_TEST_OBJECT_COMPILE_OPTIONS})
target_link_libraries(rpmalloc_test-object ${RPMALLOC_LINK_FLAGS})
