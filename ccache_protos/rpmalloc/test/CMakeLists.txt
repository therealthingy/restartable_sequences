

# --  CMake options  --
option(WITH_TESTS "Build tests  (requires OpenMP)" ON)


# --  CMake targets  --
if (WITH_TESTS)
    find_package(Threads REQUIRED)
    find_package(OpenMP REQUIRED)


    add_executable(rpm-blowup-demo rpm-blowup-demo.c)
    target_link_libraries(rpm-blowup-demo OpenMP::OpenMP_C             rpmalloc-shared)

    # -  Tests based on alloc  -
    add_executable(test-rpmalloc  thread.c main.c)
    target_include_directories(test-rpmalloc PRIVATE ./)
    target_compile_options(test-rpmalloc PRIVATE          # Required due 2 headers
                           ${RPMALLOC_TEST_OBJECT_COMPILE_OPTIONS})
    target_link_libraries(test-rpmalloc rpmalloc_test-object Threads::Threads)


    add_executable(test-rpmallocwrap  thread.c main-override.cc)
    target_include_directories(test-rpmallocwrap PRIVATE ./)
    target_compile_options(test-rpmallocwrap PRIVATE  ${RPMALLOC_COMPILE_OPTIONS})
    target_link_libraries(test-rpmallocwrap rpmalloc-shared Threads::Threads)
endif()
