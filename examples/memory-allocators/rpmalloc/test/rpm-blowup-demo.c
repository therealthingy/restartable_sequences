/*
 * Simulates (or rather approximates) worst-case span L1 cache (either t- or ccache) blowup in rpmalloc
 */
#include <stdint.h>
#include <stdio.h>
#include <omp.h>
#include <stdlib.h>
#include <getopt.h>

#include <common.h>
#include <rpmalloc.h>

// ---------------------------------------------------------------------
// Taken from `rpmalloc.c`

//! # of large block size classes
#define BLOCK_LARGE_CLASS_COUNT         63
//! # of spans in 'span l1 cache'
#define SPAN_L1_CACHE_SPANS_BUCKET_CAPACITY     400
//! # of spans in 'span l1 cache' for large spans (must be greater than BLOCK_LARGE_CLASS_COUNT / 2)
#define SPAN_L1_CACHE_SUPERSPANS_BUCKET_CAPACITY 100


// ---------------------------------------------------------------------
// Taken from `os.h`

#if defined(__linux__)
#  if defined(__linux__) && !defined(_GNU_SOURCE)
#    error "Requires `-D_GNU_SOURCE`"
#  endif
#  include <sched.h>
#endif /* __linux__ */

// Make sure we've a `cpu_set_t` type
#if defined(__FreeBSD__) || defined(__DragonFly__)
#  include <sys/cpuset.h>
typedef cpuset_t cpu_set_t;
#elif defined(__APPLE__)  // macOS doesn't provide a type `cpu_set_t`
typedef unsigned long long cpu_set_t;
#endif

/**
 * Set CPU affinity  (so our measurement is accurate   + we don't have to use `taskset 0x1 <command>`) 4 process
 *   Pass `pid = 0` 4 current process, `core = -1` 4 current CPU
 */
static inline int proc_pin_set_core(const pid_t pid, const int core, cpu_set_t* const og_set_ptr) {
#ifdef __linux__
    assert( !(core == -1 && pid > 0)  && "Pinning 2 current core only works 4 current process" );

    if (og_set_ptr) {
        CPU_ZERO(og_set_ptr);
        DIE_WHEN_ERRNO( sched_getaffinity(pid, sizeof(*og_set_ptr), og_set_ptr) );
    }

    cpu_set_t new_mask;
    CPU_ZERO(&new_mask);
    CPU_SET((0 == pid && -1 == core) ? DIE_WHEN_ERRNO( sched_getcpu() ) : core, &new_mask);
    return sched_setaffinity(pid, sizeof(new_mask), &new_mask);
#else
#  warning "CPU pinning isn't yet implemented (yet) 4 this OS  --  function will be a no-op"
   WARN_SUPPRESS_UNUSED(pid);
   WARN_SUPPRESS_UNUSED(core);
   WARN_SUPPRESS_UNUSED(og_set_ptr);
#endif /* __linux__ */
    return 0;
}
// ---------------------------------------------------------------------



static void span_l1_ccache_fill_slot(const size_t thread_mem_limit_mib, const char prefault) {

    size_t span_l1_ccache_slot_total_mem = 0;
    for (unsigned int span_count = 1; span_count < BLOCK_LARGE_CLASS_COUNT +1; ++span_count) {
        const size_t block_alloc_size =        32256 *      2 * span_count;
        void* allocd_blocks[SPAN_L1_CACHE_SPANS_BUCKET_CAPACITY];

        // NOTE: We can't simply allocate & immediately deallocate block  (since the `free`d block will be immediately reused)
        for (char free_mem = 0; free_mem < 2; ++free_mem) {
            const size_t span_l1_ccache_size = (1 == span_count) ? SPAN_L1_CACHE_SPANS_BUCKET_CAPACITY : SPAN_L1_CACHE_SUPERSPANS_BUCKET_CAPACITY;
            const size_t nblocks_2_alloc = span_l1_ccache_size -1;        // Prevent 2 l2-cache overflow from occurring

            for (unsigned int idx = 0; idx < nblocks_2_alloc; ++idx) {
                if (!free_mem) {
                    allocd_blocks[idx] = DIE_WHEN_ERRNO_VPTR( malloc(block_alloc_size) );
                    span_l1_ccache_slot_total_mem += block_alloc_size;
                    if (prefault) {
                        memset(allocd_blocks[idx], 'a', block_alloc_size);                    // "Bypass" 0-page optimization  (I.E., make sure memory is actually physically allocated)
                    }
                } else {
                    free(allocd_blocks[idx]);
                    allocd_blocks[idx] = NULL;
                }
            }
        }

        if (thread_mem_limit_mib  &&  (span_l1_ccache_slot_total_mem  >=  thread_mem_limit_mib * 1024*1024)) {
            break;
        }
    }
}


int main(int argc, char** argv) {

//#ifdef PRINT_RPMALLOC_STATS
//    rpmalloc_initialize();                                                    // NOTE: Despite `ENABLE_OVERRIDE` -> Init is required before calling API functions which aren't from the C malloc-API
//#endif

    const unsigned int ncpus_logical = DIE_WHEN_ERR( system_get_ncpus(0) );
    const unsigned int ncpus_avail = DIE_WHEN_ERR( system_get_ncpus(1) );     // May be different due 2 CPU pinning

    // Parse CLI args
    struct {
        size_t thread_mem_limit_mib;
        unsigned int nthreads;
        unsigned int wait_before_exit: 1;
        unsigned int no_prefaulting: 1;
        unsigned int cc_vs_tc: 1;                                             // CPU-cache v.s. Thread-cache
        unsigned int cs_vs_ci: 1;                                             // CPU-cache (w/ cpu(_start)-index) v.s., CPU-cache (w/ `mm_cid` as index)
    } cli_args = {
        .thread_mem_limit_mib = 1 << 10,                                      // DEFAULT: 1GB (/ Thread);   `0` = infinite
        .nthreads = 0,                                                        // USE, e.g.: `$(expr $(nproc) \* 2)`
        .wait_before_exit = 0,
        .no_prefaulting = 0,
        .cc_vs_tc = 0,
        .cs_vs_ci = 0
    };
{
    static const struct option cli_options[] = {
#define CLI_ARG_THREAD_BLOWUP_LIMIT "thread-limit-mib"
        { CLI_ARG_THREAD_BLOWUP_LIMIT, required_argument, NULL, 'l' },
#define CLI_ARG_NTHREADS "nthreads"
        { CLI_ARG_NTHREADS,            required_argument, NULL, 't' },
#define CLI_ARG_WAIT_BEFORE_EXIT "wait"
        { CLI_ARG_WAIT_BEFORE_EXIT,    no_argument,       NULL, 'w' },
#define CLI_ARG_NO_PREFAULTING "no-prefaulting"
        { CLI_ARG_NO_PREFAULTING,      no_argument,       NULL, 'p' },
        { NULL,                        0,                 NULL,  0  }
    };
    for (int opt; (-1 != (opt = getopt_long_only(argc, argv, "", cli_options, NULL))); ) {
        switch (opt) {
            case 'l':
                cli_args.thread_mem_limit_mib = (unsigned long)atol(optarg);
                break;
            case 't':
                cli_args.nthreads = (unsigned int)atoi(optarg);
                break;
            case 'w':
                cli_args.wait_before_exit = 1;
                break;
            case 'p':
                cli_args.no_prefaulting = 1;
                break;
            default:
                goto error;
        }
    }
    for ( ; optind < argc; ++optind) {
#define CLI_ARG_DEMO_CC_VS_TC "CC_VS_TC"
        if ( !strcmp(CLI_ARG_DEMO_CC_VS_TC, argv[optind]) ) {
            cli_args.cc_vs_tc = 1;
#define CLI_ARG_DEMO_CS_VS_CID "CS_VS_CI"
        } else if ( !strcmp(CLI_ARG_DEMO_CS_VS_CID, argv[optind]) ) {
            cli_args.cs_vs_ci = 1;
        } else {
        error:
            fprintf(stderr, "Usage: %s [--" CLI_ARG_THREAD_BLOWUP_LIMIT " x] [--" CLI_ARG_NTHREADS " x] [--" CLI_ARG_WAIT_BEFORE_EXIT "] [--" CLI_ARG_NO_PREFAULTING "] " CLI_ARG_DEMO_CC_VS_TC " | " CLI_ARG_DEMO_CS_VS_CID"\n", argv[0]);
            return 1;
        }
    }
    if (! (cli_args.cc_vs_tc ^ cli_args.cs_vs_ci) ) {
        goto error;
    }
    if (cli_args.cs_vs_ci  &&  0 != cli_args.nthreads) {
        fprintf(stderr, "`--" CLI_ARG_NTHREADS "` has no effect when using `" CLI_ARG_DEMO_CS_VS_CID "`\n");
    }
}


    // ...
    if (cli_args.cc_vs_tc) {

        if (cli_args.nthreads <= ncpus_logical) {
            fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!\nNOTE: # threads must be > # cpus  (otherwise no observable effect)\n!!!!!!!!!!!!!!!!!!!!!\n\n");
//            return(1);
        }

        fprintf(stdout, "["CLI_ARG_DEMO_CC_VS_TC"] Demo PRO of ccache v.s., tcache when # threads > # CPUs\n");   // ccache & ccache-cid should perform similarly
        omp_set_num_threads((int)(0 == cli_args.nthreads ? (ncpus_logical << 1) : cli_args.nthreads));
#pragma omp parallel default(none) shared(cli_args, ncpus_logical, ncpus_avail, stdout)
{
#pragma omp master
{
//        assert(cli_args.nthreads == (unsigned int)omp_get_num_threads());
        fprintf(stdout, "%d thread(s), scheduled on %u/%u logical CPU(s), thread limit = %lu MiB %s\n", omp_get_num_threads(), ncpus_avail, ncpus_logical, cli_args.thread_mem_limit_mib, 0 == cli_args.thread_mem_limit_mib ? "(unlimited)" : "");
}

        span_l1_ccache_fill_slot(cli_args.thread_mem_limit_mib, (char)(!cli_args.no_prefaulting));
}
    }

    if (cli_args.cs_vs_ci) {
        fprintf(stdout, "["CLI_ARG_DEMO_CS_VS_CID"] Demo PRO of cid v.s., ccache when # threads < # CPUs\n");  // ccache-cid & tcache should perform similarly
        fprintf(stdout, "%u logical CPUs, thread limit = %lu MiB %s\n", ncpus_logical, cli_args.thread_mem_limit_mib, 0 == cli_args.thread_mem_limit_mib ? "(unlimited)" : "");
        for (unsigned int cpu = 0; cpu < ncpus_logical; ++cpu) {
            //fprintf(stdout, "Running on CPU=%u\n", cpu);
            DIE_WHEN_ERRNO( proc_pin_set_core(0, cpu, NULL) );
            span_l1_ccache_fill_slot(cli_args.thread_mem_limit_mib, (char)(!cli_args.no_prefaulting));
        }
    }


    rpmalloc_dump_statistics(stdout);                                           // NOTE: `rpmalloc_dump_statistics` uses libc print fcts  (I.E., slightly falsifies result)  +  MUST be Debug build

    if (cli_args.wait_before_exit) {
        puts("Done file span-ccache ... Press any key 2 exit (I.E., destroy cache) ...\n");
        (void)getchar();
    }

    return 0;
}
