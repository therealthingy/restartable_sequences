/* rpmalloc.c  -  Memory allocator  -  Public Domain  -  2016-2020 Mattias Jansson
 *
 * This library provides a cross-platform lock free thread caching malloc implementation in C11.
 * The latest source code is always available at
 *
 * https://github.com/mjansson/rpmalloc
 *
 * This library is put in the public domain; you can redistribute it and/or modify it w/o any restrictions.
 *
 */

#include <common.h>           // `WARN_SUPPRESS_UNUSED`
#include "rpmalloc.h"



////////////
///
/// Build time configurable limits
///
//////

#if defined(__clang__)
#  pragma clang diagnostic ignored "-Wunused-macros"
#  pragma clang diagnostic ignored "-Wunused-function"
#if __has_warning("-Wreserved-identifier")
#  pragma clang diagnostic ignored "-Wreserved-identifier"
#endif
#if __has_warning("-Wstatic-in-inline")
#  pragma clang diagnostic ignored "-Wstatic-in-inline"
#endif
#elif defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wunused-macros"
#  pragma GCC diagnostic ignored "-Wunused-function"
#endif

#if !defined(__has_builtin)
#  define __has_builtin(b) 0
#endif

#if defined(__GNUC__) || defined(__clang__)

#if __has_builtin(__builtin_memcpy_inline)
#  define _rpmalloc_memcpy_const(x, y, s) __builtin_memcpy_inline(x, y, s)
#else
#  define _rpmalloc_memcpy_const(x, y, s) \
      do { \
          _Static_assert(__builtin_choose_expr(__builtin_constant_p(s), 1, 0), "len must be a constant integer"); \
          memcpy(x, y, s); \
      } while (0)
#endif

#if __has_builtin(__builtin_memset_inline)
#  define _rpmalloc_memset_const(x, y, s) __builtin_memset_inline(x, y, s)
#else
#  define _rpmalloc_memset_const(x, y, s) \
      do { \
          _Static_assert(__builtin_choose_expr(__builtin_constant_p(s), 1, 0), "len must be a constant integer"); \
          memset(x, y, s); \
      } while (0)
#endif
#else
#  define _rpmalloc_memcpy_const(x, y, s) memcpy(x, y, s)
#  define _rpmalloc_memset_const(x, y, s) memset(x, y, s)
#endif

#if __has_builtin(__builtin_assume)
#  define rpmalloc_assume(cond) __builtin_assume(cond)
#elif defined(__GNUC__)
#  define rpmalloc_assume(cond) \
      do { \
          if (!__builtin_expect(!!(cond), 0)) \
              __builtin_unreachable(); \
      } while (0)
#elif defined(_MSC_VER)
#  define rpmalloc_assume(cond) __assume(cond)
#else
#  define rpmalloc_assume(cond) 0
#endif

#ifndef HEAP_ARRAY_SIZE
//! Size of heap hashmap
#  define HEAP_ARRAY_SIZE           47
#endif
#ifndef ENABLE_SPAN_L1_TCACHE
//! Enable per-thread cache
#  define ENABLE_SPAN_L1_TCACHE       1
#endif
#ifndef ENABLE_SPAN_L1_CCACHE
//! Disable per-CPU cache
#  define ENABLE_SPAN_L1_CCACHE        0
#endif
#if ENABLE_SPAN_L1_CCACHE
#  ifndef SPAN_L1_CCACHE_USE_CID
#    define SPAN_L1_CCACHE_USE_CID 0        // Use by default `cpu_id`
#  endif
#endif /* ENABLE_SPAN_L1_CCACHE */
#if ENABLE_SPAN_L1_TCACHE && ENABLE_SPAN_L1_CCACHE
#  error "Span L1 cache can either be a CPU- or thread cache"
#endif
#ifndef ENABLE_SPAN_L2_CACHE
//! Enable L2 (a.k.a., global) cache shared b/w all threads, requires L1 cache
#  define ENABLE_SPAN_L2_CACHE       1
#endif
#ifndef ENABLE_VALIDATE_ARGS
//! Enable validation of args to public entry points
#  define ENABLE_VALIDATE_ARGS      0
#endif
#ifndef ENABLE_STATISTICS
//! Enable statistics collection
#  define ENABLE_STATISTICS         0
#endif
#ifndef ENABLE_ASSERTS
//! Enable asserts
#  define ENABLE_ASSERTS            0
#endif
#ifndef ENABLE_OVERRIDE
//! Override standard library malloc/free & new/delete entry points
#  define ENABLE_OVERRIDE           0
#endif
#ifndef ENABLE_PRELOAD
//! Support preloading
#  define ENABLE_PRELOAD            0
#endif
#ifndef DISABLE_UNMAP
//! Disable unmapping memory pages (also enables unlimited cache)
#  define DISABLE_UNMAP             0
#endif
#ifndef ENABLE_UNLIMITED_SPAN_L2_CACHE
//! Enable unlimited 'span l2 cache' (no unmapping until finalization)
#  define ENABLE_UNLIMITED_SPAN_L2_CACHE    0
#endif
#ifndef ENABLE_ADAPTIVE_SPAN_L1_CACHE
//! Enable adaptive thread cache size based on use heuristics
#  define ENABLE_ADAPTIVE_SPAN_L1_CACHE 0
#endif
#ifndef DEFAULT_SPAN_MAP_COUNT
//! Default # of spans to map in call to map more virtual memory (default values yield 4MiB here)
#  define DEFAULT_SPAN_MAP_COUNT    64
#endif
#ifndef SPAN_L2_CACHE_MULTIPLIER
//! Multiplier for 'span l2 cache'
#  define SPAN_L2_CACHE_MULTIPLIER   8
#endif

#if DISABLE_UNMAP && !ENABLE_SPAN_L2_CACHE
#  error "Must use 'span l2 cache' if unmap is disabled"
#endif

#if DISABLE_UNMAP
#  undef ENABLE_UNLIMITED_SPAN_L2_CACHE
#  define ENABLE_UNLIMITED_SPAN_L2_CACHE 1
#endif

#if !ENABLE_SPAN_L2_CACHE
#  undef ENABLE_UNLIMITED_SPAN_L2_CACHE
#  define ENABLE_UNLIMITED_SPAN_L2_CACHE 0
#endif

#if !ENABLE_SPAN_L1_TCACHE && !ENABLE_SPAN_L1_CCACHE
#  undef ENABLE_ADAPTIVE_SPAN_L1_CACHE
#  define ENABLE_ADAPTIVE_SPAN_L1_CACHE 0
#endif

#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64)
#  define PLATFORM_WINDOWS 1
#  define PLATFORM_POSIX 0
#else
#  define PLATFORM_WINDOWS 0
#  define PLATFORM_POSIX 1
#endif

#define SIZE_OF_STRUCT_MEMBER(TYPE, MEMBER) sizeof(((TYPE*)0)->MEMBER)
#define WARN_SUPPRESS_UNUSED(X) (void)(X)

/// Platform & arch specifics
// -----------------   TODO: Support other compilers
#define ATTR_UNUSED __attribute__((unused))
#define ATTR_FORMAT_CHECK(archetype, idx_fmt_string, idx_first_varg) __attribute__((format (archetype, idx_fmt_string, idx_first_varg)))
// -----------------

#if defined(_MSC_VER) && !defined(__clang__)
#  pragma warning (disable: 5105)
#  ifndef ATTR_FORCE_INLINE
#    define ATTR_FORCE_INLINE inline __forceinline
#  endif
#  define _Static_assert static_assert
#else
#  ifndef ATTR_FORCE_INLINE
#    define ATTR_FORCE_INLINE inline __attribute__((__always_inline__))
#  endif
#endif
#if PLATFORM_WINDOWS
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  if ENABLE_VALIDATE_ARGS
#    include <intsafe.h>
#  endif
#else
#  include <unistd.h>
#  include <stdio.h>
#  include <stdlib.h>
#  include <time.h>
#  if defined(__linux__) || defined(__ANDROID__)
#    include <sys/prctl.h>
#    if !defined(PR_SET_VMA)
#      define PR_SET_VMA 0x53564d41
#      define PR_SET_VMA_ANON_NAME 0
#    endif
#  endif
#  if defined(__APPLE__)
#    include <TargetConditionals.h>
#    if !TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
#    include <mach/mach_vm.h>
#    include <mach/vm_statistics.h>
#    endif
#    include <pthread.h>
#  endif
#  if defined(__HAIKU__) || defined(__TINYC__)
#    include <pthread.h>
#  endif
#endif

#include <stdint.h>
#include <string.h>
#include <errno.h>

#if defined(_WIN32) && (!defined(BUILD_DYNAMIC_LINK) || !BUILD_DYNAMIC_LINK)
#  include <fibersapi.h>
static DWORD fls_key;
#endif

#if PLATFORM_POSIX
#  include <sys/mman.h>
#  include <sched.h>
#  ifdef __FreeBSD__
#    include <sys/sysctl.h>
#    define MAP_HUGETLB MAP_ALIGNED_SUPER
#    ifndef PROT_MAX
#      define PROT_MAX(f) 0
#    endif
#  else
#    define PROT_MAX(f) 0
#  endif
#  ifdef __sun
extern int madvise(caddr_t, size_t, int);
#  endif
#  ifndef MAP_UNINITIALIZED
#    define MAP_UNINITIALIZED 0
#  endif
#endif
#include <errno.h>

#if ENABLE_ASSERTS
#  undef NDEBUG
#  if defined(_MSC_VER) && !defined(_DEBUG)
#    define _DEBUG
#  endif

// Avoid SEGFAULT due 2 `assert` causing infinite recursion by alloc'ing mem
#  ifndef LOG_BUFFER_BYTES
#    define LOG_BUFFER_BYTES (1 << 9)       // WARNING: Compiler WON'T WARN (even when invoked w/ `-Wall`) when truncation occurs (not feasible since not inlined)
#  endif
#  include <stdarg.h>
ATTR_FORMAT_CHECK(printf, 2, 3) void ___FWRITE_LOG__(const int fd, const char* const fmt, ...) {
    char log_buffer[LOG_BUFFER_BYTES];

    va_list ap;
    va_start(ap, fmt);
    if ( vsnprintf(log_buffer, sizeof(log_buffer), fmt, ap) < 0 ||
         write(fd, log_buffer, strnlen(log_buffer, sizeof(log_buffer))) == -1 ) {
        _exit(EXIT_FAILURE);
    }
    va_end(ap);
}
#  define RPMALLOC_TOSTRING_M(x) #x
#  define RPMALLOC_TOSTRING(x) RPMALLOC_TOSTRING_M(x)
#  define rpmalloc_assert(truth, msg_fmt, ...) \
      do { \
          if (!(truth)) { \
              if (g_config_alloc.error_callback) { \
                  g_config_alloc.error_callback("ASSERT FAILED @ " __FILE__ ":" RPMALLOC_TOSTRING(__LINE__) ": " msg_fmt "\n", ##__VA_ARGS__); \
              } else { \
                  ___FWRITE_LOG__(STDERR_FILENO, "ASSERT FAILED @ " __FILE__ ":" RPMALLOC_TOSTRING(__LINE__) ": " msg_fmt "\n", ##__VA_ARGS__); \
                  abort(); \
              } \
          } \
      } while (0)
#else
#  define rpmalloc_assert(truth, msg_fmt, ...) do { } while(0)
#endif

#if ENABLE_STATISTICS
#  include <stdio.h>
#endif

#if ENABLE_SPAN_L1_CCACHE
#  if !defined(__linux__)
#    error "Span L1 CPU-cache is (currently) only supported on GNU/Linux"
#  endif

#  if ENABLE_ADAPTIVE_SPAN_L1_CACHE
#    error "Adaptive L1 cache is (currently) unsupported by the CPU-cache"          // TODO
#  endif

#  include <rseq/rseq.h>

#  if SPAN_L1_CCACHE_USE_CID
#    define RSEQ_CPU_ID_FIELD_OFFSET     RSEQ_MM_CID_OFFSET
#    define SPAN_CCACHE_SLOT_GET_INDEX() rseq_current_mm_cid()
#  else
#    define RSEQ_CPU_ID_FIELD_OFFSET     RSEQ_CPU_ID_OFFSET
#    define SPAN_CCACHE_SLOT_GET_INDEX() rseq_cpu_start()
#  endif
#endif


//////
///
/// Atomic access abstraction (since MSVC does not do C11 yet)
///
//////

#if defined(_MSC_VER) && !defined(__clang__)

typedef volatile long      atomic32_t;
typedef volatile long long atomic64_t;
typedef volatile void*     atomicptr_t;

static ATTR_FORCE_INLINE int32_t atomic_load32(atomic32_t* src) { return *src; }
static ATTR_FORCE_INLINE void    atomic_store32(atomic32_t* dst, int32_t val) { *dst = val; }
static ATTR_FORCE_INLINE int32_t atomic_incr32(atomic32_t* val) { return (int32_t)InterlockedIncrement(val); }
static ATTR_FORCE_INLINE int32_t atomic_decr32(atomic32_t* val) { return (int32_t)InterlockedDecrement(val); }
static ATTR_FORCE_INLINE int32_t atomic_add32(atomic32_t* val, int32_t add) { return (int32_t)InterlockedExchangeAdd(val, add) + add; }
static ATTR_FORCE_INLINE int     atomic_cas32_acquire(atomic32_t* dst, int32_t val, int32_t ref) { return (InterlockedCompareExchange(dst, val, ref) == ref) ? 1 : 0; }
static ATTR_FORCE_INLINE void    atomic_store32_release(atomic32_t* dst, int32_t val) { *dst = val; }
static ATTR_FORCE_INLINE int64_t atomic_load64(atomic64_t* src) { return *src; }
static ATTR_FORCE_INLINE int64_t atomic_add64(atomic64_t* val, int64_t add) { return (int64_t)InterlockedExchangeAdd64(val, add) + add; }
static ATTR_FORCE_INLINE void*   atomic_load_ptr(atomicptr_t* src) { return (void*)*src; }
static ATTR_FORCE_INLINE void    atomic_store_ptr(atomicptr_t* dst, void* val) { *dst = val; }
static ATTR_FORCE_INLINE void    atomic_store_ptr_release(atomicptr_t* dst, void* val) { *dst = val; }
static ATTR_FORCE_INLINE void*   atomic_exchange_ptr_acquire(atomicptr_t* dst, void* val) { return (void*)InterlockedExchangePointer((void* volatile*)dst, val); }
static ATTR_FORCE_INLINE int     atomic_cas_ptr(atomicptr_t* dst, void* val, void* ref) { return (InterlockedCompareExchangePointer((void* volatile*)dst, val, ref) == ref) ? 1 : 0; }

#  define EXPECTED(x) (x)
#  define UNEXPECTED(x) (x)

#else

#  include <stdatomic.h>

typedef volatile _Atomic(int32_t) atomic32_t;
typedef volatile _Atomic(int64_t) atomic64_t;
typedef volatile _Atomic(void*) atomicptr_t;

static ATTR_FORCE_INLINE int32_t atomic_load32(atomic32_t* src) { return atomic_load_explicit(src, memory_order_relaxed); }
static ATTR_FORCE_INLINE void    atomic_store32(atomic32_t* dst, int32_t val) { atomic_store_explicit(dst, val, memory_order_relaxed); }
static ATTR_FORCE_INLINE int32_t atomic_incr32(atomic32_t* val) { return atomic_fetch_add_explicit(val, 1, memory_order_relaxed) + 1; }
static ATTR_FORCE_INLINE int32_t atomic_decr32(atomic32_t* val) { return atomic_fetch_add_explicit(val, -1, memory_order_relaxed) - 1; }
static ATTR_FORCE_INLINE int32_t atomic_add32(atomic32_t* val, int32_t add) { return atomic_fetch_add_explicit(val, add, memory_order_relaxed) + add; }
static ATTR_FORCE_INLINE int     atomic_cas32_acquire(atomic32_t* dst, int32_t val, int32_t ref) { return atomic_compare_exchange_weak_explicit(dst, &ref, val, memory_order_acquire, memory_order_relaxed); }
static ATTR_FORCE_INLINE void    atomic_store32_release(atomic32_t* dst, int32_t val) { atomic_store_explicit(dst, val, memory_order_release); }
static ATTR_FORCE_INLINE int64_t atomic_load64(atomic64_t* val) { return atomic_load_explicit(val, memory_order_relaxed); }
static ATTR_FORCE_INLINE int64_t atomic_add64(atomic64_t* val, int64_t add) { return atomic_fetch_add_explicit(val, add, memory_order_relaxed) + add; }
static ATTR_FORCE_INLINE void*   atomic_load_ptr(atomicptr_t* src) { return atomic_load_explicit(src, memory_order_relaxed); }
static ATTR_FORCE_INLINE void    atomic_store_ptr(atomicptr_t* dst, void* val) { atomic_store_explicit(dst, val, memory_order_relaxed); }
static ATTR_FORCE_INLINE void    atomic_store_ptr_release(atomicptr_t* dst, void* val) { atomic_store_explicit(dst, val, memory_order_release); }
static ATTR_FORCE_INLINE void*   atomic_exchange_ptr_acquire(atomicptr_t* dst, void* val) { return atomic_exchange_explicit(dst, val, memory_order_acquire); }
static ATTR_FORCE_INLINE int     atomic_cas_ptr(atomicptr_t* dst, void* val, void* ref) { return atomic_compare_exchange_weak_explicit(dst, &ref, val, memory_order_relaxed, memory_order_relaxed); }

#  define EXPECTED(x) (__builtin_expect(!!(x), 1))
#  define UNEXPECTED(x) (__builtin_expect(!!(x), 0))

#endif

////////////
///
/// Statistics related functions (evaluate to nothing when statistics not enabled)
///
//////

#if ENABLE_STATISTICS
#  define _rpmalloc_stat_inc(counter) atomic_incr32(counter)
#  define _rpmalloc_stat_dec(counter) atomic_decr32(counter)
#  define _rpmalloc_stat_add(counter, value) atomic_add32(counter, (int32_t)(value))
#  define _rpmalloc_stat_add64(counter, value) atomic_add64(counter, (int64_t)(value))
#  define _rpmalloc_stat_add_peak(counter, value, peak) do { int32_t _cur_count = atomic_add32(counter, (int32_t)(value)); if (_cur_count > (peak)) peak = _cur_count; } while (0)
#  define _rpmalloc_stat_sub(counter, value) atomic_add32(counter, -(int32_t)(value))
#  define _rpmalloc_stat_inc_alloc(heap, class_idx) do { \
    int32_t alloc_current = atomic_incr32(&heap->stats_block_sizeclass_use[class_idx].alloc_current); \
    if (alloc_current > heap->stats_block_sizeclass_use[class_idx].alloc_peak) \
        heap->stats_block_sizeclass_use[class_idx].alloc_peak = alloc_current; \
    atomic_incr32(&heap->stats_block_sizeclass_use[class_idx].alloc_total); \
} while(0)
#  define _rpmalloc_stat_inc_free(heap, class_idx) do { \
    atomic_decr32(&heap->stats_block_sizeclass_use[class_idx].alloc_current); \
    atomic_incr32(&heap->stats_block_sizeclass_use[class_idx].free_total); \
} while(0)
#else
#  define _rpmalloc_stat_inc(counter) do { } while(0)
#  define _rpmalloc_stat_dec(counter) do { } while(0)
#  define _rpmalloc_stat_add(counter, value) do { } while(0)
#  define _rpmalloc_stat_add64(counter, value) do { } while(0)
#  define _rpmalloc_stat_add_peak(counter, value, peak) do {} while (0)
#  define _rpmalloc_stat_sub(counter, value) do { } while(0)
#  define _rpmalloc_stat_inc_alloc(heap, class_idx) do { } while(0)
#  define _rpmalloc_stat_inc_free(heap, class_idx) do { } while(0)
#endif


///
/// Preconfigured limits & sizes
///

//! Granularity of a small allocation block (must be power of 2)
#define BLOCK_SMALL_GRANULARITY         16
_Static_assert((BLOCK_SMALL_GRANULARITY & (BLOCK_SMALL_GRANULARITY - 1)) == 0, "Small granularity must be power of 2");
//! Small granularity shift count
#define BLOCK_SMALL_GRANULARITY_SHIFT   4             // I.E., 1 << 4 = 16 ??!
//! # of small block size classes
#define BLOCK_SMALL_CLASS_COUNT         65
//! Maximum size of a small block
#define BLOCK_SMALL_SIZE_LIMIT          (BLOCK_SMALL_GRANULARITY * (BLOCK_SMALL_CLASS_COUNT - 1))
//! Granularity of a medium allocation block
#define BLOCK_MEDIUM_GRANULARITY        512
//! Medium granularity shift count
#define BLOCK_MEDIUM_GRANULARITY_SHIFT  9
//! # of medium block size classes
#define BLOCK_MEDIUM_CLASS_COUNT        61
//! Total # of small + medium size classes
#define BLOCK_SMALL_MEDIUM_CLASS_COUNT  (BLOCK_SMALL_CLASS_COUNT + BLOCK_MEDIUM_CLASS_COUNT)
//! # of large block size classes
#define BLOCK_MEDIUM_SIZE_LIMIT         (BLOCK_SMALL_SIZE_LIMIT + (BLOCK_MEDIUM_GRANULARITY * BLOCK_MEDIUM_CLASS_COUNT))
//! Maximum size of a large block
#define BLOCK_LARGE_CLASS_COUNT         63
//! Maximum size of a medium block
#define BLOCK_LARGE_SIZE_LIMIT          ((BLOCK_LARGE_CLASS_COUNT * g_config_span_size) - SPAN_HEADER_SIZE)
//! Size of a span header (must be a multiple of BLOCK_SMALL_GRANULARITY & a power of 2)
#define SPAN_HEADER_SIZE                128
_Static_assert((SPAN_HEADER_SIZE & (SPAN_HEADER_SIZE - 1)) == 0, "Span header size must be power of 2");
//! # of spans in 'span l1 cache'
#define SPAN_L1_CACHE_SPANS_BUCKET_CAPACITY          400
//! # of spans in 'span l1 cache' for large spans (must be greater than BLOCK_LARGE_CLASS_COUNT / 2)
#define SPAN_L1_CACHE_SUPERSPANS_BUCKET_CAPACITY    100
//! # of spans to transfer b/w l1- & 'span l2 cache'
#define SPAN_L1_2_L2_CACHE_TRANSFER_COUNT 64
//! # of spans to transfer b/w l1 & 'span l2 cache' for large spans
#define SPAN_L1_2_L2_CACHE_LARGE_TRANSFER_COUNT 6

#define BLOCK_SIZE_CLASS_LARGE BLOCK_SMALL_MEDIUM_CLASS_COUNT
#define BLOCK_SIZE_CLASS_HUGE ((uint32_t)-1)


#if ENABLE_VALIDATE_ARGS
//! Maximum allocation size to avoid integer overflow
#  undef  MAX_ALLOC_SIZE
#  define MAX_ALLOC_SIZE            (((size_t)-1) - g_config_span_size)
#endif

#define pointer_add_offset(ptr, ofs) (void*)((char*)(ptr) + (ptrdiff_t)(ofs))
#define pointer_diff(first, second) (ptrdiff_t)((const char*)(first) - (const char*)(second))

#define INVALID_POINTER ((void*)((uintptr_t)-1))

/* Lock operations
 */
#define SPINLOCK_ACQUIRE(LOCK) do { \
    while (!atomic_cas32_acquire(LOCK, 1, 0)) { \
        _rpmalloc_spin(); \
    } \
} while(0)

#define SPINLOCK_RELEASE(LOCK) atomic_store32_release(LOCK, 0)

////////////
///
/// Data types
///
//////

//! A memory heap, per thread
typedef struct heap heap_t;
//! Span of memory pages
typedef struct span span_t;
//! L2 (a.k.a., global) cache
typedef struct span_l2_cache span_l2_cache_t;

//! Flag indicating span is the 1st (master) span of a split "super span"
#define SPAN_FLAG_MASTER 1U
//! Flag indicating span is a secondary (sub) span of a split "super span"
#define SPAN_FLAG_SUBSPAN 2U
//! Flag indicating an unmapped master span
#define SPAN_FLAG_UNMAPPED_MASTER 8U
//! Flag indicating span has blocks w/ increased alignment
#define SPAN_FLAG_ALIGNED_BLOCKS 4U

#if ENABLE_ADAPTIVE_SPAN_L1_CACHE || ENABLE_STATISTICS
typedef struct {
    //! Current # of spans used (actually used, not in cache)
    atomic32_t current;
    //! High water mark of spans used
    atomic32_t high;
#  if ENABLE_STATISTICS
    //! # of spans in deferred list
    atomic32_t stats_spans_deferred;
    //! # of spans transitioned to 'span l2 cache'
    atomic32_t stats_spans_to_l2;
    //! # of spans transitioned from 'span l2 cache'
    atomic32_t stats_spans_from_global;
    //! # of spans transitioned to 'span l1 cache'
    atomic32_t stats_spans_to_cache;
    //! # of spans transitioned from 'span l1 cache'
    atomic32_t stats_spans_from_cache;
    //! # of spans transitioned to reserved state
    atomic32_t stats_spans_to_reserved;
    //! # of spans transitioned from reserved state
    atomic32_t stats_spans_from_reserved;
    //! # of raw memory map calls
    atomic32_t stats_spans_map_calls;
#  endif
} span_use_t;
#endif

#if ENABLE_STATISTICS
typedef struct {
    //! Current # of allocations
    atomic32_t alloc_current;
    //! Peak # of allocations
    int32_t alloc_peak;
    //! Total # of allocations
    atomic32_t alloc_total;
    //! Total # of frees
    atomic32_t free_total;
    //! # of spans in use
    atomic32_t spans_current;
    //! # of spans transitioned to cache
    int32_t spans_peak;
    //! # of spans transitioned to cache
    atomic32_t spans_to_cache;
    //! # of spans transitioned from cache
    atomic32_t spans_from_cache;
    //! # of spans transitioned from reserved state
    atomic32_t spans_from_reserved;
    //! # of spans mapped
    atomic32_t spans_map_calls;
    int32_t unused;
} stats_block_sizeclass_use_t;
#endif

/*
 * A span can either represent a
 *   - single span of memory pages w/ size declared by `span_map_count` configuration variable, or a
 *   - "super span", comprised of a set of spans in a continuous region. Any reference to the term "span" usually
 *     refers to both a single- or a "super span".
 *
 * A "super span" can further be divided into multiple spans (or this, "super span"s), where the
 *   - 1st "(super)span" is the master &
 *   - subsequent "(super)spans" are "sub-spans".
 *
 * The "master span" keeps track of how many "sub-spans" are still alive & mapped in virtual memory,
 * and once all "sub-spans" & "master" have been unmapped, the entire "super span" region is released & unmapped
 * (on Windows e.g., the entire "super span" range has to be released in the same call to release the virtual
 * memory range, but individual sub-ranges can be decommitted individually to reduce physical memory use).
 */
struct span {
    //! Free list               (either block free list OR sll of spans (`heap->span_free_deferred_sll`))
    union {
        void* block_freelist;
        span_t* heap_span_free_deferred_sll;
    };
    //! Index of last block initialized in free list
    uint32_t    block_freelist_inited_count;
    //! # of used blocks remaining when in partial state ???
    uint32_t    block_freelist_used_count;

    //! Size class
    uint32_t    block_sizeclass_idx;
    //! Total block count of size class
    uint32_t    block_sizeclass_count;
    //! Size of a block
    uint32_t    block_sizeclass_size;

    //! Deferred free list
    atomicptr_t block_freelist_deferred;
    //! Size of deferred free list, OR list of spans when part of a list
    union {
        uint32_t    block_freelist_deferred_count;
        uint32_t    heap_span_free_deferred_sll_count;
    };

    //! Flags & counters
    uint32_t    flags;

    //! # of spans  (if > 1 = 'super span' ???????????!?!?!!?!?!?!?!)
    uint32_t    span__count;

    //! Total span counter for master spans                     // TODO: Consider using union 4 data depending on span type
    uint32_t    masterspan_total_span_count;
    //! Remaining span counter, for master spans
    atomic32_t  masterspan_remaining_spans;
    //! Offset from master span for sub-spans
    uint32_t    subspan_master_offset;

    //! Alignment offset
    uint32_t    align_offset;

    //! Owning heap
    heap_t*     owner_heap;

    //! Doubly linked list  ('dll';  used by `heap_sizeclass_spans_t` & `span_l2_cache_t`)
    //! Next span
    span_t*     next_dll;
    //! Previous span
    span_t*     prev_dll;
#if ENABLE_ASSERTS && ENABLE_SPAN_L1_CCACHE                   // 4 'span l1 ccache' "tracing"
    int32_t     span_l1_ccache_last_idx;
    unsigned int span_l1_ccache_owned: 1;
#endif
};
_Static_assert(sizeof(span_t) <= SPAN_HEADER_SIZE, "`SPAN_HEADER_SIZE` is too small");

#if !defined(NDEBUG) && ENABLE_SPAN_L1_CCACHE
#  define SPAN_L1_CCACHE_INIT_SPAN(SPAN_PTR) do { \
      SPAN_PTR->span_l1_ccache_last_idx = -1; \
      SPAN_PTR->span_l1_ccache_owned = 0; \
  } while(0)
#else
#  define SPAN_L1_CCACHE_INIT_SPAN(SPAN_PTR) do { } while(0)
#endif

typedef struct {
    size_t       count;
    span_t*      bin[SPAN_L1_CACHE_SPANS_BUCKET_CAPACITY];
} span_l1_cache_bucket_t;

typedef struct {
    size_t       count;
    span_t*      bin[SPAN_L1_CACHE_SUPERSPANS_BUCKET_CAPACITY];
} span_l1_cache_bucket_large_t;
_Static_assert(offsetof(span_l1_cache_bucket_t, count) == offsetof(span_l1_cache_bucket_large_t, count)  &&
               offsetof(span_l1_cache_bucket_t, bin) == offsetof(span_l1_cache_bucket_large_t, bin), "`span_l1_xx_cache_t` fields offset mismatch");

typedef struct {
    //! Arrays of fully freed spans, single span
    span_l1_cache_bucket_t spans_bucket;
    //! Arrays of fully freed spans, large spans with > 1 span count
    span_l1_cache_bucket_large_t superspans_buckets[BLOCK_LARGE_CLASS_COUNT - 1];
} span_l1_cache_t;

typedef struct {
    //! Each size class has an ACTIVE SPAN (from which we allocate)  -->  This is the free list of blocks 4 this size class
    void*        active_spans_block_freelist;                     // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    //! Double linked list of partially used spans w/ free blocks.
    //  Previous span pointer in head points to tail span of list.
    span_t*      partially_inited_spans_dll;
    //! "Early level cache" (L0) of fully free spans
    span_t*      fully_inited_spans_dll;
} heap_sizeclass_spans_t;

// Control structure for a thread heap
struct heap {
    //! Owning thread ID
    uintptr_t    owner_thread;
    //! Free lists for each size class
    heap_sizeclass_spans_t sizeclass_spans[BLOCK_SMALL_MEDIUM_CLASS_COUNT];
#if ENABLE_SPAN_L1_TCACHE
    span_l1_cache_t span_l1_tcache;
#endif
    //! List of deferred free spans (single linked list)
    atomicptr_t  span_free_deferred_sll;
    //! # of full spans
    size_t       fully_inited_spans_count;

    //! Mapped, but unused spans  (CONTIGUOUS AREA OF MEMORY, I.E., NOT A LIST)
    span_t*      span_reserve;
    //! Master span for mapped, but unused spans
    span_t*      span_reserve_master;
    //! # of mapped, but unused spans
    uint32_t     spans_reserve_count;

    //! Child count  (# of child heaps ??)
    atomic32_t   child_count;
    //! Next heap in id list   (EXPLAINER: Heaps are stored in `g_alloc_heaps`, where each heap gets a slot derived from mod reduced heap-id .. HOWEVER, if there's a collision, we use a singly linked list 2 accommodate multiple heaps in the same slot)
    heap_t*      id_next_sll;
    //! Next heap in orphan list  (Explainer: Are maintained in `g_alloc_orphan_heaps_sll`)
    heap_t*      orphan_next_sll;

    //! Heap ID  (used 4 finding index in `g_alloc_heaps` + statistics output)
    int32_t      id;
    //! Finalization state flag
    int          finalize;
    //! Master heap owning the memory pages
    heap_t*      master_heap;
#if ENABLE_ADAPTIVE_SPAN_L1_CACHE || ENABLE_STATISTICS
    //! Current & high water mark of spans used per span count
    span_use_t   span_use[BLOCK_LARGE_CLASS_COUNT];
#endif
#if ENABLE_STATISTICS
    //! Allocation stats per size class
    stats_block_sizeclass_use_t stats_block_sizeclass_use[BLOCK_SMALL_MEDIUM_CLASS_COUNT + 1];
    //! # of bytes transitioned thread -> global
    atomic64_t   stats_l1_to_l2;
    //! # of bytes transitioned global -> thread
    atomic64_t   stats_l2_to_l1;
#endif
};

// Size class definition  (for defining a block size bucket)
typedef struct {
    //! Size of blocks in this class
    uint32_t block_size;
    //! # of blocks in each chunk
    uint16_t block_count;
    //! Class index this class is merged w/
    uint16_t class_idx;
} block_sizeclass_t;
_Static_assert(sizeof(block_sizeclass_t) == 8, "Size class size mismatch");

#if ENABLE_SPAN_L1_CCACHE
//! Used 2 transfer spans from- & to 'span l1 cache'
typedef struct {
    //! # of spans requested which shall be transferred  (either 2 or from 'span l1 cache')
    size_t count_requested;
    //! # of spans actually transferred  (only valid if function returned `0`)
    size_t count_carried_out;
    //! Type of span ??
    size_t span_count;
    //! Buffer containing the spans
    span_t* spans[SPAN_L1_2_L2_CACHE_TRANSFER_COUNT    +1 /* 'reserved span' so we can refill the 'span l1 cache' + return 1 item from 'span l2 cache' */];
} span_l1_ccache_request_t;

#  define SPAN_L1_CCACHE_REQUEST_BUFFER_MAX_SIZE ( (SIZE_OF_STRUCT_MEMBER(span_l1_ccache_request_t, spans) / SIZE_OF_STRUCT_MEMBER(span_l1_ccache_request_t, spans[0]))   -1 /* reserved span */ )

#  define _SPAN_L1_CCACHE_REQUEST_INITIALIZER(SPAN_COUNT, REQUEST_COUNT) { \
    .span_count = SPAN_COUNT, \
    .count_requested = REQUEST_COUNT, .count_carried_out = 0, \
    .spans = {0} }
#  define SPAN_L1_CCACHE_REQUEST_INITIALIZER_ZERO                           _SPAN_L1_CCACHE_REQUEST_INITIALIZER(0, 0)
#  define SPAN_L1_CCACHE_REQUEST_INITIALIZER_PUSH(REQUEST_COUNT)            _SPAN_L1_CCACHE_REQUEST_INITIALIZER(0, REQUEST_COUNT)
#  define SPAN_L1_CCACHE_REQUEST_INITIALIZER_POP(SPAN_COUNT, REQUEST_COUNT) _SPAN_L1_CCACHE_REQUEST_INITIALIZER(SPAN_COUNT, REQUEST_COUNT)
#endif

// A.k.a., 'global cache'
struct span_l2_cache {
    //! Cache lock
    atomic32_t lock;
    //! Cache count
    uint32_t count;
#if ENABLE_STATISTICS
    //! Insert count
    size_t stats_insert_count;
    //! Extract count
    size_t stats_extract_count;
#endif
    //! Cached spans
    span_t* spans_dll[SPAN_L2_CACHE_MULTIPLIER * SPAN_L1_CACHE_SPANS_BUCKET_CAPACITY];
    //! Unlimited cache overflow
    span_t* overflow_dll;
};

////////////
///
/// Global data
///
//////

//! Initialized flag
static char g_alloc_state_inited;
//! Main thread ID
static uintptr_t g_alloc_main_thread_id;
//! Heap ID counter
static atomic32_t g_alloc_heap_id;


#if ENABLE_SPAN_L1_CCACHE
//! rseq registration flag
static _Thread_local char g_rpmalloc_rseq_thread_registered;
//! # of entries in 'span l1 cache'  (which corresponds to the # of logical CPUs (installed in the system))
static unsigned int g_span_l1_ccache_ncpus;
//! Base address of 'span l1 cache'
static span_l1_cache_t* g_span_l1_ccache_slots_baseptr;

#  if !defined(NDEBUG) && ENABLE_STATISTICS
static atomic64_t g_span_l1_ccache_rseq_push_success_count;
static atomic64_t g_span_l1_ccache_rseq_pop_success_count;
static atomic64_t g_span_l1_ccache_rseq_push_abort_count;
static atomic64_t g_span_l1_ccache_rseq_pop_abort_count;

static atomic64_t g_span_l1_ccache_spans_push_count;
static atomic64_t g_span_l1_ccache_spans_pop_count;
static atomic64_t g_span_l1_ccache_spans_push_requested_count;
static atomic64_t g_span_l1_ccache_spans_pop_requested_count;
#  endif
#endif

#if ENABLE_SPAN_L2_CACHE
//! Global span cache
static span_l2_cache_t g_alloc_span_l2_cache[BLOCK_LARGE_CLASS_COUNT];
#endif

//! Global reserved spans
static span_t* g_alloc_global_span_reserve;
//! Global reserved count
static size_t g_alloc_global_span_reserve_count;
//! Global reserved master
static span_t* g_alloc_global_span_reserve_master;

//! All heaps
static heap_t* g_alloc_heaps[HEAP_ARRAY_SIZE];
//! Used to restrict access to mapping memory for huge pages
static atomic32_t g_alloc_global_lock;
//! Orphaned heaps
static heap_t* g_alloc_orphan_heaps_sll;

//! Configuration
static rpmalloc_config_t g_config_alloc;
//! Huge page support
static char g_config_use_huge_pages;
//! Memory page size
static size_t g_config_page_size;
//! Shift to divide by page size
static size_t g_config_page_size_shift;
//! Granularity at which memory pages are mapped by OS
static size_t g_config_map_granularity;
//! Default span size (64KiB)
#define g_config_default_span_size (64 * 1024)
#define g_config_default_span_size_shift 16
#define g_config_default_span_mask (~((uintptr_t)(g_config_span_size - 1)))
#if RPMALLOC_CONFIGURABLE
//! Size of a span of memory pages
static size_t g_config_span_size;
//! Shift to divide by span size
static size_t g_config_span_size_shift;
//! Mask to get to start of a memory span
static uintptr_t g_config_span_mask;
#else
//! Hardwired span size
#  define g_config_span_size g_config_default_span_size
#  define g_config_span_size_shift g_config_default_span_size_shift
#  define g_config_span_mask g_config_default_span_mask
#endif

//! # of spans to map in each map call
static size_t g_config_span_map_count;

//! # of spans to keep reserved in each heap
static size_t g_config_heap_reserve_count;
//! Global size classes
static block_sizeclass_t g_config_block_sizeclasses[BLOCK_SMALL_MEDIUM_CLASS_COUNT];
//! Run-time size limit of medium blocks
static size_t g_config_block_medium_size_limit;


#if ENABLE_STATISTICS
//! Allocations counter
static atomic64_t g_stats_allocation_counter;
//! Deallocations counter
static atomic64_t g_stats_deallocation_counter;
//! Active heap count
static atomic32_t g_stats_memory_active_heaps;
//! # of currently mapped memory pages
static atomic32_t g_stats_mapped_pages;
//! Peak # of concurrently mapped memory pages
static int32_t g_stats_mapped_pages_peak;
//! # of mapped master spans
static atomic32_t g_stats_master_spans;
//! # of unmapped dangling master spans
static atomic32_t g_stats_unmapped_master_spans;
//! Running counter of total # of mapped memory pages since start
static atomic32_t g_stats_mapped_total;
//! Running counter of total # of unmapped memory pages since start
static atomic32_t g_stats_unmapped_total;
//! # of currently mapped memory pages in OS calls
static atomic32_t g_stats_mapped_pages_os;
//! # of currently allocated pages in huge allocations
static atomic32_t g_stats_huge_pages_current;
//! Peak # of currently allocated pages in huge allocations
static int32_t g_stats_huge_pages_peak;
#endif

////////////
///
/// Thread local heap & ID
///
//////

//! Current thread heap
#if ((defined(__APPLE__) || defined(__HAIKU__)) && ENABLE_PRELOAD) || defined(__TINYC__)
static pthread_key_t g_memory_thread_heap;
#else
#  ifdef _MSC_VER
#    define _Thread_local __declspec(thread)
#    define TLS_MODEL
#  else
#    ifndef __HAIKU__
#      define TLS_MODEL __attribute__((tls_model("initial-exec")))
#    else
#      define TLS_MODEL
#    endif
#    if !defined(__clang__) && defined(__GNUC__)
#      define _Thread_local __thread
#    endif
#  endif
static _Thread_local heap_t* g_memory_thread_heap TLS_MODEL;
#endif

static inline heap_t*
get_thread_heap_raw(void) {
#if (defined(__APPLE__) || defined(__HAIKU__)) && ENABLE_PRELOAD
    return pthread_getspecific(g_memory_thread_heap);
#else
    return g_memory_thread_heap;
#endif
}

//! Get the current thread heap
static inline heap_t*
get_thread_heap(void) {
    heap_t* const heap = get_thread_heap_raw();
#if ENABLE_PRELOAD
    if EXPECTED(NULL != heap)
        return heap;
    DIE_WHEN_ERR( rpmalloc_initialize() );
    return get_thread_heap_raw();
#else
    return heap;
#endif
}

//! Fast thread ID
static inline uintptr_t
get_thread_id(void) {
#if defined(_WIN32)
    return (uintptr_t)((void*)NtCurrentTeb());
#elif (defined(__GNUC__) || defined(__clang__)) && !defined(__CYGWIN__)
    uintptr_t tid;
#  if defined(__i386__)
    __asm__("movl %%gs:0, %0" : "=r" (tid) : : );
#  elif defined(__x86_64__)
#    if defined(__MACH__)
    __asm__("movq %%gs:0, %0" : "=r" (tid) : : );
#    else
    __asm__("movq %%fs:0, %0" : "=r" (tid) : : );
#    endif
#  elif defined(__arm__)
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (tid));
#  elif defined(__aarch64__)
#    if defined(__MACH__)
    // tpidr_el0 likely unused, always return 0 on iOS
    __asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (tid));
#    else
    __asm__ volatile ("mrs %0, tpidr_el0" : "=r" (tid));
#    endif
#  else
#    error "This platform needs implementation of get_thread_id()"
#  endif
    return tid;
#else
#    error "This platform needs implementation of get_thread_id()"
#endif
}

//! Set the current thread heap
static void
set_thread_heap(heap_t* const heap) {
#if ((defined(__APPLE__) || defined(__HAIKU__)) && ENABLE_PRELOAD) || defined(__TINYC__)
    pthread_setspecific(g_memory_thread_heap, heap);
#else
    g_memory_thread_heap = heap;
#endif
    if (heap)
        heap->owner_thread = get_thread_id();
}

//! Set main thread ID
extern void
rpmalloc_set_main_thread(void);

void
rpmalloc_set_main_thread(void) {
    g_alloc_main_thread_id = get_thread_id();
}

static void
_rpmalloc_spin(void) {
#if defined(_MSC_VER)
    _mm_pause();
#elif defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__) || (defined(__arm__) && __ARM_ARCH >= 7)
    __asm__ volatile("yield" ::: "memory");
#elif defined(__powerpc__) || defined(__powerpc64__)
        // No idea if ever been compiled in such archs but ... as precaution
    __asm__ volatile("or 27,27,27");
#elif defined(__sparc__)
    __asm__ volatile("rd %ccr, %g0 \n\trd %ccr, %g0 \n\trd %ccr, %g0");
#else
    struct timespec ts = {0};
    nanosleep(&ts, 0);
#endif
}

#if defined(_WIN32) && (!defined(BUILD_DYNAMIC_LINK) || !BUILD_DYNAMIC_LINK)
static void NTAPI
_rpmalloc_thread_destructor(void* value) {
#  if ENABLE_OVERRIDE
    // If this is called on main thread it means `rpmalloc_finalize`
    // has not been called & shutdown is forced (through `_exit`) or unclean
    if (get_thread_id() == g_alloc_main_thread_id)
        return;
#  endif
    if (value)
        rpmalloc_thread_finalize(1);
}
#endif


////////////
///
/// Low level memory map/unmap
///
//////

static void
_rpmalloc_set_page_name(void* const address, const size_t size) {
#if defined(__linux__) || defined(__ANDROID__)
    const char* const name = g_config_use_huge_pages ? g_config_alloc.huge_page_name : g_config_alloc.page_name;
    if (MAP_FAILED == address || !name)
        return;
    // If the kernel doesn't support `CONFIG_ANON_VMA_NAME` or if the call fails
    // (e.g. invalid name) it is a nop basically.
    (void)prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, (uintptr_t)address, size, (uintptr_t)name);
#else
    WARN_SUPPRESS_UNUSED(size);
    WARN_SUPPRESS_UNUSED(address);
#endif
}


//! Map more virtual memory
//  `size` is # of bytes to map
//  `offset` receives the offset in bytes from start of mapped region
//  returns address to start of mapped region to use
static void*
_rpmalloc_mmap(const size_t size, size_t* const offset) {
    rpmalloc_assert(!(size % g_config_page_size), "Invalid mmap size");
    rpmalloc_assert(size >= g_config_page_size, "Invalid mmap size");
    void* const address = g_config_alloc.memory_map_fct(size, offset);
    if EXPECTED(NULL != address) {
        _rpmalloc_stat_add_peak(&g_stats_mapped_pages, (size >> g_config_page_size_shift), g_stats_mapped_pages_peak);
        _rpmalloc_stat_add(&g_stats_mapped_total, (size >> g_config_page_size_shift));
    }
    return address;
}

//! Unmap virtual memory
//  `address` is the memory address to unmap, as returned from `memory_map_fct`
//  `size` is the # of bytes to unmap, which might be less than full region for a partial unmap
//  `offset` is the offset in bytes to the actual mapped region, as set by `memory_map_fct`
//  `release` is set to `0` for partial unmap, or size of entire range for a full unmap
static void
_rpmalloc_unmap(void* const address,
                const size_t size,
                const size_t offset,
                const size_t release) {
    rpmalloc_assert(!release || (release >= size), "Invalid unmap size");
    rpmalloc_assert(!release || (release >= g_config_page_size), "Invalid unmap size");
    if (release) {
        rpmalloc_assert(!(release % g_config_page_size), "Invalid unmap size");
        _rpmalloc_stat_sub(&g_stats_mapped_pages, (release >> g_config_page_size_shift));
        _rpmalloc_stat_add(&g_stats_unmapped_total, (release >> g_config_page_size_shift));
    }
    g_config_alloc.memory_unmap_fct(address, size, offset, release);
}

//! Default implementation to map new pages to virtual memory
static void*
_rpmalloc_mmap_os(const size_t size, size_t* const offset) {
    //Either size is a heap (a single page) or a (multiple) span - we only need to align spans, and only if larger than map granularity
    const size_t padding = ((size >= g_config_span_size) && (g_config_span_size > g_config_map_granularity)) ? g_config_span_size : 0;
    rpmalloc_assert(size >= g_config_page_size, "Invalid mmap size");
#if PLATFORM_WINDOWS
    //Ok to MEM_COMMIT - according to MSDN, "actual physical pages are not allocated unless/until the virtual addresses are actually accessed"
    void* ptr = VirtualAlloc(0, size + padding, (g_config_use_huge_pages ? MEM_LARGE_PAGES : 0) | MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!ptr) {
        if (g_config_alloc.map_fail_callback) {
            if (g_config_alloc.map_fail_callback(size + padding))
                return _rpmalloc_mmap_os(size, offset);
        } else {
            rpmalloc_assert(ptr, "Failed to map virtual memory block");
        }
        return NULL;
    }
#else
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNINITIALIZED;
#  if defined(__APPLE__) && !TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    void* ptr = mmap(NULL,
                     size + padding,
                     PROT_READ | PROT_WRITE,
                     flags,
                     (int)VM_MAKE_TAG(240U) | (g_config_use_huge_pages ? VM_FLAGS_SUPERPAGE_SIZE_2MB : 0),
                     0);
#  elif defined(MAP_HUGETLB)
    void* ptr = mmap(NULL,
                     size + padding,
                     PROT_READ | PROT_WRITE | PROT_MAX(PROT_READ | PROT_WRITE),
                     (g_config_use_huge_pages ? MAP_HUGETLB : 0) | flags,
                     -1,
                     0);
#    if defined(MADV_HUGEPAGE)
    // In some configurations, huge pages allocations might fail thus
    // we fallback to normal allocations & promote the region as transparent huge page
    if ((MAP_FAILED == ptr || !ptr) && g_config_use_huge_pages) {
        ptr = mmap(NULL,
                   size + padding,
                   PROT_READ | PROT_WRITE,
                   flags,
                   -1,
                   0);
        if (ptr && MAP_FAILED != ptr) {
            const int prm = madvise(ptr, size + padding, MADV_HUGEPAGE);
            WARN_SUPPRESS_UNUSED(prm);
            rpmalloc_assert((0 == prm), "Failed to promote the page to THP");
        }
    }
#    endif
    _rpmalloc_set_page_name(ptr, size + padding);
#  elif defined(MAP_ALIGNED)
    const size_t align = (sizeof(size_t) * 8) - (size_t)(__builtin_clzl(size - 1));
    void* ptr = mmap(NULL,
                     size + padding,
                     PROT_READ | PROT_WRITE,
                     (g_config_use_huge_pages ? MAP_ALIGNED(align) : 0) | flags,
                     -1,
                     0);
#  elif defined(MAP_ALIGN)
    caddr_t base = (g_config_use_huge_pages ? (caddr_t)(4 << 20) : 0);
    void* ptr = mmap(base,
                     size + padding,
                     PROT_READ | PROT_WRITE,
                     (g_config_use_huge_pages ? MAP_ALIGN : 0) | flags,
                     -1,
                     0);
#  else
    void* ptr = mmap(NULL,
                     size + padding,
                     PROT_READ | PROT_WRITE,
                     flags,
                     -1,
                     0);
#  endif
    if ((MAP_FAILED == ptr) || !ptr) {
        if (g_config_alloc.map_fail_callback) {
            if (g_config_alloc.map_fail_callback(size + padding))
                return _rpmalloc_mmap_os(size, offset);
        } else if (errno != ENOMEM) {
            rpmalloc_assert((MAP_FAILED != ptr) && ptr, "Failed to map virtual memory block");
        }
        return NULL;
    }
#endif
    _rpmalloc_stat_add(&g_stats_mapped_pages_os, (int32_t)((size + padding) >> g_config_page_size_shift));
    if (padding) {
        const size_t final_padding = padding - ((uintptr_t)ptr & ~g_config_span_mask);
        rpmalloc_assert(final_padding <= g_config_span_size, "Internal failure in padding");
        rpmalloc_assert(final_padding <= padding, "Internal failure in padding");
        rpmalloc_assert(!(final_padding % 8), "Internal failure in padding");
        ptr = pointer_add_offset(ptr, final_padding);
        *offset = final_padding >> 3;
    }
    rpmalloc_assert((size < g_config_span_size) || !((uintptr_t)ptr & ~g_config_span_mask), "Internal failure in padding");
    return ptr;
}

//! Default implementation to unmap pages from virtual memory
static void
_rpmalloc_unmap_os(void* address,
                   const size_t size,
                   size_t offset,
                   size_t release) {
    rpmalloc_assert(release || (offset == 0), "Invalid unmap size");
    rpmalloc_assert(!release || (release >= g_config_page_size), "Invalid unmap size");
    rpmalloc_assert(size >= g_config_page_size, "Invalid unmap size");
    if (release && offset) {
        offset <<= 3;
        address = pointer_add_offset(address, -(int32_t)offset);
        if ((release >= g_config_span_size) && (g_config_span_size > g_config_map_granularity)) {
            //Padding is always one span size
            release += g_config_span_size;
        }
    }
#if !DISABLE_UNMAP
#  if PLATFORM_WINDOWS
    if (!VirtualFree(address, release ? 0 : size, release ? MEM_RELEASE : MEM_DECOMMIT)) {
        rpmalloc_assert(0, "Failed to unmap virtual memory block");
    }
#  else
    if (release) {
        if (munmap(address, release)) {
            rpmalloc_assert(0, "Failed to unmap virtual memory block");
        }
    } else {
#    if defined(MADV_FREE_REUSABLE)
        int ret;
        while ((ret = madvise(address, size, MADV_FREE_REUSABLE)) == -1 && (EAGAIN == errno))
            errno = 0;
        if ((-1 == ret) && (0 != errno)) {
#    elif defined(MADV_DONTNEED)
        if (madvise(address, size, MADV_DONTNEED)) {
#    elif defined(MADV_PAGEOUT)
        if (madvise(address, size, MADV_PAGEOUT)) {
#    elif defined(MADV_FREE)
        if (madvise(address, size, MADV_FREE)) {
#    else
        if (posix_madvise(address, size, POSIX_MADV_DONTNEED)) {
#    endif
            rpmalloc_assert(0, "Failed to madvise virtual memory block as free");
        }
    }
#  endif
#endif
    if (release)
        _rpmalloc_stat_sub(&g_stats_mapped_pages_os, release >> g_config_page_size_shift);
}

static void
_rpmalloc_span_init_subspan(span_t* master_span, span_t* sub_span, size_t span_count);

//! Use global reserved spans to fulfill a memory map request (reserve size must be checked by caller)
static span_t*
_rpmalloc_global_get_reserved_spans(const size_t span_count) {
    span_t* const span = g_alloc_global_span_reserve;
    _rpmalloc_span_init_subspan(g_alloc_global_span_reserve_master,
                                span,
                                span_count);
    g_alloc_global_span_reserve_count -= span_count;
    g_alloc_global_span_reserve = (g_alloc_global_span_reserve_count) ? (span_t*)pointer_add_offset(span, span_count << g_config_span_size_shift) :
                                                                        NULL;
    return span;
}

//! Store the given spans as global reserve (not thread safe -> must only be called from within new heap allocation)
static void
_rpmalloc_global_set_reserved_spans(span_t* const master_span,
                                    span_t* const reserve,
                                    const size_t reserve_span_count) {
    g_alloc_global_span_reserve_master = master_span;
    g_alloc_global_span_reserve_count = reserve_span_count;
    g_alloc_global_span_reserve = reserve;
}


////////////
///
/// Span linked list management
///
//////

//! Add a span to double linked list at the head
static void
_rpmalloc_span_dll_add(span_t** const head, span_t* const span) {
    if (*head)
        (*head)->prev_dll = span;
    span->next_dll = *head;
    *head = span;
}

//! Pop head span from double linked list
static void
_rpmalloc_span_dll_pop_head(span_t** const head, span_t* span) {
    rpmalloc_assert(*head == span, "Linked list corrupted");
    span = *head;
    *head = span->next_dll;
}

//! Remove a span from double linked list
static void
_rpmalloc_span_dll_remove(span_t** const head, span_t* const span) {
    rpmalloc_assert(*head, "Linked list corrupted");
    if (*head == span) {
        *head = span->next_dll;
    } else {
        span_t* next_span = span->next_dll;
        span_t* prev_span = span->prev_dll;
        prev_span->next_dll = next_span;
        if EXPECTED(NULL != next_span)
            next_span->prev_dll = prev_span;
    }
}


////////////
///
/// Span control
///
//////

static void
_rpmalloc_heap_span_lx_cache_insert(heap_t* heap, span_t* span);

static void
_rpmalloc_heap_finalize(heap_t* heap);

static void
_rpmalloc_heap_set_reserved_spans(heap_t* const heap, span_t* const master_span, span_t* const reserve, const size_t reserve_span_count);

//! Declare the span to be a subspan & store distance from master span & span count
static void
_rpmalloc_span_init_subspan(span_t* const master_span,
                            span_t* const sub_span,
                            const size_t span_count) {
    rpmalloc_assert((sub_span != master_span) || (sub_span->flags & SPAN_FLAG_MASTER), "Span master pointer and/or flag mismatch");
    // Set stuff if "sub-span"
    if (sub_span != master_span) {                // TODO: Isn't this if superfluous ?
        sub_span->flags = SPAN_FLAG_SUBSPAN;
        sub_span->subspan_master_offset = (uint32_t)((uintptr_t)pointer_diff(sub_span, master_span) >> g_config_span_size_shift);
        sub_span->align_offset = 0;
        SPAN_L1_CCACHE_INIT_SPAN(sub_span);
    }
    sub_span->span__count = (uint32_t)span_count;
}

//! Use reserved spans to fulfill a memory map request (reserve size must be checked by caller)
static span_t*
_rpmalloc_span_map_from_reserve(heap_t* const heap, const size_t span_count) {
    //Update the heap span reserve
    span_t* const span = heap->span_reserve;
    heap->span_reserve = (span_t*)pointer_add_offset(span, span_count * g_config_span_size);
    heap->spans_reserve_count -= (uint32_t)span_count;

    _rpmalloc_span_init_subspan(heap->span_reserve_master, span, span_count);
    if (span_count <= BLOCK_LARGE_CLASS_COUNT)
        _rpmalloc_stat_inc(&heap->span_use[span_count - 1].stats_spans_from_reserved);

    return span;
}

//! Get the # of aligned spans to map in based on wanted count, configured mapping granularity & the page size
static size_t
_rpmalloc_span_calc_align_count(const size_t span_count) {
    size_t request_count = (span_count > g_config_span_map_count) ? span_count : g_config_span_map_count;
    if ((g_config_page_size > g_config_span_size) && ((request_count * g_config_span_size) % g_config_page_size))
        request_count += g_config_span_map_count - (request_count % g_config_span_map_count);
    return request_count;
}

//! Setup a newly mapped span
static void
_rpmalloc_span_init(span_t* const span,
                    const size_t total_span_count,
                    const size_t span_count,
                    const size_t align_offset) {
    span->masterspan_total_span_count = (uint32_t)total_span_count;
    span->span__count = (uint32_t)span_count;
    span->align_offset = (uint32_t)align_offset;
    span->flags = SPAN_FLAG_MASTER;
    SPAN_L1_CCACHE_INIT_SPAN(span);
    atomic_store32(&span->masterspan_remaining_spans, (int32_t)total_span_count);
}

static void
_rpmalloc_span_unmap(span_t* span);

//! Map an aligned set of spans, taking configured mapping granularity & page size into account
static span_t*
_rpmalloc_span_map_aligned_count(heap_t* const heap,
                                 const size_t span_count) {
    // (1.) `mmap` new spans
    const size_t aligned_span_count = _rpmalloc_span_calc_align_count(span_count);
    size_t align_offset = 0;
    span_t* const span = (span_t*)_rpmalloc_mmap(aligned_span_count * g_config_span_size, &align_offset);
    if (!span)
        return NULL;

    // (2.) Init new spans
    _rpmalloc_span_init(span, aligned_span_count, span_count, align_offset);
    _rpmalloc_stat_inc(&g_stats_master_spans);
    if (span_count <= BLOCK_LARGE_CLASS_COUNT)
        _rpmalloc_stat_inc(&heap->span_use[span_count - 1].stats_spans_map_calls);

    // (3.)  Do we've more spans than requested due 2 alignment --> put them in the "reserve" ???!
    if (aligned_span_count > span_count) {
        // Find out where the "excess" spans begin & calculate # of excess spans
        span_t* const excess_spans = (span_t*)pointer_add_offset(span, span_count * g_config_span_size);
        size_t excess_spans_count = aligned_span_count - span_count;

        //If we already have some, but not enough reserved spans: release them to heap cache & map a new
        //full set of spans.  (Otherwise, we'd waste memory if page size > span size (huge pages))
        if (heap->spans_reserve_count) {
            _rpmalloc_span_init_subspan(heap->span_reserve_master,
                                        heap->span_reserve,
                                        heap->spans_reserve_count);
            _rpmalloc_heap_span_lx_cache_insert(heap, heap->span_reserve);
        }
        // Unmap, if there are too many 4 global reserve ????!
        if (excess_spans_count > g_config_heap_reserve_count) {
            // If huge pages or eager span map count, the global reserve spin lock is held by caller, `_rpmalloc_span_map`
            rpmalloc_assert(atomic_load32(&g_alloc_global_lock) == 1, "Global spin lock not held as expected");
            const size_t remain_count = excess_spans_count - g_config_heap_reserve_count;
            excess_spans_count = g_config_heap_reserve_count;
            span_t* const remain_span = (span_t*)pointer_add_offset(excess_spans, excess_spans_count * g_config_span_size);
            if (g_alloc_global_span_reserve) {
                _rpmalloc_span_init_subspan(g_alloc_global_span_reserve_master,
                                            g_alloc_global_span_reserve,
                                            g_alloc_global_span_reserve_count);
                _rpmalloc_span_unmap(g_alloc_global_span_reserve);
            }
            _rpmalloc_global_set_reserved_spans(span, remain_span, remain_count);
        }
        _rpmalloc_heap_set_reserved_spans(heap, span, excess_spans, excess_spans_count);
    }
    return span;
}

//! Map in memory pages for the given # of spans (or use previously reserved pages)
static span_t*
_rpmalloc_span_map(heap_t* const heap, const size_t span_count) {
    // (1.) Map from reserve
    if (span_count <= heap->spans_reserve_count)
        return _rpmalloc_span_map_from_reserve(heap, span_count);

    // (2.) Reserve was empty
    // (2.1.) Check global reserve
    span_t* span = NULL;
    const char use_global_reserve = (g_config_page_size > g_config_span_size) || (g_config_span_map_count > g_config_heap_reserve_count);
    if (use_global_reserve) {
        // If huge pages, make sure only 1 thread maps more memory to avoid bloat
        SPINLOCK_ACQUIRE(&g_alloc_global_lock);
        if (g_alloc_global_span_reserve_count >= span_count) {
            size_t reserve_count = (!heap->spans_reserve_count ? g_config_heap_reserve_count : span_count);
            if (g_alloc_global_span_reserve_count < reserve_count)
                reserve_count = g_alloc_global_span_reserve_count;
            span = _rpmalloc_global_get_reserved_spans(reserve_count);
            if (span) {
                if (reserve_count > span_count) {
                    span_t* reserved_span = (span_t*)pointer_add_offset(span, span_count << g_config_span_size_shift);
                    _rpmalloc_heap_set_reserved_spans(heap, g_alloc_global_span_reserve_master, reserved_span, reserve_count - span_count);
                }
                // Already marked as subspan in `_rpmalloc_global_get_reserved_spans`
                span->span__count = (uint32_t)span_count;
            }
        }
    }
    //(2.2.) If not available (or not used ???): Map new VM
    if (!span)
        span = _rpmalloc_span_map_aligned_count(heap, span_count);
    if (use_global_reserve)
        SPINLOCK_RELEASE(&g_alloc_global_lock);
    return span;
}

//! Unmap memory pages for the given # of spans (or mark as unused if no partial unmappings)
static void
_rpmalloc_span_unmap(span_t* const span) {
    rpmalloc_assert((span->flags & SPAN_FLAG_MASTER) || (span->flags & SPAN_FLAG_SUBSPAN), "`span->flags` corrupted");
    rpmalloc_assert(!(span->flags & SPAN_FLAG_MASTER) || !(span->flags & SPAN_FLAG_SUBSPAN), "`span->flags` corrupted");

    const char is_master = !!(span->flags & SPAN_FLAG_MASTER);
    rpmalloc_assert(is_master || (span->flags & SPAN_FLAG_SUBSPAN), "`span->flags` corrupted");
    span_t* const master_span = is_master ? span :
                                            ((span_t*)pointer_add_offset(span, -(intptr_t)((uintptr_t)span->subspan_master_offset * g_config_span_size)));
    rpmalloc_assert(master_span->flags & SPAN_FLAG_MASTER, "Span flag corrupted");

    const size_t span_count = span->span__count;
    if (!is_master) {
        //Directly unmap sub-spans (unless huge pages, in which case we defer & unmap entire page range w/ master)
        rpmalloc_assert(0 == span->align_offset, "`span->align_offset` corrupted");
        if (g_config_span_size >= g_config_page_size)
            _rpmalloc_unmap(span, span_count * g_config_span_size, 0, 0);
    } else {
        //Special double flag to denote an unmapped master
        //It must be kept in memory since span header must be used
        span->flags |= SPAN_FLAG_MASTER | SPAN_FLAG_SUBSPAN | SPAN_FLAG_UNMAPPED_MASTER;
        _rpmalloc_stat_add(&g_stats_unmapped_master_spans, 1);
    }

    if (atomic_add32(&master_span->masterspan_remaining_spans, -(int32_t)span_count) <= 0) {
        //Everything unmapped, unmap the master span w/ release flag to unmap the entire range of the "super span"
        rpmalloc_assert(!!(master_span->flags & SPAN_FLAG_MASTER) && !!(master_span->flags & SPAN_FLAG_SUBSPAN), "`master_span->flags` corrupted");
        size_t unmap_count = master_span->span__count;
        if (g_config_span_size < g_config_page_size)
            unmap_count = master_span->masterspan_total_span_count;
        _rpmalloc_stat_sub(&g_stats_master_spans, 1);
        _rpmalloc_stat_sub(&g_stats_unmapped_master_spans, 1);
        _rpmalloc_unmap(master_span, unmap_count * g_config_span_size, master_span->align_offset, (size_t)master_span->masterspan_total_span_count * g_config_span_size);
    }
}

//! Move the span (used for small or medium allocations) to the heaps 'span l0 cache' .. if there
//  are already spans -> move them 2 'span l1 cache'
static void
_rpmalloc_span_release_to_heap_span_l0_cache(heap_t* const heap, span_t* span) {
    rpmalloc_assert(heap == span->owner_heap, "`span->owner_heap` corrupted");
    rpmalloc_assert(span->block_sizeclass_idx < BLOCK_SMALL_MEDIUM_CLASS_COUNT, "Invalid `span->block_sizeclass_idx`");
    rpmalloc_assert(1 == span->span__count, "Invalid `span->span__count`");
#if ENABLE_ADAPTIVE_SPAN_L1_CACHE || ENABLE_STATISTICS
    atomic_decr32(&heap->span_use[0].current);
#endif
    _rpmalloc_stat_dec(&heap->stats_block_sizeclass_use[span->block_sizeclass_idx].spans_current);

    if (!heap->finalize) {                                                              // TODO: Should be handled differently 4 'span l1 ccache' (since 'span l1 ccache' will continue 2 exist v.s., 'span l1 tcache' which will be destroyed)
        _rpmalloc_stat_inc(&heap->span_use[0].stats_spans_to_cache);
        _rpmalloc_stat_inc(&heap->stats_block_sizeclass_use[span->block_sizeclass_idx].spans_to_cache);

        // IF there are "old" ones, release them 2 'span l1 cache'
        if (heap->sizeclass_spans[span->block_sizeclass_idx].fully_inited_spans_dll)
            _rpmalloc_heap_span_lx_cache_insert(heap, heap->sizeclass_spans[span->block_sizeclass_idx].fully_inited_spans_dll);
        // Replace them w/ current span ???
        heap->sizeclass_spans[span->block_sizeclass_idx].fully_inited_spans_dll = span;
    } else {
        _rpmalloc_span_unmap(span);
    }
}

//! Init a (partial) free free list up to next system memory page, while
//! reserving the 1st block as allocated,
//! returning # of blocks in list
static uint32_t
block_freelist_init_partially_reserve_1st_block_for_caller_and_add_remaining_2_heap_class_freelist(void** const heap_active_span_freelist,
                                                                                                   void** const first_block/* 1st block (reserved 4 caller) */,
                                                                                                   void* const page_start,
                                                                                                   void* const block_start,
                                                                                                   uint32_t block_count,
                                                                                                   const uint32_t block_size) {
    rpmalloc_assert(block_count, "Internal failure");

    *first_block = block_start;
    if (block_count > 1) {          // Isn't this `if` superfluous ??
        void* last_block_end = pointer_add_offset(block_start, (size_t)block_size * block_count);
        //If block size is < 1/2 a memory page, bound init to next memory page boundary
        if (block_size < (g_config_page_size >> 1/*/2 -> "half mem page"*/)) {
            void* page_end = pointer_add_offset(page_start, g_config_page_size);
            if (page_end < last_block_end)
                last_block_end = page_end;
        }

        // Create free list  (sll of free blocks) 4 heap
        void* cur_block = pointer_add_offset(block_start, block_size);
        *heap_active_span_freelist = cur_block;    // Add node as head of heap span freelist
        block_count = 2;                            // "Reuse" `block_count` by setting it 2 `2`
        // Create remaining nodes until we've created `block_count` many  ???
        void* next_block = pointer_add_offset(cur_block, block_size);
        while (next_block < last_block_end) {
            *((void**)cur_block) = next_block;
            cur_block = next_block;
            ++block_count;
            next_block = pointer_add_offset(next_block, block_size);
        }
        *((void**)cur_block) = NULL;        // End of sll

    } else {
        *heap_active_span_freelist = NULL;
    }
    return block_count;
}

//! Initialize an unused span (from cache or mapped) to be new active span, putting the initial free list in "heap class free list"
static void*
_rpmalloc_span_init_and_return_block_and_add_remaining_2_heap(heap_t* const heap,
                                                              heap_sizeclass_spans_t* const heap_sizeclass_spans,
                                                              span_t* const span,
                                                              const uint32_t class_idx) {
    rpmalloc_assert(1 == span->span__count, "Internal failure");

    block_sizeclass_t* const block_sizeclass = g_config_block_sizeclasses + class_idx;
    span->block_sizeclass_idx = class_idx;
    span->owner_heap = heap;
    span->flags &= ~SPAN_FLAG_ALIGNED_BLOCKS;
    span->block_sizeclass_size = block_sizeclass->block_size;
    span->block_sizeclass_count = block_sizeclass->block_count;
    span->block_freelist = NULL;
    span->block_freelist_deferred_count = 0;
    atomic_store_ptr_release(&span->block_freelist_deferred, NULL);

    //Setup free list. Init only 1 system page worth of free blocks in list & add it in heaps active free-list 4 its "size class"
    void* block;
    span->block_freelist_inited_count = block_freelist_init_partially_reserve_1st_block_for_caller_and_add_remaining_2_heap_class_freelist(&heap_sizeclass_spans->active_spans_block_freelist,
                                                                                                                                           &block/*first_block*/,
                                                                                                                                           span/*page_start*/,
                                                                                                                                           pointer_add_offset(span, SPAN_HEADER_SIZE)/*block_start*/,
                                                                                                                                           block_sizeclass->block_count,
                                                                                                                                           block_sizeclass->block_size);

    //Link span as partial IF there remains blocks to be initialized as free list, or full if fully initialized
    if (span->block_freelist_inited_count < span->block_sizeclass_count) {
        _rpmalloc_span_dll_add(&heap_sizeclass_spans->partially_inited_spans_dll, span);
        span->block_freelist_used_count = span->block_freelist_inited_count;
    } else {
        ++heap->fully_inited_spans_count;
        span->block_freelist_used_count = span->block_sizeclass_count;
    }
    return block;
}

static void
_rpmalloc_span_extract_from_block_freelist_deferred(span_t* const span) {
    /* Move (adopt) ALL spans ?? in 'deferred free list' 2 'free list'
     *   We need acquire semantics on the CAS operation since we are interested in the list size
     *   Refer to _rpmalloc_deallocate_defer_small_or_medium for further comments on this dependency
     */
    do {
        span->block_freelist = atomic_exchange_ptr_acquire(&span->block_freelist_deferred, INVALID_POINTER);
    } while (INVALID_POINTER == span->block_freelist);
    span->block_freelist_used_count -= span->block_freelist_deferred_count;
    span->block_freelist_deferred_count = 0;
    atomic_store_ptr_release(&span->block_freelist_deferred, NULL);
}

static int
_rpmalloc_span_is_fully_inited(span_t* const span) {
    rpmalloc_assert(span->block_freelist_inited_count <= span->block_sizeclass_count, "Span free list corrupted");
    return !span->block_freelist && (span->block_freelist_inited_count >= span->block_sizeclass_count);
}

static int
_rpmalloc_span_finalize(heap_t* const heap,
                        const size_t iclass,
                        span_t* const span,
                        span_t** const head_dll) {
    void* const active_spans_block_freelist = heap->sizeclass_spans[iclass].active_spans_block_freelist;
    span_t* const sizeclass_active_span = (span_t*)((uintptr_t)active_spans_block_freelist & g_config_span_mask);        // Derive from block (in free list) its "underlying span"
    // Is 2 be finalized span the "active span" (4 the size class)?
    if (span == sizeclass_active_span) {
        // Adopt the "heap class free list" back into the "span free list"
        void *cur_block = span->block_freelist,
             *last_block = NULL;
        // Traverse free-list to end
        while (cur_block) {
            last_block = cur_block;
            cur_block = *((void**)cur_block);
        }
        // Count # of free blocks in free-list  ???
        uint32_t free_count = 0;
        cur_block = active_spans_block_freelist;
        while (cur_block) {
            ++free_count;
            cur_block = *((void**)cur_block);
        }
        // Update everything  ??  ( Adopt them (heap free list blocks ??) in spans free list  ??? )
        if (last_block) {
            *((void**)last_block) = active_spans_block_freelist;
        } else {
            span->block_freelist = active_spans_block_freelist;
        }
        heap->sizeclass_spans[iclass].active_spans_block_freelist = NULL;
        span->block_freelist_used_count -= free_count;
    }
#if 0           // TODO: Temporary workaround -- Memory leak `assert` (which is very likely a 'false alarm') will cause `SIGABRT`
    //If this assert triggers you have memory leaks
    rpmalloc_assert(span->block_freelist_deferred_count == span->block_freelist_used_count, "Memory leak detected");
#endif

    // Remove span from dll  ???
    if (span->block_freelist_deferred_count == span->block_freelist_used_count) {
        _rpmalloc_stat_dec(&heap->span_use[0].current);
        _rpmalloc_stat_dec(&heap->stats_block_sizeclass_use[iclass].spans_current);
        // This function only used for spans in double linked lists
        if (head_dll)
            _rpmalloc_span_dll_remove(head_dll, span);
        _rpmalloc_span_unmap(span);
        return 1;
    }
    return 0;
}

////////////
///
/// L2 (Global) cache
///
//////

#if ENABLE_SPAN_L2_CACHE

//! Finalize 'span l2 cache'
static void
_rpmalloc_span_l2_cache_finalize(span_l2_cache_t* const span_l2_cache) {
    SPINLOCK_ACQUIRE(&span_l2_cache->lock);

    for (size_t ispan = 0; ispan < span_l2_cache->count; ++ispan)
        _rpmalloc_span_unmap(span_l2_cache->spans_dll[ispan]);
    span_l2_cache->count = 0;

    while (span_l2_cache->overflow_dll) {
        span_t* span = span_l2_cache->overflow_dll;
        span_l2_cache->overflow_dll = span->next_dll;
        _rpmalloc_span_unmap(span);
    }

    SPINLOCK_RELEASE(&span_l2_cache->lock);
}

static void
_rpmalloc_span_l2_cache_insert(const size_t span_count,
                               span_t** const span_buf,
                               const size_t count) {
    const size_t cache_limit = (1 == span_count) ?
        SPAN_L2_CACHE_MULTIPLIER * SPAN_L1_CACHE_SPANS_BUCKET_CAPACITY :
        SPAN_L2_CACHE_MULTIPLIER * (SPAN_L1_CACHE_SUPERSPANS_BUCKET_CAPACITY - (span_count >> 1));

    span_l2_cache_t* const span_l2_cache = &g_alloc_span_l2_cache[span_count - 1];

    size_t insert_count = count;
    SPINLOCK_ACQUIRE(&span_l2_cache->lock);

#  if ENABLE_STATISTICS
    span_l2_cache->stats_insert_count += count;
#  endif
    if ((span_l2_cache->count + insert_count) > cache_limit)
        insert_count = cache_limit - span_l2_cache->count;

    memcpy(span_l2_cache->spans_dll + span_l2_cache->count, span_buf, sizeof(span_t*) * insert_count);
    span_l2_cache->count += (uint32_t)insert_count;

#  if ENABLE_UNLIMITED_SPAN_L2_CACHE
    while (insert_count < count) {
#  else
    // Enable unlimited cache if huge pages, or we will leak since it is unlikely that an entire huge page
    // will be unmapped, and we're unable to partially decommit a huge page
    while ((g_config_page_size > g_config_span_size) && (insert_count < count)) {
#  endif
        span_t* const current_span = span_buf[insert_count++];
        current_span->next_dll = span_l2_cache->overflow_dll;
        span_l2_cache->overflow_dll = current_span;
    }
    SPINLOCK_RELEASE(&span_l2_cache->lock);

    span_t* keep = NULL;
    for (size_t ispan = insert_count; ispan < count; ++ispan) {
        span_t* const current_span = span_buf[ispan];
        // Keep master spans which have remaining sub-spans to avoid dangling them
        if ((current_span->flags & SPAN_FLAG_MASTER) &&
            (atomic_load32(&current_span->masterspan_remaining_spans) > (int32_t)current_span->span__count)) {
            current_span->next_dll = keep;
            keep = current_span;
        } else {
            _rpmalloc_span_unmap(current_span);
        }
    }

    if (keep) {
        SPINLOCK_ACQUIRE(&span_l2_cache->lock);

        size_t islot = 0;
        while (keep) {
            for (; islot < span_l2_cache->count; ++islot) {
                span_t* current_span = span_l2_cache->spans_dll[islot];
                if (!(current_span->flags & SPAN_FLAG_MASTER) || ((current_span->flags & SPAN_FLAG_MASTER) &&
                    (atomic_load32(&current_span->masterspan_remaining_spans) <= (int32_t)current_span->span__count))) {
                    _rpmalloc_span_unmap(current_span);
                    span_l2_cache->spans_dll[islot] = keep;
                    break;
                }
            }
            if (islot == span_l2_cache->count)
                break;
            keep = keep->next_dll;
        }

        if (keep) {
            span_t* tail = keep;
            while (tail->next_dll)
                tail = tail->next_dll;
            tail->next_dll = span_l2_cache->overflow_dll;
            span_l2_cache->overflow_dll = keep;
        }

        SPINLOCK_RELEASE(&span_l2_cache->lock);
    }
}

static size_t
_rpmalloc_span_l2_cache_extract(const size_t span_count,
                                span_t** const span_buf,
                                const size_t count) {
    span_l2_cache_t* const span_l2_cache = &g_alloc_span_l2_cache[span_count - 1];

    size_t already_extracted = 0;
    SPINLOCK_ACQUIRE(&span_l2_cache->lock);

#  if ENABLE_STATISTICS
    span_l2_cache->stats_extract_count += count;
#  endif
    size_t num_extractable = count - already_extracted;
    if (num_extractable > span_l2_cache->count)
        num_extractable = span_l2_cache->count;

    // "Transfer" spans from 'span l2 cache' 2 `span_buf` ..
    // .. from "regular" cache ?
    memcpy(span_buf + already_extracted, span_l2_cache->spans_dll + (span_l2_cache->count - num_extractable), sizeof(span_t*) * num_extractable);
    span_l2_cache->count -= (uint32_t)num_extractable;
    already_extracted += num_extractable;

    // .. from "unlimited" cache ?
    while ((already_extracted < count) && span_l2_cache->overflow_dll) {
        span_t* const current_span = span_l2_cache->overflow_dll;
        span_buf[already_extracted++] = current_span;
        span_l2_cache->overflow_dll = current_span->next_dll;
    }

#  if ENABLE_ASSERTS
    for (size_t ispan = 0; ispan < already_extracted; ++ispan) {
        rpmalloc_assert(span_buf[ispan]->span__count == span_count, "span_l2_cache span_buf count mismatch");
    }
#  endif

    SPINLOCK_RELEASE(&span_l2_cache->lock);

    return already_extracted;
}

#endif /* ENABLE_SPAN_L2_CACHE */

////////////
///
/// CPU cache
///
//////

#if ENABLE_SPAN_L1_CCACHE
// Derived from: https://stackoverflow.com/a/9194117
static inline size_t
_rpmalloc_mmap_round_size_up(const size_t requested_size) {
    rpmalloc_assert(g_config_page_size && ((g_config_page_size & (g_config_page_size - 1)) == 0), "`g_config_page_size` must be a multiple of 2");
    return (requested_size + g_config_page_size - 1) & -g_config_page_size;
}

//! Retrieves 'span l1 cache' slot based on provided `idx`
static inline span_l1_cache_t*
_rpmalloc_span_l1_ccache_get_slot(const unsigned int idx) {
    // Init checks
    rpmalloc_assert(g_span_l1_ccache_slots_baseptr, "'span l1 cache' isn't PROC INITed yet/anymore");
    rpmalloc_assert(0 != g_span_l1_ccache_ncpus, "Invalid # of CPUs  (%u)", g_span_l1_ccache_ncpus);
    // Input validation
    rpmalloc_assert(idx < g_span_l1_ccache_ncpus, "Invalid 'span l1 cache' idx  (ncpus=%u, idx=%u)", g_span_l1_ccache_ncpus, idx);

    return (span_l1_cache_t*)((uintptr_t)g_span_l1_ccache_slots_baseptr + sizeof(*g_span_l1_ccache_slots_baseptr) * idx);
}

//! Assigns the
//!   - `span_l1_cache_bucket_t` in the `OWNING_OBJ` (may be a heap OR 'span l1 cache') and
//!   - max capacity
//! based on the provided `SPAN_COUNT`
#define SPAN_L1_CACHE_GET_BUCKET_AND_CAPACITY(OWNING_OBJ, SPAN_COUNT, SPAN_BUCKET_VAR, SPAN_BUCKET_SIZE_VAR) do { \
    rpmalloc_assert((SPAN_COUNT) > 0      && (SPAN_COUNT) <= BLOCK_LARGE_CLASS_COUNT/* TODO: CHECK ??!!?? */, "Invalid span_count`"); \
    if (1 == (SPAN_COUNT)) { \
        SPAN_BUCKET_VAR = &(OWNING_OBJ)->spans_bucket; \
        SPAN_BUCKET_SIZE_VAR = SPAN_L1_CACHE_SPANS_BUCKET_CAPACITY; \
    } else { \
        SPAN_BUCKET_VAR = (span_l1_cache_bucket_t*)((OWNING_OBJ)->superspans_buckets + ((SPAN_COUNT) - 2)); \
        SPAN_BUCKET_SIZE_VAR = SPAN_L1_CACHE_SUPERSPANS_BUCKET_CAPACITY; \
    } \
} while(0)

//! Pushes provided span(s) 2 'span l1 cache'
//! Returns
//!   - `0` on success,
//!   - `-1` if preempted or `cpu_expected` mismatch  (requiring a manual restart)
static inline int
_rpmalloc_span_l1_ccache_push(span_l1_ccache_request_t* const request,
                              const unsigned int cpu_expected) {
    rpmalloc_assert(g_rpmalloc_rseq_thread_registered, "'span l1 ccache' (more precisely `rseq_abi`) isn't THREAD INITed yet/anymore");
    rpmalloc_assert(request->count_requested <= SPAN_L1_CCACHE_REQUEST_BUFFER_MAX_SIZE, "Too large `request->count_requested`");  // NOTE: `count_carried_out` shouldn't be validated as it may contains old values from prior try

    if (0 == request->count_requested) {
        request->count_carried_out = 0;
        return 0;
    }


    // Determine "bucket"
    span_l1_cache_bucket_t* spans_bucket;
    size_t span_bucket_capacity;
{   span_l1_cache_t* const span_l1_ccache_slot = _rpmalloc_span_l1_ccache_get_slot(cpu_expected);
    SPAN_L1_CACHE_GET_BUCKET_AND_CAPACITY(span_l1_ccache_slot, request->spans[0]->span__count,
                                          spans_bucket, span_bucket_capacity);

    rpmalloc_assert(request->spans[0], "`request` contains invalid span reference (may not be `NULL`)");       // Only necessary 2 prevent SEGV in following `assert`s
#if ENABLE_ASSERTS
    const uint32_t span_count = request->spans[0]->span__count;
    for (size_t i = 0; i < request->count_requested; ++i) {
        // NOTE: (Assertion down below) will only be helpful when `request` was init'ed using `SPAN_L1_CCACHE_REQUEST_INITIALIZER_ZERO` or `calloc`
        rpmalloc_assert(request->spans[i], "`request` contains invalid span reference (may not be `NULL`)");
        rpmalloc_assert(span_count == request->spans[i]->span__count, "`request->spans` shouldn't contain spans w/ different `span__count` intermixed");

        rpmalloc_assert(request->spans[i]->span_l1_ccache_last_idx < (int32_t)g_span_l1_ccache_ncpus, "Invalid `span_l1_ccache_last_idx` ... span has been most likely corrupted");  // -1 = Was never in 'span l1 ccache'
        rpmalloc_assert(!request->spans[i]->span_l1_ccache_owned, "span is already owned by 'span l1 ccache'");     // Indicates multiple references "floating around"

        request->spans[i]->span_l1_ccache_owned = 1;
    }
#endif
}


#if ENABLE_ASSERTS
    size_t cs_pre_count = 0,
           cs_post_count = 0;
#endif
#ifdef __x86_64__
    __asm__ __volatile__ goto (
        RSEQ_ASM_DEFINE_TABLE(3/* `cs_label` (address of rseq cs descriptor) */, 1f/* `start_ip` (start address of rseq cs) */, 2f/* `post_commit_ip` (address AFTER commit instruction) */, 4f/* `abort_ip` (address of abort handler (which 'resides' in different ELF section)) */)

        //  - Register CS  (clobbers rax)
        RSEQ_ASM_STORE_RSEQ_CS(1/* `start_ip` */, 3b/* `cs_label` */, RSEQ_ASM_TP_SEGMENT/* (thread pointer (pointing 2 thread control block (TCB;  SEE: https://docs.oracle.com/cd/E19683-01/817-3677/chapter8-1/index.html))) */:RSEQ_CS_OFFSET(%[rseq_offset])/* `rseq_cs` */)  /* NOTE: `rseq_offset` = thread pointer offset 2 rseq area */

        //  - Check cpu / cc-id
        RSEQ_ASM_CMP_CPU_ID(cpu_id, RSEQ_ASM_TP_SEGMENT:RSEQ_CPU_ID_FIELD_OFFSET(%[rseq_offset]), 4f/* `abort_ip` */)

        /* - Read current `spans_bucket->count`  (!!  clobbers rbx  !!)
         *   NOTE: Has 2 be done 'manually' (!! not via `InputOperands` !!) during rseq
         */
        "movq    %c[span_bucket_off_count](%[span_bucket_ptr]),    %%rbx\n\t"          // NOTE: `size_t` = QWORD
#  if ENABLE_ASSERTS
        "movq    %%rbx,                                            %[pre_count]\n\t"
#  endif

        /* - Init counter 4 # of copied spans  (!!  clobbers rcx  !!) */
        "xor     %%rcx,                                            %%rcx\n\t"

        /* - (LOOP) Check 'span l1 cache' already full? */
        "11:\n\t"
        "cmpq    %[span_bucket_capacity],                          %%rbx\n\t"
        "je      12f\n\t"

        /* - Copy span from transfer-buf 2 'span l1 cache' */
        "movq    %c[request_off_spans](%[request_ptr],%%rcx,8),    %%rax\n\t"
        "movq    %%rax,                                            %c[span_bucket_off_span](%[span_bucket_ptr],%%rbx,8)\n\t"

        /* - Increment 'span l1 cache''s count & # of spans copied counter */
        "addq    $1,                                               %%rbx\n\t"
        "addq    $1,                                               %%rcx\n\t"

        /* - Loop if not copied everything */
        "cmpq    %c[request_off_count_requested](%[request_ptr]),  %%rcx\n\t"
        "jl      11b\n\t"

        "12:\n\t"
        /* - Update `request->count_carried_out` */
        "movq    %%rcx,                                            %c[request_off_count_carried_out](%[request_ptr])\n\t"

        /* - Update `spans_bucket->count`  TODO@phil: Is this atomic ???! */
#  if ENABLE_ASSERTS
        "movq    %%rbx,                                            %[post_count]\n\t"
#  endif
        "mfence\n\t"
        "movq    %%rbx,                                            %c[span_bucket_off_count](%[span_bucket_ptr])\n\t"
        "2:\n\t"/* `post_commit_ip` */
        RSEQ_ASM_DEFINE_ABORT(4/* `abort_ip` */, ""/* `teardown` (cleanup instructions) */, abort/* `abort_label` */)
        :
#  if ENABLE_ASSERTS
          [pre_count]                      "=m"  (cs_pre_count),
          [post_count]                     "=m"  (cs_post_count)
#  endif
        : [cpu_id]                         "r"   (cpu_expected),
          [rseq_offset]                    "r"   (rseq_offset),
          [request_ptr]                    "r"   (request),
          [request_off_count_requested]    "i"   (offsetof(span_l1_ccache_request_t, count_requested)),
          [request_off_count_carried_out]  "i"   (offsetof(span_l1_ccache_request_t, count_carried_out)),
          [request_off_spans]              "i"   (offsetof(span_l1_ccache_request_t, spans)),
          [span_bucket_ptr]                "r"   (spans_bucket),
          [span_bucket_off_count]          "i"   (offsetof(span_l1_cache_bucket_t, count)),
          [span_bucket_off_span]           "i"   (offsetof(span_l1_cache_bucket_t, bin)),
          [span_bucket_capacity]           "rm"  (span_bucket_capacity)
        : "memory", "cc", "rax", "rbx", "rcx"
        : abort
    );
#else
#  error "Unsupported architecture"
#endif /* __x86_64__ */

    rseq_after_asm_goto();
    rseq_clear_rseq_cs();


#ifndef NDEBUG
    _rpmalloc_stat_add64(&g_span_l1_ccache_rseq_push_success_count, 1L);
    _rpmalloc_stat_add64(&g_span_l1_ccache_spans_push_requested_count, request->count_requested);
    _rpmalloc_stat_add64(&g_span_l1_ccache_spans_push_count, request->count_carried_out);
#endif
    rpmalloc_assert(request->count_carried_out <= request->count_requested, "Invalid 'request' count");
    rpmalloc_assert(cs_post_count == cs_pre_count + request->count_carried_out  &&
                    cs_post_count <= span_bucket_capacity, "Invalid 'span l1 ccache' count");
#if ENABLE_ASSERTS
    for (size_t i = 0; i < (size_t)(request->count_requested - request->count_carried_out); ++i) {
        request->spans[request->count_carried_out /*-1 +1*/  +i]->span_l1_ccache_owned = 0;     // Unset flag 4 spans which weren't transferred
    }
#endif
    return 0;

abort:
    rseq_after_asm_goto();
#ifndef NDEBUG
    _rpmalloc_stat_add64(&g_span_l1_ccache_rseq_push_abort_count, 1L);
#endif
#if ENABLE_ASSERTS
    for (size_t i = 0; i < request->count_requested; ++i) {
        request->spans[i]->span_l1_ccache_owned = 0;
    }
#endif
    return -1;       // Caller must handle restart
}


//! Pops requested span(s) from 'span l1 cache'
//! Returns
//!   - `0` on success,
//!   - `-1` if preempted or `cpu_expected` mismatch  (requiring a manual restart)
static inline int
_rpmalloc_span_l1_ccache_pop(span_l1_ccache_request_t* const request,
                             const unsigned int cpu_expected,
                             heap_t* const new_owner_heap) {
    rpmalloc_assert(g_rpmalloc_rseq_thread_registered, "'span l1 ccache' (more precisely `rseq_abi`) isn't THREAD INITed yet/anymore");
    rpmalloc_assert(request->count_requested <= SPAN_L1_CCACHE_REQUEST_BUFFER_MAX_SIZE, "Too large `request->count_requested`");  // NOTE: `count_carried_out` shouldn't be validated as it may contains old values from prior try

    if (0 == request->count_requested) {
        request->count_carried_out = 0;
        return 0;
    }

    // Determine "bucket"
    span_l1_cache_bucket_t* spans_bucket;
    ATTR_UNUSED size_t span_bucket_capacity;
    span_l1_cache_t* const span_l1_ccache_slot = _rpmalloc_span_l1_ccache_get_slot(cpu_expected);
    SPAN_L1_CACHE_GET_BUCKET_AND_CAPACITY(span_l1_ccache_slot, request->span_count,
                                          spans_bucket, span_bucket_capacity);

#if ENABLE_ASSERTS
    size_t cs_pre_count = 0,
           cs_post_count = 0;
#endif
#ifdef __x86_64__
    __asm__ __volatile__ goto (
        RSEQ_ASM_DEFINE_TABLE(3/* `cs_label` */, 1f/* `start_ip` */, 2f/* `post_commit_ip` */, 4f/* `abort_ip` */)

        //  - Register CS  (clobbers rax)
        RSEQ_ASM_STORE_RSEQ_CS(1/* `start_ip` */, 3b/* `cs_label` */, RSEQ_ASM_TP_SEGMENT:RSEQ_CS_OFFSET(%[rseq_offset])/* `rseq_cs` */)

        //  - Check cpu / cc-id
        RSEQ_ASM_CMP_CPU_ID(cpu_id, RSEQ_ASM_TP_SEGMENT:RSEQ_CPU_ID_FIELD_OFFSET(%[rseq_offset]), 4f/* `abort_ip` */)

        /* - Read current `span_ccache_count`  (!!  clobbers rbx  !!)
         *   NOTE: Has 2 be done 'manually' (!! not via `InputOperands` !!) during rseq
         */
        "movq    %c[span_bucket_off_count](%[span_bucket_ptr]),         %%rbx\n\t"          // NOTE: `size_t` = QWORD
#  if ENABLE_ASSERTS
        "movq    %%rbx,                                                 %[pre_count]\n\t"
#  endif

        /* - Init counter 4 # of copied spans  (!!  clobbers rcx  !!) */
        "xor     %%rcx,                                                 %%rcx\n\t"

        /* - (LOOP) Check 'span l1 cache' empty? */
        "11:\n\t"
        "testq   %%rbx,                                                 %%rbx\n\t"
        "jz      12f\n\t"

        /* - Copy span from 'span l1 cache' 2 transfer-buf */
        "subq    $1,                                                    %%rbx\n\t"          // `spans_bucket->count` -1 4 indexing
        "movq    %c[span_bucket_off_span](%[span_bucket_ptr],%%rbx,8),  %%rax\n\t"
        "movq    %%rax,                                                 %c[request_off_spans](%[request_ptr],%%rcx,8)\n\t"
        "addq    $1,                                                    %%rbx\n\t"          // restore `spans_bucket->count`

        /* - Decrement 'span l1 cache''s count & Increment # of spans copied counter */
        "subq    $1,                                                    %%rbx\n\t"
        "addq    $1,                                                    %%rcx\n\t"

        /* - Loop if not copied everything */
        "cmpq    %c[request_off_count_requested](%[request_ptr]),       %%rcx\n\t"
        "jl      11b\n\t"

        "12:\n\t"
        /* - Update `request->count_carried_out` */
        "movq    %%rcx,                                                 %c[request_off_count_carried_out](%[request_ptr])\n\t"

        /* - Update `spans_bucket->count`  TODO@phil: Is this atomic ???! */
#  if ENABLE_ASSERTS
        "movq    %%rbx,                                                 %[post_count]\n\t"
#  endif
        "mfence\n\t"
        "movq    %%rbx,                                                 %c[span_bucket_off_count](%[span_bucket_ptr])\n\t"
        "2:\n\t"/* `post_commit_ip` */
        RSEQ_ASM_DEFINE_ABORT(4/* `abort_ip` */, ""/* `teardown` (cleanup instructions) */, abort/* `abort_label` */)
        :
#  if ENABLE_ASSERTS
          [pre_count]                      "=m"  (cs_pre_count),
          [post_count]                     "=m"  (cs_post_count)
#  endif
        : [cpu_id]                         "r"   (cpu_expected),
          [rseq_offset]                    "r"   (rseq_offset),
          [request_ptr]                    "r"   (request),
          [request_off_count_requested]    "i"   (offsetof(span_l1_ccache_request_t, count_requested)),
          [request_off_count_carried_out]  "i"   (offsetof(span_l1_ccache_request_t, count_carried_out)),
          [request_off_spans]              "i"   (offsetof(span_l1_ccache_request_t, spans)),
          [span_bucket_ptr]                "r"   (spans_bucket),
          [span_bucket_off_count]          "i"   (offsetof(span_l1_cache_bucket_t, count)),
          [span_bucket_off_span]           "i"   (offsetof(span_l1_cache_bucket_t, bin))
        : "memory", "cc", "rax", "rbx", "rcx"
        : abort
    );
#else
#  error "Unsupported architecture"
#endif /* __x86_64__ */

    rseq_after_asm_goto();
    rseq_clear_rseq_cs();


#ifndef NDEBUG
    _rpmalloc_stat_add64(&g_span_l1_ccache_rseq_pop_success_count, 1L);
    _rpmalloc_stat_add64(&g_span_l1_ccache_spans_pop_requested_count, request->count_requested);
    _rpmalloc_stat_add64(&g_span_l1_ccache_spans_pop_count, request->count_carried_out);
#endif
    rpmalloc_assert(request->count_carried_out <= request->count_requested, "Invalid 'request' count");
    rpmalloc_assert(cs_pre_count == cs_post_count + request->count_carried_out  &&
                    cs_post_count <= span_bucket_capacity, "Invalid 'span l1 ccache' count");

    for (size_t i = 0; i < request->count_carried_out; ++i) {
        // NOTE: (Assertion down below) will only help if `request` was init'ed using `SPAN_L1_CCACHE_REQUEST_INITIALIZER_ZERO` or `calloc`
        rpmalloc_assert(request->spans[i], "`request->spans` shouldn't contain span references which are `NULL`");
        rpmalloc_assert(request->span_count == request->spans[i]->span__count, "`request->spans` shouldn't contain spans w/ different `span__count` intermixed");

        rpmalloc_assert(request->spans[i]->span_l1_ccache_owned, "span isn't owned by 'span l1 ccache' anymore");     // Indicates multiple references "floating around"

#if ENABLE_ASSERTS
        request->spans[i]->span_l1_ccache_owned = 0;
        request->spans[i]->span_l1_ccache_last_idx = cpu_expected;
#endif

        request->spans[i]->owner_heap = new_owner_heap;     // Set new owning heap
    }
    return 0;

abort:
    rseq_after_asm_goto();
#ifndef NDEBUG
    _rpmalloc_stat_add64(&g_span_l1_ccache_rseq_pop_abort_count, 1L);
#endif
    return -1;                                          // Caller must handle restart
}


// Auxiliary functions
//! Handles spans which couldn't be transferred (I.E., the delta b/w requested & carried out) 2 'span l1 cache'
static inline void
_rpmalloc_span_l1_ccache_push_handle_extant_spans(span_l1_ccache_request_t* const request,
                                                  const int mv_2_l2_cache,
                                                  heap_t* const heap) {

    rpmalloc_assert(NULL != request, "`request` may not be `NULL`");
    const ssize_t extant_spans_count = request->count_requested - request->count_carried_out;
    rpmalloc_assert(extant_spans_count >= 0, "Invalid `request`");

    if (0 == extant_spans_count) {
        return;
    }

#if ENABLE_ASSERTS
    {   const size_t base_idx = request->count_carried_out /*-1 +1*/;
        const uint32_t span_count = request->spans[base_idx]->span__count;
        for (size_t i = 0; i < (size_t)extant_spans_count; ++i) {
            // NOTE: (Assertion down below) will only help if `request` was init'ed using `SPAN_L1_CCACHE_REQUEST_INITIALIZER_ZERO` or `calloc`
            rpmalloc_assert(request->spans[base_idx +i], "`request->spans` shouldn't contain span references which are `NULL`");
            rpmalloc_assert(span_count == request->spans[base_idx +i]->span__count, "`request->spans` shouldn't contain spans w/ different `span_count` intermixed");
        }
    }
#endif

#if ENABLE_SPAN_L2_CACHE
    if (mv_2_l2_cache) {   // Mv 2 span-l2-cache
        rpmalloc_assert(heap, "`heap` may not be `NULL`");

        const size_t span__count = request->spans[0]->span__count;
        _rpmalloc_stat_add64(&heap->stats_l1_to_l2, extant_spans_count * span__count * g_config_span_size);
        _rpmalloc_stat_add(&heap->span_use[span__count - 1].stats_spans_to_l2, extant_spans_count);


        _rpmalloc_span_l2_cache_insert(span__count,
                                       &request->spans[request->count_carried_out /*-1 +1*/],
                                       extant_spans_count);
        return;
    }
#else
    rpmalloc_assert(! mv_2_l2_cache, "span-l2-cache isn't available");
    WARN_SUPPRESS_UNUSED(mv_2_l2_cache);
#endif
#  if ! ENABLE_SPAN_L2_CACHE || ! ENABLE_STATISTICS
    WARN_SUPPRESS_UNUSED(heap);
#  endif

    for (size_t i = 0; i < (size_t)extant_spans_count; ++i) {
        _rpmalloc_span_unmap( request->spans[request->count_carried_out /*-1 +1*/ + i] );
    }
}
#endif /* ENABLE_SPAN_L1_CCACHE */

////////////
///
/// Heap control
///
//////

static void _rpmalloc_deallocate_huge(span_t*);

//! Store the given spans as reserve in the given heap
static void
_rpmalloc_heap_set_reserved_spans(heap_t* const heap,
                                  span_t* const master_span,
                                  span_t* const reserve,
                                  const size_t reserve_span_count) {
    heap->span_reserve_master = master_span;
    heap->span_reserve = reserve;
    heap->spans_reserve_count = (uint32_t)reserve_span_count;
}

//! Adopt the "deferred span cache list", optionally extracting the 1st single span for immediate re-use
static void
_rpmalloc_heap_cache_adopt_deferred(heap_t* const heap, span_t** const extracted_span_ptr) {
    // Go through "deferred span cache list"
    span_t* span = (span_t*)((void*)atomic_exchange_ptr_acquire(&heap->span_free_deferred_sll, NULL));
    while (span) {
        rpmalloc_assert(span->owner_heap == heap, "`span->owner_heap` corrupted");

        span_t* const next_span = span->heap_span_free_deferred_sll;
        if EXPECTED(span->block_sizeclass_idx < BLOCK_SMALL_MEDIUM_CLASS_COUNT) {
            rpmalloc_assert(heap->fully_inited_spans_count, "`heap->fully_inited_spans_count` corrupted");

            --heap->fully_inited_spans_count;
            _rpmalloc_stat_dec(&heap->span_use[0].stats_spans_deferred);
            _rpmalloc_stat_dec(&heap->span_use[0].current);
            _rpmalloc_stat_dec(&heap->stats_block_sizeclass_use[span->block_sizeclass_idx].spans_current);
            if (extracted_span_ptr/*does the caller want a span?*/ && !*extracted_span_ptr /*has a span already been extracted?*/)
                *extracted_span_ptr = span;
            else
                _rpmalloc_heap_span_lx_cache_insert(heap, span);

        } else {
            if (BLOCK_SIZE_CLASS_HUGE == span->block_sizeclass_idx) {
                _rpmalloc_deallocate_huge(span);

            } else {
                rpmalloc_assert(BLOCK_SIZE_CLASS_LARGE == span->block_sizeclass_idx, "`span->block_sizeclass_idx` invalid");
                rpmalloc_assert(heap->fully_inited_spans_count, "`heap->fully_inited_spans_count` corrupted");
                --heap->fully_inited_spans_count;
                const uint32_t idx = span->span__count - 1;
                _rpmalloc_stat_dec(&heap->span_use[idx].stats_spans_deferred);
                _rpmalloc_stat_dec(&heap->span_use[idx].current);
                if (!idx && extracted_span_ptr && !*extracted_span_ptr)
                    *extracted_span_ptr = span;
                else
                    _rpmalloc_heap_span_lx_cache_insert(heap, span);
            }
        }
        span = next_span;
    }
}

static void
_rpmalloc_heap_unmap(heap_t* const heap) {
    if (!heap->master_heap) {
        if ((heap->finalize > 1) && !atomic_load32(&heap->child_count)) {
            span_t* span = (span_t*)((uintptr_t)heap & g_config_span_mask);      // Span which stores this heap
            _rpmalloc_span_unmap(span);
        }
    } else {
        if (atomic_decr32(&heap->master_heap->child_count) == 0) {
            _rpmalloc_heap_unmap(heap->master_heap);
        }
    }
}

static void
_rpmalloc_heap_global_finalize(heap_t* const heap) {
    if (heap->finalize++ > 1) {
        --heap->finalize;
        return;
    }

    _rpmalloc_heap_finalize(heap);

#if ENABLE_SPAN_L1_TCACHE
    for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass) {
#  define SPAN_L1_TCACHE_GET_BUCKET(ICLASS, HEAP) ( (!(ICLASS)) ? &(HEAP)->span_l1_tcache.spans_bucket : (span_l1_cache_bucket_t*)((HEAP)->span_l1_tcache.superspans_buckets + ((ICLASS) - 1)) )
        span_l1_cache_bucket_t* const spans_bucket = SPAN_L1_TCACHE_GET_BUCKET(iclass, heap);
        for (size_t ispan = 0; ispan < spans_bucket->count; ++ispan)
            _rpmalloc_span_unmap(spans_bucket->bin[ispan]);
        spans_bucket->count = 0;
    }
#endif

    if (heap->fully_inited_spans_count) {
        --heap->finalize;
        return;
    }

    for (size_t iclass = 0; iclass < BLOCK_SMALL_MEDIUM_CLASS_COUNT; ++iclass) {
        if (heap->sizeclass_spans[iclass].active_spans_block_freelist || heap->sizeclass_spans[iclass].partially_inited_spans_dll) {
            --heap->finalize;
            return;
        }
    }
    //Heap is now completely free, unmap & remove from heap list
    const size_t list_idx = (size_t)heap->id % HEAP_ARRAY_SIZE;
    heap_t* cur_heap = g_alloc_heaps[list_idx];
    if (cur_heap == heap) {                             // was head in list (immediate match)
        g_alloc_heaps[list_idx] = heap->id_next_sll;    // .. unlink
    } else {                                            // traverse sll until we find heap -> then unlink
        while (cur_heap->id_next_sll != heap)
            cur_heap = cur_heap->id_next_sll;
        cur_heap->id_next_sll = heap->id_next_sll;
    }

    _rpmalloc_heap_unmap(heap);
}

//! Insert a single span into 'span l1 cache', releasing to 'span l2 cache' if overflow
static void
_rpmalloc_heap_span_lx_cache_insert(heap_t* const heap, span_t* span) {
    if UNEXPECTED(0 != heap->finalize) {
        _rpmalloc_span_unmap(span);
        _rpmalloc_heap_global_finalize(heap);
        return;
    }

#if ENABLE_SPAN_L1_TCACHE | ENABLE_SPAN_L1_CCACHE
    _rpmalloc_stat_inc(&heap->span_use[span->span__count - 1].stats_spans_to_cache);

    if (1 == span->span__count) {
        // (1.) Push 2 'span l1 cache'
#  if ENABLE_SPAN_L1_TCACHE
        span_l1_cache_bucket_t* const spans_bucket = &heap->span_l1_tcache.spans_bucket;
        spans_bucket->bin[spans_bucket->count++] = span;
#  else /* ENABLE_SPAN_L1_CCACHE */
#    if ENABLE_SPAN_L2_CACHE
#      define _SPAN_L1_CCACHE__PUSH_SPAN(HEAP, REQUEST) _rpmalloc_span_l1_ccache_push_handle_extant_spans(&REQUEST, 1, HEAP)
#    else
#      define _SPAN_L1_CCACHE__PUSH_SPAN(HEAP, REQUEST) _rpmalloc_span_l1_ccache_push_handle_extant_spans(&REQUEST, 0, NULL)
#    endif /* ENABLE_SPAN_L2_CACHE */
#    define SPAN_L1_CCACHE__PUSH_SPAN(HEAP, SPAN) do { \
        /* NOTE: Insert in2 'span l1 cache' might fail since we're not guaranteed (unlike the 'span l1 tcache') \
         *        2 have @ least 1 free slot in the 'span l1 cache' remaining \
         */ \
        span_l1_ccache_request_t _request = SPAN_L1_CCACHE_REQUEST_INITIALIZER_PUSH(1); \
        _request.spans[0] = SPAN;     SPAN = NULL /* `span` MAY now be owned by 'span l1 cache' */; \
        while( -1 == _rpmalloc_span_l1_ccache_push(&_request, SPAN_CCACHE_SLOT_GET_INDEX()) ) \
            ; \
        /* (1.1.) Handle case "'span l1 ccache' was already full" by mv'ing 2 'span l2 cache' (or unmap) \
         *        ( NOTE: We can't rely on a thread being able 2 "clear" the current 'span l1 ccache' \
         *          "slot" as it might be rescheduled @ any time (2 a different CPU) ) \
         */ \
        _SPAN_L1_CCACHE__PUSH_SPAN(HEAP, _request); \
    } while(0)

        const size_t span_span_count = span->span__count;   // NOTE: We'll set `span` 2 `NULL` later, THUS: Make copy of `span__count`
        SPAN_L1_CCACHE__PUSH_SPAN(heap, span);
#  endif /* ENABLE_SPAN_L1_TCACHE */

        // (2.) Transfer "excess" from 'span l1 cache' 2 'span l2 cache' when 'span l1 cache' is full  (preventing "heap-blowup")
        //      NOTE: We're NOT guaranteed that we clean up the same 'span l1 cache' slot 2 which we pushed prior
        if (SPAN_L1_CACHE_SPANS_BUCKET_CAPACITY ==
#  if ENABLE_SPAN_L1_TCACHE
            spans_bucket->count
#  else /* ENABLE_SPAN_L1_CCACHE */
            _rpmalloc_span_l1_ccache_get_slot( SPAN_CCACHE_SLOT_GET_INDEX() )->spans_bucket.count
#  endif /* ENABLE_SPAN_L1_TCACHE */
                             ) {
            const size_t num_spans_2_be_transferred = SPAN_L1_2_L2_CACHE_TRANSFER_COUNT;
#  if ENABLE_SPAN_L1_TCACHE
            const size_t remain_count = SPAN_L1_CACHE_SPANS_BUCKET_CAPACITY - num_spans_2_be_transferred;
#    if ENABLE_SPAN_L2_CACHE
            _rpmalloc_stat_add64(&heap->stats_l1_to_l2, num_spans_2_be_transferred * g_config_span_size);
            _rpmalloc_stat_add(&heap->span_use[span->span__count - 1].stats_spans_to_l2, num_spans_2_be_transferred);
            _rpmalloc_span_l2_cache_insert(span->span__count, spans_bucket->bin + remain_count, num_spans_2_be_transferred);
#    else
            for (size_t ispan = 0; ispan < num_spans_2_be_transferred; ++ispan)
                _rpmalloc_span_unmap(spans_bucket->bin[remain_count + ispan]);
#    endif /* ENABLE_SPAN_L2_CACHE */
            spans_bucket->count = remain_count;
#  else /* ENABLE_SPAN_L1_CCACHE */
#    if ENABLE_SPAN_L2_CACHE
#      define _SPAN_L1_CCACHE__REDUCE_HEAP_BLOWUP(HEAP, SPAN_COUNT, REQUEST) do { \
            _rpmalloc_stat_add64(&HEAP->stats_l1_to_l2, REQUEST.count_carried_out * SPAN_COUNT * g_config_span_size); \
            _rpmalloc_stat_add(&HEAP->span_use[SPAN_COUNT - 1].stats_spans_to_l2, REQUEST.count_carried_out); \
            _rpmalloc_span_l2_cache_insert(SPAN_COUNT, REQUEST.spans, REQUEST.count_carried_out); \
       } while(0)
#    else
#      define _SPAN_L1_CCACHE__REDUCE_HEAP_BLOWUP(HEAP, SPAN_COUNT, REQUEST) do { \
           for (size_t i = 0; i < REQUEST.count_carried_out; ++i) {\
               _rpmalloc_span_unmap( REQUEST.spans[i] ); \
           } \
      } while(0)
#    endif /* ENABLE_SPAN_L2_CACHE */
#    define SPAN_L1_CCACHE__REDUCE_HEAP_BLOWUP(HEAP, SPAN_COUNT, TRANSFER_COUNT) do { \
          span_l1_ccache_request_t _request = SPAN_L1_CCACHE_REQUEST_INITIALIZER_POP(SPAN_COUNT, TRANSFER_COUNT); \
          /* (1.) Pop spans from 'span l1 cache'  (NOTE: `TRANSFER_COUNT` MIGHT BE != `request.count_carried_out`) */ \
          while( -1 == _rpmalloc_span_l1_ccache_pop(&_request, SPAN_CCACHE_SLOT_GET_INDEX(), heap) ) \
              ; \
          \
          /* (2.) Move spans 2 'span l2 cache' (or unmap if non-existent) */ \
          _SPAN_L1_CCACHE__REDUCE_HEAP_BLOWUP(HEAP, SPAN_COUNT, _request); \
       } while(0)

            SPAN_L1_CCACHE__REDUCE_HEAP_BLOWUP(heap, span_span_count, num_spans_2_be_transferred);
#  endif /* ENABLE_SPAN_L1_TCACHE */
        }

    } else {            // span->span__count > 1
        const size_t cache_idx = span->span__count - 2;
        const size_t cache_limit = (SPAN_L1_CACHE_SUPERSPANS_BUCKET_CAPACITY - (span->span__count >> 1));

        // (1.) Push 2 'span l1 cache'
#  if ENABLE_SPAN_L1_TCACHE
        span_l1_cache_bucket_large_t* const spans_bucket = heap->span_l1_tcache.superspans_buckets + cache_idx;
        spans_bucket->bin[spans_bucket->count++] = span;
#  else /* ENABLE_SPAN_L1_CCACHE */
        const size_t span_span_count = span->span__count;   // NOTE: We'll set `span` 2 `NULL` later, THUS: Make copy of `span__count`
        SPAN_L1_CCACHE__PUSH_SPAN(heap, span);
#  endif /* ENABLE_SPAN_L1_TCACHE */

        // (2.) Transfer "excess" from 'span l1 cache' 2 'span l2 cache'  (preventing "heap-blowup")
        if (cache_limit ==
#  if ENABLE_SPAN_L1_TCACHE
            spans_bucket->count
#  else /* ENABLE_SPAN_L1_CCACHE */
            (_rpmalloc_span_l1_ccache_get_slot( SPAN_CCACHE_SLOT_GET_INDEX() )->superspans_buckets + cache_idx)->count
#  endif /* ENABLE_SPAN_L1_TCACHE */
                ) {
            const size_t transfer_limit = 2 + (cache_limit >> 2);
            const size_t transfer_count = (SPAN_L1_2_L2_CACHE_LARGE_TRANSFER_COUNT <= transfer_limit ? SPAN_L1_2_L2_CACHE_LARGE_TRANSFER_COUNT : transfer_limit);
#  if ENABLE_SPAN_L1_TCACHE
            const size_t remain_count = cache_limit - transfer_count;
#    if ENABLE_SPAN_L2_CACHE
            _rpmalloc_stat_add64(&heap->stats_l1_to_l2, transfer_count * span->span__count * g_config_span_size);
            _rpmalloc_stat_add(&heap->span_use[span->span__count - 1].stats_spans_to_l2, transfer_count);
            _rpmalloc_span_l2_cache_insert(span->span__count, spans_bucket->bin + remain_count, transfer_count);
#    else
            for (size_t ispan = 0; ispan < transfer_count; ++ispan)
                _rpmalloc_span_unmap(spans_bucket->bin[remain_count + ispan]);
#    endif /* ENABLE_SPAN_L2_CACHE */
            spans_bucket->count = remain_count;
#  else /* ENABLE_SPAN_L1_CCACHE */
            SPAN_L1_CCACHE__REDUCE_HEAP_BLOWUP(heap, span_span_count, transfer_count);
#  endif /* ENABLE_SPAN_L1_TCACHE */
        }
    }
#else
    WARN_SUPPRESS_UNUSED(heap);
    _rpmalloc_span_unmap(span);
#endif /* ENABLE_SPAN_L1_TCACHE | ENABLE_SPAN_L1_CCACHE */
}

//! Extract the given # of spans from the different cache levels
static span_t*
_rpmalloc_span_lx_cache_extract(heap_t* const heap, const size_t span_count) {
#if ENABLE_SPAN_L1_TCACHE
    span_l1_cache_bucket_t* const spans_bucket = (1 == span_count) ? &heap->span_l1_tcache.spans_bucket : (span_l1_cache_bucket_t*)(heap->span_l1_tcache.superspans_buckets + (span_count - 2));       // $$$$$  TODO: REFACTOR & USE e.g., `SPAN_L1_CACHE_GET_BUCKET_AND_CAPACITY`  $$$$$
    if (spans_bucket->count) {
        _rpmalloc_stat_inc(&heap->span_use[span_count - 1].stats_spans_from_cache);
        return spans_bucket->bin[--spans_bucket->count];
    }
#elif ENABLE_SPAN_L1_CCACHE
{   // Pop SINGLE span from 'span l1 cache'  (NOTE: no direct "target cache")
    span_l1_ccache_request_t request = SPAN_L1_CCACHE_REQUEST_INITIALIZER_POP(span_count, 1);
    while( -1 == _rpmalloc_span_l1_ccache_pop(&request, SPAN_CCACHE_SLOT_GET_INDEX(), heap) )
        ;
#  if ENABLE_STATISTICS
    if (request.count_carried_out) {
        _rpmalloc_stat_inc(&heap->span_use[span_count - 1].stats_spans_from_cache);
    }
#  else
    WARN_SUPPRESS_UNUSED(heap);
#  endif
    return request.count_carried_out ? request.spans[0] : NULL;
}
#else
    WARN_SUPPRESS_UNUSED(heap);
    WARN_SUPPRESS_UNUSED(span_count);
#endif /* ENABLE_SPAN_L1_TCACHE */
    return NULL;
}

static span_t*
_rpmalloc_heap_cache_deferred_extract(heap_t* const heap, const size_t span_count) {
    span_t* span = NULL;
    if (1 == span_count) {
        _rpmalloc_heap_cache_adopt_deferred(heap, &span);
    } else {
        _rpmalloc_heap_cache_adopt_deferred(heap, NULL);
        span = _rpmalloc_span_lx_cache_extract(heap, span_count);
    }
    return span;
}

static span_t*
_rpmalloc_heap_reserved_extract(heap_t* const heap, const size_t span_count) {
    if (heap->spans_reserve_count >= span_count)
        return _rpmalloc_span_map(heap, span_count);
    return NULL;
}

//! Extract a span from the span l2 (a.k.a., global) cache
static span_t*
_rpmalloc_heap_span_l2_cache_extract(heap_t* const heap, const size_t span_count) {
#if ENABLE_SPAN_L2_CACHE
#  define SPAN_L1_CACHE_GET_BUCKET_AND_CACHE_TRANSFER_COUNT(OWNING_OBJ, SPAN_COUNT, SPAN_BUCKET_VAR, CACHE_TRANSFER_COUNT_VAR) do { \
      rpmalloc_assert((SPAN_COUNT) > 0      && (SPAN_COUNT) <= BLOCK_LARGE_CLASS_COUNT/* TODO: CHECK ??!!?? */, "Invalid span_count`"); \
      if (1 == (SPAN_COUNT)) { \
          SPAN_BUCKET_VAR = &(OWNING_OBJ).spans_bucket; \
          CACHE_TRANSFER_COUNT_VAR = SPAN_L1_2_L2_CACHE_TRANSFER_COUNT; \
      } else { \
          SPAN_BUCKET_VAR = (span_l1_cache_bucket_t*)((OWNING_OBJ).superspans_buckets + ((SPAN_COUNT) - 2)); \
          CACHE_TRANSFER_COUNT_VAR = SPAN_L1_2_L2_CACHE_LARGE_TRANSFER_COUNT; \
      } \
  }   while(0)
    span_l1_cache_bucket_t* spans_bucket;
    size_t wanted_count;
#  if ENABLE_SPAN_L1_TCACHE
    SPAN_L1_CACHE_GET_BUCKET_AND_CACHE_TRANSFER_COUNT(heap->span_l1_tcache, span_count, spans_bucket, wanted_count);
    // (1.) Refill 'span l1 tcache' w/ spans from the 'span l2 cache'
    spans_bucket->count = _rpmalloc_span_l2_cache_extract(span_count, spans_bucket->bin, wanted_count);

    // If 'span l1 tcache' was successfully (re)filled ..
    if (spans_bucket->count) {
        _rpmalloc_stat_add64(&heap->stats_l2_to_l1, span_count * spans_bucket->count * g_config_span_size);
        _rpmalloc_stat_add(&heap->span_use[span_count - 1].stats_spans_from_global, spans_bucket->count);
    // (2.) Return span from 'span l1 tcache'
        return spans_bucket->bin[--spans_bucket->count];
    }
#  else /* ENABLE_SPAN_L1_CCACHE */
{   SPAN_L1_CACHE_GET_BUCKET_AND_CACHE_TRANSFER_COUNT(*_rpmalloc_span_l1_ccache_get_slot( SPAN_CCACHE_SLOT_GET_INDEX() ), span_count, spans_bucket, wanted_count);
    // (1.) Refill 'span l1 cache' w/ spans from the 'span l2 cache'
    span_l1_ccache_request_t request = SPAN_L1_CCACHE_REQUEST_INITIALIZER_ZERO;
    wanted_count =     wanted_count   - spans_bucket->count /* refill spans 4 'span l1 cache' (stale estimate if preempted inb/w) */   +1 /* span 2 be returned */;
    request.count_requested = _rpmalloc_span_l2_cache_extract(span_count, request.spans, wanted_count);

    // If 'span l2 cache' wasn't empty .. -> transfer them back 2 'span l1 ccache'
    if (request.count_requested) {
        // Push all spans except the last
        --request.count_requested;
        while (-1 == _rpmalloc_span_l1_ccache_push(&request, SPAN_CCACHE_SLOT_GET_INDEX()) )
            ;

#if ENABLE_STATISTICS
        if (request.count_carried_out) {
            _rpmalloc_stat_add64(&heap->stats_l2_to_l1, span_count * request.count_carried_out * g_config_span_size);
            _rpmalloc_stat_add(&heap->span_use[span_count - 1].stats_spans_from_global, request.count_carried_out);
        }
#endif

        // Mv spans which didn't fit back  (-> information was stale)
        _rpmalloc_span_l1_ccache_push_handle_extant_spans(&request, 1, heap);

        // (2.) Return "reserved" span
        return request.spans[request.count_requested /*+1     -1 */];
    }
}
#  endif /* ENABLE_SPAN_L1_TCACHE */
#endif /* ENABLE_SPAN_L2_CACHE */
    WARN_SUPPRESS_UNUSED(heap);
    WARN_SUPPRESS_UNUSED(span_count);
    return NULL;
}

static void
_rpmalloc_inc_span_statistics(heap_t* const heap, const size_t span_count, const uint32_t class_idx) {
#if ENABLE_ADAPTIVE_SPAN_L1_CACHE || ENABLE_STATISTICS
    uint32_t idx = (uint32_t)span_count - 1;
    uint32_t current_count = (uint32_t)atomic_incr32(&heap->span_use[idx].current);
    if (current_count > (uint32_t)atomic_load32(&heap->span_use[idx].high))
        atomic_store32(&heap->span_use[idx].high, (int32_t)current_count);
    _rpmalloc_stat_add_peak(&heap->stats_block_sizeclass_use[class_idx].spans_current, 1, heap->stats_block_sizeclass_use[class_idx].spans_peak);
#else
    WARN_SUPPRESS_UNUSED(heap);
    WARN_SUPPRESS_UNUSED(span_count);
    WARN_SUPPRESS_UNUSED(class_idx);
#endif
}

//! Get a span from 1 of the cache levels ('span l1 cache', reserved, 'span l2 cache') or fallback to mapping more memory
static span_t*
_rpmalloc_heap_span_lx_cache_extract(heap_t* const heap,
                                     heap_sizeclass_spans_t* const heap_sizeclass_spans,
                                     size_t span_count,
                                     const uint32_t class_idx) {
    span_t* span;
#if ENABLE_SPAN_L1_TCACHE || ENABLE_SPAN_L1_CCACHE
    // (1.) Get span from "early level cache"
    if (heap_sizeclass_spans && heap_sizeclass_spans->fully_inited_spans_dll) {
        span = heap_sizeclass_spans->fully_inited_spans_dll;

        // (1.1.) Refill "early level cache" from 'span l1 cache' ??!
#  if ENABLE_SPAN_L1_TCACHE
        heap_sizeclass_spans->fully_inited_spans_dll = (heap->span_l1_tcache.spans_bucket.count ? heap->span_l1_tcache.spans_bucket.bin[--heap->span_l1_tcache.spans_bucket.count] : NULL);
#  else /* ENABLE_SPAN_L1_CCACHE */
{       span_l1_ccache_request_t request = SPAN_L1_CCACHE_REQUEST_INITIALIZER_POP(span_count, 1);
        while( -1 == _rpmalloc_span_l1_ccache_pop(&request, SPAN_CCACHE_SLOT_GET_INDEX(), heap) )
            ;
        heap_sizeclass_spans->fully_inited_spans_dll = (request.count_carried_out) ? request.spans[0] : NULL/* 'span l1 cache' was empty */;
}
#  endif /* ENABLE_SPAN_L1_TCACHE */
        _rpmalloc_inc_span_statistics(heap, span_count, class_idx);
        return span;
    }
#else
    WARN_SUPPRESS_UNUSED(heap_sizeclass_spans);
#endif /* ENABLE_SPAN_L1_TCACHE || ENABLE_SPAN_L1_CCACHE */
    // (2.) Early level cache was empty -> try 'span lx caches' or span reserve
    // Allow 50% overhead to increase cache hits
    const size_t base_span_count = span_count;
    size_t limit_span_count = (span_count > 2) ? (span_count + (span_count >> 1)) : span_count;
    if (limit_span_count > BLOCK_LARGE_CLASS_COUNT)
        limit_span_count = BLOCK_LARGE_CLASS_COUNT;

    do {
        span = _rpmalloc_span_lx_cache_extract(heap, span_count);
        if EXPECTED(NULL != span) {
            _rpmalloc_stat_inc(&heap->stats_block_sizeclass_use[class_idx].spans_from_cache);
            _rpmalloc_inc_span_statistics(heap, span_count, class_idx);
            return span;
        }
        span = _rpmalloc_heap_cache_deferred_extract(heap, span_count);
        if EXPECTED(NULL != span) {
            _rpmalloc_stat_inc(&heap->stats_block_sizeclass_use[class_idx].spans_from_cache);
            _rpmalloc_inc_span_statistics(heap, span_count, class_idx);
            return span;
        }
        span = _rpmalloc_heap_reserved_extract(heap, span_count);
        if EXPECTED(NULL != span) {
            _rpmalloc_stat_inc(&heap->stats_block_sizeclass_use[class_idx].spans_from_reserved);
            _rpmalloc_inc_span_statistics(heap, span_count, class_idx);
            return span;
        }
        span = _rpmalloc_heap_span_l2_cache_extract(heap, span_count);
        if EXPECTED(NULL != span) {
            _rpmalloc_stat_inc(&heap->stats_block_sizeclass_use[class_idx].spans_from_cache);
            _rpmalloc_inc_span_statistics(heap, span_count, class_idx);
            return span;
        }
        ++span_count;
    } while (span_count <= limit_span_count);

    // (3.) Final fallback: Map in more VM
    span = _rpmalloc_span_map(heap, base_span_count);
    _rpmalloc_inc_span_statistics(heap, base_span_count, class_idx);
    _rpmalloc_stat_inc(&heap->stats_block_sizeclass_use[class_idx].spans_map_calls);
    return span;
}

static void
_rpmalloc_heap_initialize(heap_t* const heap) {
    _rpmalloc_memset_const(heap, 0, sizeof(heap_t));
    //Get a new heap ID
    heap->id = 1 + atomic_incr32(&g_alloc_heap_id);

    //Link in heap in heap ID map
    const size_t list_idx = (size_t)heap->id % HEAP_ARRAY_SIZE;
    heap->id_next_sll = g_alloc_heaps[list_idx];
    g_alloc_heaps[list_idx] = heap;
}

static void
_rpmalloc_heap_orphan(heap_t* heap) {
// Link in `heap` as new list head of orphaned sll
    heap->owner_thread = (uintptr_t)-1;
    heap_t** const heap_list = &g_alloc_orphan_heaps_sll;
    heap->orphan_next_sll = *heap_list;         // Link `heap` in as new head of the list
    *heap_list = heap;                          // Update 2 point 2 new head
}

//! Allocate a new heap from newly mapped memory pages
static heap_t*
_rpmalloc_heap_alloc_new(void) {
    // Map in pages for a 16 heaps. If page size is greater than required size for this, map a page &
    // use 1st part for heaps & remaining part for spans for allocations. Adds a lot of complexity,
    // but saves a lot of memory on systems where page size > 64 spans (4MiB)
    const size_t heap_aligned_size = 16 * ((sizeof(heap_t) + 15) / 16);

    size_t heap_request_count = 16;
    size_t heap_span_count = ((heap_aligned_size * heap_request_count) + sizeof(span_t) + g_config_span_size - 1) / g_config_span_size;

    // If there are global reserved spans, use these first
    span_t* span = (g_alloc_global_span_reserve_count >= heap_span_count) ? _rpmalloc_global_get_reserved_spans(heap_span_count) : NULL;

    size_t block_size = g_config_span_size * heap_span_count;
    size_t span_count = heap_span_count;
    if (!span) {
        if (g_config_page_size > block_size) {
            span_count = g_config_page_size / g_config_span_size;
            block_size = g_config_page_size;
            // If using huge pages, make sure to grab enough heaps to avoid reallocating a huge page just to serve new heaps
            const size_t heap_possible_count = (block_size - sizeof(span_t)) / heap_aligned_size;
            if (heap_possible_count >= (heap_request_count * 16))
                heap_request_count *= 16;
            else if (heap_possible_count < heap_request_count)
                heap_request_count = heap_possible_count;
            heap_span_count = ((heap_aligned_size * heap_request_count) + sizeof(span_t) + g_config_span_size - 1) / g_config_span_size;
        }

        size_t align_offset = 0;
        span = (span_t*)_rpmalloc_mmap(block_size, &align_offset);
        if (!span)
            return NULL;

        // Master span will contain the heaps
        _rpmalloc_stat_inc(&g_stats_master_spans);
        _rpmalloc_span_init(span, span_count, heap_span_count, align_offset);
    }

    const size_t remain_size = g_config_span_size - sizeof(span_t);
    heap_t* const heap = (heap_t*)pointer_add_offset(span, sizeof(span_t));
    _rpmalloc_heap_initialize(heap);

    // Put extra heaps as orphans
    size_t num_heaps = remain_size / heap_aligned_size;
    if (num_heaps < heap_request_count)
        num_heaps = heap_request_count;
    atomic_store32(&heap->child_count, (int32_t)num_heaps - 1);
    heap_t* extra_heap = (heap_t*)pointer_add_offset(heap, heap_aligned_size);
    while (num_heaps > 1) {
        _rpmalloc_heap_initialize(extra_heap);
        extra_heap->master_heap = heap;
        _rpmalloc_heap_orphan(extra_heap);
        extra_heap = (heap_t*)pointer_add_offset(extra_heap, heap_aligned_size);
        --num_heaps;
    }

    if (span_count > heap_span_count) {
        // Cap reserved spans
        size_t remain_count = span_count - heap_span_count;
        size_t reserve_count = (remain_count > g_config_heap_reserve_count ? g_config_heap_reserve_count : remain_count);
        span_t* remain_span = (span_t*)pointer_add_offset(span, heap_span_count * g_config_span_size);
        _rpmalloc_heap_set_reserved_spans(heap, span, remain_span, reserve_count);

        if (remain_count > reserve_count) {
            // Set to global reserved spans
            remain_span = (span_t*)pointer_add_offset(remain_span, reserve_count * g_config_span_size);
            reserve_count = remain_count - reserve_count;
            _rpmalloc_global_set_reserved_spans(span, remain_span, reserve_count);
        }
    }

    return heap;
}

static heap_t*
_rpmalloc_heap_extract_orphan(heap_t** const heap_list) {
    heap_t* const heap = *heap_list;
    *heap_list = (heap ? heap->orphan_next_sll : NULL);
    return heap;
}

//! Allocate a new heap, potentially reusing a previously orphaned heap
static heap_t*
_rpmalloc_heap_alloc_orphaned_or_new(void) {
    heap_t* heap = NULL;
    SPINLOCK_ACQUIRE(&g_alloc_global_lock);
    heap = _rpmalloc_heap_extract_orphan(&g_alloc_orphan_heaps_sll);
    if (!heap)
        heap = _rpmalloc_heap_alloc_new();
    SPINLOCK_RELEASE(&g_alloc_global_lock);

    if (heap)
        _rpmalloc_heap_cache_adopt_deferred(heap, NULL);

    return heap;
}

static void
_rpmalloc_heap_release(void* const heapptr,
                       const char release_cache) {
    heap_t* const heap = (heap_t*)heapptr;
    if (!heap)
        return;
    //Release 'span l1 cache' spans back to 'span l2 cache'
    _rpmalloc_heap_cache_adopt_deferred(heap, NULL);
    if (release_cache  || heap->finalize) {
#if ENABLE_SPAN_L1_TCACHE
        for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass) {
            span_l1_cache_bucket_t* spans_bucket = SPAN_L1_TCACHE_GET_BUCKET(iclass, heap);
            if (!spans_bucket->count)
                continue;
#  if ENABLE_SPAN_L2_CACHE
            if (heap->finalize) {
                for (size_t ispan = 0; ispan < spans_bucket->count; ++ispan)
                    _rpmalloc_span_unmap(spans_bucket->bin[ispan]);
            } else {
                _rpmalloc_stat_add64(&heap->stats_l1_to_l2, spans_bucket->count * (iclass + 1) * g_config_span_size);
                _rpmalloc_stat_add(&heap->span_use[iclass].stats_spans_to_l2, spans_bucket->count);
                _rpmalloc_span_l2_cache_insert(iclass + 1, spans_bucket->bin, spans_bucket->count);
            }
#  else
            for (size_t ispan = 0; ispan < spans_bucket->count; ++ispan)
                _rpmalloc_span_unmap(spans_bucket->bin[ispan]);
#  endif /* ENABLE_SPAN_L2_CACHE */
            spans_bucket->count = 0;
        }
#endif /* ENABLE_SPAN_L1_TCACHE */
    }

    if (get_thread_heap_raw() == heap)
        set_thread_heap(NULL);

#if ENABLE_STATISTICS
    atomic_decr32(&g_stats_memory_active_heaps);
    rpmalloc_assert(atomic_load32(&g_stats_memory_active_heaps) >= 0, "Still active heaps during finalization");
#endif

    // If we are forcibly terminating w/ _exit the state of the
    // lock atomic is unknown & it's best to just go ahead & exit
    if (get_thread_id() != g_alloc_main_thread_id) {
        SPINLOCK_ACQUIRE(&g_alloc_global_lock);
    }
    _rpmalloc_heap_orphan(heap);
    SPINLOCK_RELEASE(&g_alloc_global_lock);
}

static void
_rpmalloc_heap_release_raw(void* const heapptr, const char release_cache) {
    _rpmalloc_heap_release(heapptr, release_cache);
}

static void
_rpmalloc_heap_release_raw_fc(void* const heapptr) {
    _rpmalloc_heap_release_raw(heapptr, 1);
}

static void
_rpmalloc_heap_finalize(heap_t* const heap) {
    if (heap->spans_reserve_count) {
        span_t* span = _rpmalloc_span_map(heap, heap->spans_reserve_count);
        _rpmalloc_span_unmap(span);
        heap->spans_reserve_count = 0;
    }

    _rpmalloc_heap_cache_adopt_deferred(heap, NULL);

    for (size_t iclass = 0; iclass < BLOCK_SMALL_MEDIUM_CLASS_COUNT; ++iclass) {
        if (heap->sizeclass_spans[iclass].fully_inited_spans_dll)
            _rpmalloc_span_unmap(heap->sizeclass_spans[iclass].fully_inited_spans_dll);
        heap->sizeclass_spans[iclass].fully_inited_spans_dll = NULL;
        span_t* span = heap->sizeclass_spans[iclass].partially_inited_spans_dll;
        while (span) {
            span_t* next = span->next_dll;
            _rpmalloc_span_finalize(heap, iclass, span, &heap->sizeclass_spans[iclass].partially_inited_spans_dll);
            span = next;
        }
        // If class still has a free list it must be a full span
        if (heap->sizeclass_spans[iclass].active_spans_block_freelist) {
            span_t* const sizeclass_active_span = (span_t*)((uintptr_t)heap->sizeclass_spans[iclass].active_spans_block_freelist & g_config_span_mask);
            span_t** list = NULL;
            --heap->fully_inited_spans_count;
            if (!_rpmalloc_span_finalize(heap, iclass, sizeclass_active_span, list)) {
                if (list)
                    _rpmalloc_span_dll_remove(list, sizeclass_active_span);
                _rpmalloc_span_dll_add(&heap->sizeclass_spans[iclass].partially_inited_spans_dll, sizeclass_active_span);
            }
        }
    }

#if ENABLE_SPAN_L1_TCACHE
    for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass) {
        span_l1_cache_bucket_t* const spans_bucket = SPAN_L1_TCACHE_GET_BUCKET(iclass, heap);
        for (size_t ispan = 0; ispan < spans_bucket->count; ++ispan)
            _rpmalloc_span_unmap(spans_bucket->bin[ispan]);
        spans_bucket->count = 0;
    }
#endif
    rpmalloc_assert(!atomic_load_ptr(&heap->span_free_deferred_sll), "Heaps still active during finalization");
}

////////////
///
/// Allocation entry points
///
//////

//! Pop 1st block from a free list
static void*
block_freelist_pop(void** list) {
    void* block = *list;        // Get head (block)
    *list = *((void**)block);   // Update head (block)
    return block;
}

//! Allocate a small/medium sized memory block from the given heap
static void*
_rpmalloc_allocate_from_heap_fallback(heap_t* const heap,
                                      heap_sizeclass_spans_t* const heap_sizeclass_spans,
                                      const uint32_t class_idx) {
    span_t* span = heap_sizeclass_spans->partially_inited_spans_dll;
    rpmalloc_assume(NULL != heap);
    if EXPECTED(NULL != span) {
        rpmalloc_assert(span->block_sizeclass_count == g_config_block_sizeclasses[span->block_sizeclass_idx].block_count, "`span->block_sizeclass_count` corrupted");
        rpmalloc_assert(!_rpmalloc_span_is_fully_inited(span), "Internal failure");
        rpmalloc_assert(heap == span->owner_heap, "`span->owner_heap` corrupted");      // $$$$$$$$$$$$

        void* block;
        if (span->block_freelist) {
            //"Span local free list" isn't empty, swap to "size class free list"
            block = block_freelist_pop(&span->block_freelist);
            heap_sizeclass_spans->active_spans_block_freelist = span->block_freelist;
            span->block_freelist = NULL;

        } else {
            //If the span hasn't a fully initialize free list, link up another page worth of blocks
            void* block_start = pointer_add_offset(span, SPAN_HEADER_SIZE + ((size_t)span->block_freelist_inited_count * span->block_sizeclass_size));
            span->block_freelist_inited_count += block_freelist_init_partially_reserve_1st_block_for_caller_and_add_remaining_2_heap_class_freelist(&heap_sizeclass_spans->active_spans_block_freelist,
                                                                                                                                                     &block/*first_block*/,
                                                                                                                                                     (void*)((uintptr_t)block_start & ~(g_config_page_size - 1))/*page_start*/,
                                                                                                                                                     block_start,
                                                                                                                                                     span->block_sizeclass_count - span->block_freelist_inited_count,
                                                                                                                                                     span->block_sizeclass_size);
        }
        rpmalloc_assert(span->block_freelist_inited_count <= span->block_sizeclass_count, "`span->block_freelist_inited_count` corrupted");
        span->block_freelist_used_count = span->block_freelist_inited_count;

        //Swap in 'deferred free list' if present
        if (atomic_load_ptr(&span->block_freelist_deferred))
            _rpmalloc_span_extract_from_block_freelist_deferred(span);

        //If span still isn't fully utilized: keep it in partial list & early return block
        if (!_rpmalloc_span_is_fully_inited(span))
            return block;

        //The span is fully utilized, unlink from partial list & add to fully utilized list
        _rpmalloc_span_dll_pop_head(&heap_sizeclass_spans->partially_inited_spans_dll, span);
        ++heap->fully_inited_spans_count;
        return block;
    }

    //Find a span in 1 of the cache levels
    span = _rpmalloc_heap_span_lx_cache_extract(heap, heap_sizeclass_spans, 1, class_idx);
    if EXPECTED(NULL != span) {
        //Mark span as owned by this heap & set base data, return first block
        return _rpmalloc_span_init_and_return_block_and_add_remaining_2_heap(heap, heap_sizeclass_spans, span,
                                                                             class_idx);
    }

    return NULL;
}

//! Allocate a small sized memory block from the given heap
static void*
_rpmalloc_allocate_small(heap_t* const heap, const size_t size) {
    rpmalloc_assert(heap, "No thread heap");
    //Small sizes have unique size classes
    const uint32_t class_idx = (uint32_t)((size + (BLOCK_SMALL_GRANULARITY - 1)) >> BLOCK_SMALL_GRANULARITY_SHIFT);
    heap_sizeclass_spans_t* const heap_sizeclass_spans = heap->sizeclass_spans + class_idx;
    _rpmalloc_stat_inc_alloc(heap, class_idx);
    // Allocate from currently active span or use fallback
    if EXPECTED(NULL != heap_sizeclass_spans->active_spans_block_freelist) {
#define ASSERT_ACTIVE_SPAN_HEAP(HEAP, HEAP_SIZECLASS_SPANS) do { rpmalloc_assert((HEAP) == (((span_t*)((uintptr_t)(HEAP_SIZECLASS_SPANS)->active_spans_block_freelist & g_config_span_mask)))->owner_heap, "Active spans heap corrupted"); } while(0)
        ASSERT_ACTIVE_SPAN_HEAP(heap, heap_sizeclass_spans);      // $$$$$$$$$$$$
        return block_freelist_pop(&heap_sizeclass_spans->active_spans_block_freelist);
    }
    return _rpmalloc_allocate_from_heap_fallback(heap, heap_sizeclass_spans, class_idx);
}

//! Allocate a medium sized memory block from the given heap
static void*
_rpmalloc_allocate_medium(heap_t* const heap, const size_t size) {
    rpmalloc_assert(heap, "No thread heap");

    //Calculate the size class index & do a dependent lookup of the final class index (in case of merged classes)
    const uint32_t class_idx = g_config_block_sizeclasses[ (uint32_t)(BLOCK_SMALL_CLASS_COUNT + ((size - (BLOCK_SMALL_SIZE_LIMIT + 1)) >> BLOCK_MEDIUM_GRANULARITY_SHIFT))/*base_idx*/ ].class_idx;
    heap_sizeclass_spans_t* const heap_sizeclass_spans = heap->sizeclass_spans + class_idx;
    _rpmalloc_stat_inc_alloc(heap, class_idx);
    // Allocate from currently active span or use fallback
    if EXPECTED(NULL != heap_sizeclass_spans->active_spans_block_freelist) {
        ASSERT_ACTIVE_SPAN_HEAP(heap, heap_sizeclass_spans);      // $$$$$$$$$$$$
        return block_freelist_pop(&heap_sizeclass_spans->active_spans_block_freelist);
    }
    return _rpmalloc_allocate_from_heap_fallback(heap, heap_sizeclass_spans, class_idx);
}

//! Allocate a large sized memory block from the given heap
static void*
_rpmalloc_allocate_large(heap_t* const heap, size_t size) {
    rpmalloc_assert(heap, "No thread heap");
    //Calculate # of needed max sized spans (including header)
    //Since this function is never called if `size` > `BLOCK_LARGE_SIZE_LIMIT`
    //the `span_count` is guaranteed to be <= `BLOCK_LARGE_CLASS_COUNT`
    size += SPAN_HEADER_SIZE;
    size_t span_count = size >> g_config_span_size_shift;
    if (size & (g_config_span_size - 1))
        ++span_count;

    //Find a span in 1 of the cache levels
    span_t* const span = _rpmalloc_heap_span_lx_cache_extract(heap, NULL, span_count, BLOCK_SIZE_CLASS_LARGE);
    if (!span)
        return span;

    //Mark span as owned by this heap & set base data
    rpmalloc_assert(span->span__count >= span_count, "Internal failure");
    span->block_sizeclass_idx = BLOCK_SIZE_CLASS_LARGE;
    span->owner_heap = heap;

    ++heap->fully_inited_spans_count;

    return pointer_add_offset(span, SPAN_HEADER_SIZE);
}

//! Allocate a huge block by mapping memory pages directly
static void*
_rpmalloc_allocate_huge(heap_t* const heap, size_t size) {
    rpmalloc_assert(heap, "No thread heap");
    _rpmalloc_heap_cache_adopt_deferred(heap, NULL);
    size += SPAN_HEADER_SIZE;
    size_t num_pages = size >> g_config_page_size_shift;
    if (size & (g_config_page_size - 1))
        ++num_pages;
    size_t align_offset = 0;
    span_t* const span = (span_t*)_rpmalloc_mmap(num_pages * g_config_page_size, &align_offset);
    if (!span)
        return span;

    //Store page count in `span__count`
    span->block_sizeclass_idx = BLOCK_SIZE_CLASS_HUGE;
    span->span__count = (uint32_t)num_pages;
    span->align_offset = (uint32_t)align_offset;
    span->owner_heap = heap;
    SPAN_L1_CCACHE_INIT_SPAN(span);             // NOTE: Won't be mv'ed 2 'span l1 cache' anyways, but 4 consistency
    _rpmalloc_stat_add_peak(&g_stats_huge_pages_current, num_pages, g_stats_huge_pages_peak);

    ++heap->fully_inited_spans_count;

    return pointer_add_offset(span, SPAN_HEADER_SIZE);
}

//! Allocate a block of the given size
static void*
_rpmalloc_allocate(heap_t* const heap, size_t size) {
    _rpmalloc_stat_add64(&g_stats_allocation_counter, 1);
    if EXPECTED(size <= BLOCK_SMALL_SIZE_LIMIT)
        return _rpmalloc_allocate_small(heap, size);
    else if (size <= g_config_block_medium_size_limit)
        return _rpmalloc_allocate_medium(heap, size);
    else if (size <= BLOCK_LARGE_SIZE_LIMIT)
        return _rpmalloc_allocate_large(heap, size);
    return _rpmalloc_allocate_huge(heap, size);
}

static void*
_rpmalloc_aligned_allocate(heap_t* const heap,
                           const size_t alignment,
                           const size_t size) {
    if (alignment <= BLOCK_SMALL_GRANULARITY)
        return _rpmalloc_allocate(heap, size);

#if ENABLE_VALIDATE_ARGS
    if ((size + alignment) < size) {
        errno = EINVAL;
        return NULL;
    }
    if (alignment & (alignment - 1)) {
        errno = EINVAL;
        return NULL;
    }
#endif

    if ((alignment <= SPAN_HEADER_SIZE) && ((size + SPAN_HEADER_SIZE) < g_config_block_medium_size_limit)) {
        // If alignment is less or equal to span header size (which is power of 2),
        // and size aligned to span header size multiples is less than size + alignment,
        // then use natural alignment of blocks to provide alignment
        size_t multiple_size = size ? (size + (SPAN_HEADER_SIZE - 1)) & ~(uintptr_t)(SPAN_HEADER_SIZE - 1) : SPAN_HEADER_SIZE;
        rpmalloc_assert(!(multiple_size % SPAN_HEADER_SIZE), "Failed alignment calculation");
        if (multiple_size <= (size + alignment))
            return _rpmalloc_allocate(heap, multiple_size);
    }

    void* ptr = NULL;
    const size_t align_mask = alignment - 1;
    if (alignment <= g_config_page_size) {
        ptr = _rpmalloc_allocate(heap, size + alignment);
        if ((uintptr_t)ptr & align_mask) {
            ptr = (void*)(((uintptr_t)ptr & ~(uintptr_t)align_mask) + alignment);
            //Mark as having aligned blocks
            span_t* span = (span_t*)((uintptr_t)ptr & g_config_span_mask);
            span->flags |= SPAN_FLAG_ALIGNED_BLOCKS;
        }
        return ptr;
    }

    // Fallback to mapping new pages for this request. Since pointers passed
    // to rpfree must be able to reach the start of the span by bitmasking of
    // the address w/ the span size, the returned aligned pointer from this
    // function must be w/ a span size of the start of the mapped area.
    // In worst case this requires us to loop & map pages until we get a
    // suitable memory address. It also means we can never align to span size
    // or greater, since the span header will push alignment more than one
    // span size away from span start (thus causing pointer mask to give us
    // an invalid span start on free)
    if (alignment & align_mask) {
        errno = EINVAL;
        return NULL;
    }
    if (alignment >= g_config_span_size) {
        errno = EINVAL;
        return NULL;
    }

    const size_t extra_pages = alignment / g_config_page_size;

    // Since each span has a header, we will at least need one extra memory page
    size_t num_pages = 1 + (size / g_config_page_size);
    if (size & (g_config_page_size - 1))
        ++num_pages;

    if (extra_pages > num_pages)
        num_pages = 1 + extra_pages;

    const size_t original_pages = num_pages;
    size_t limit_pages = (g_config_span_size / g_config_page_size) * 2;
    if (limit_pages < (original_pages * 2))
        limit_pages = original_pages * 2;

    size_t align_offset;

retry:
    align_offset = 0;
    const size_t mapped_size = num_pages * g_config_page_size;

    span_t* const span = (span_t*)_rpmalloc_mmap(mapped_size, &align_offset);
    if (!span) {
        errno = ENOMEM;
        return NULL;
    }
    ptr = pointer_add_offset(span, SPAN_HEADER_SIZE);

    if ((uintptr_t)ptr & align_mask)
        ptr = (void*)(((uintptr_t)ptr & ~(uintptr_t)align_mask) + alignment);

    if (((size_t)pointer_diff(ptr, span) >= g_config_span_size) ||
        (pointer_add_offset(ptr, size) > pointer_add_offset(span, mapped_size)) ||
        (((uintptr_t)ptr & g_config_span_mask) != (uintptr_t)span)) {
        _rpmalloc_unmap(span, mapped_size, align_offset, mapped_size);
        ++num_pages;
        if (num_pages > limit_pages) {
            errno = EINVAL;
            return NULL;
        }
        goto retry;
    }

    //Store page count in `span__count`
    span->block_sizeclass_idx = BLOCK_SIZE_CLASS_HUGE;
    span->span__count = (uint32_t)num_pages;
    span->align_offset = (uint32_t)align_offset;
    span->owner_heap = heap;
    SPAN_L1_CCACHE_INIT_SPAN(span);             // NOTE: Won't be mv'ed 2 'span l1 cache' anyways, but 4 consistency
    _rpmalloc_stat_add_peak(&g_stats_huge_pages_current, num_pages, g_stats_huge_pages_peak);

    ++heap->fully_inited_spans_count;

    _rpmalloc_stat_add64(&g_stats_allocation_counter, 1);

    return ptr;
}


////////////
///
/// Deallocation entry points
///
//////

//! Deallocate the given small/medium memory block in the current thread local heap
static void
_rpmalloc_deallocate_direct_small_or_medium(span_t* const span, void* const block) {
    heap_t* const heap = span->owner_heap;
    rpmalloc_assert(get_thread_id() == heap->owner_thread || !heap->owner_thread || heap->finalize, "Internal failure");

    // Add span 2 heaps 'partially full list'  ??????????
    if UNEXPECTED(_rpmalloc_span_is_fully_inited(span)) {
        span->block_freelist_used_count = span->block_sizeclass_count;
        _rpmalloc_span_dll_add(&heap->sizeclass_spans[span->block_sizeclass_idx].partially_inited_spans_dll, span);
        --heap->fully_inited_spans_count;
    }

    //Add block to free list
    *((void**)block) = span->block_freelist;        // Take head node & add it in current node
    --span->block_freelist_used_count;
    span->block_freelist = block;                   // Make current block new head node

    // Try 2 release 2 'span l0 cache' if not used  ???
    if UNEXPECTED(span->block_freelist_used_count == span->block_freelist_deferred_count) {
        // If there are no used blocks it's guaranteed that no other thread is accessing the span
        if (span->block_freelist_used_count) {
            // Make sure we've synchronized the deferred list & list size by using acquire semantics
            // & guarantee that no external thread is accessing span concurrently
            void* span_deferred_freelist;
            do {
                span_deferred_freelist = atomic_exchange_ptr_acquire(&span->block_freelist_deferred, INVALID_POINTER);
            } while (INVALID_POINTER == span_deferred_freelist);
            atomic_store_ptr_release(&span->block_freelist_deferred, span_deferred_freelist);
        }
        _rpmalloc_span_dll_remove(&heap->sizeclass_spans[span->block_sizeclass_idx].partially_inited_spans_dll, span);
        _rpmalloc_span_release_to_heap_span_l0_cache(heap, span);
    }
}

static void
_rpmalloc_deallocate_defer_free_span(heap_t* const heap, span_t* const span) {
    if (BLOCK_SIZE_CLASS_HUGE != span->block_sizeclass_idx)
        _rpmalloc_stat_inc(&heap->span_use[span->span__count - 1].stats_spans_deferred);

    //This list does not need ABA protection, no mutable side state
    //Read current head of 'heaps deferred list'  &  'move' it in spans free-list,  forming a linked list
    do {
        span->heap_span_free_deferred_sll = (span_t*)atomic_load_ptr(&heap->span_free_deferred_sll);
    } while (!atomic_cas_ptr(&heap->span_free_deferred_sll, span, span->heap_span_free_deferred_sll));
}

//! Put the block in the deferred free list of the owning span
static void
_rpmalloc_deallocate_defer_small_or_medium(span_t* const span, void* const block) {
    // The memory ordering here is a bit tricky, to avoid having to ABA protect
    // the deferred free list to avoid desynchronization of list & list size
    // we need to have acquire semantics on successful CAS of the pointer to
    // guarantee the `heap_span_free_deferred_sll_count` variable validity + release semantics on pointer store
    void* span_deferred_freelist;
    do {
        span_deferred_freelist = atomic_exchange_ptr_acquire(&span->block_freelist_deferred, INVALID_POINTER);
    } while (span_deferred_freelist == INVALID_POINTER);
    *((void**)block) = span_deferred_freelist;
    const uint32_t free_count = ++span->heap_span_free_deferred_sll_count;
    atomic_store_ptr_release(&span->block_freelist_deferred, block);
    const char all_deferred_free = (free_count == span->block_sizeclass_count);
    if (all_deferred_free) {
        // Span was completely freed by this block. Due to the INVALID_POINTER spin lock
        // no other thread can reach this state simultaneously on this span.
        // Safe to move to owner heap deferred cache
        _rpmalloc_deallocate_defer_free_span(span->owner_heap, span);
    }
}

static void
_rpmalloc_deallocate_small_or_medium(span_t* const span, void* p) {
    _rpmalloc_stat_inc_free(span->owner_heap, span->block_sizeclass_idx);
    if (span->flags & SPAN_FLAG_ALIGNED_BLOCKS) {
        //Realign pointer to block start
        void* blocks_start = pointer_add_offset(span, SPAN_HEADER_SIZE);
        uint32_t block_offset = (uint32_t)pointer_diff(p, blocks_start);
        p = pointer_add_offset(p, -(int32_t)(block_offset % span->block_sizeclass_size));
    }
    //Check if block belongs to this heap or if deallocation should be deferred
#define DEFER_DEALLOC_IF_DIFFERENT_HEAP(SPAN) ( (get_thread_id() != (SPAN)->owner_heap->owner_thread) && !(SPAN)->owner_heap->finalize )
    if (! DEFER_DEALLOC_IF_DIFFERENT_HEAP(span))
        _rpmalloc_deallocate_direct_small_or_medium(span, p);
    else
        _rpmalloc_deallocate_defer_small_or_medium(span, p);
}

//! Deallocate the given large memory block to the current heap
static void
_rpmalloc_deallocate_large(span_t* span) {
    rpmalloc_assert(BLOCK_SIZE_CLASS_LARGE == span->block_sizeclass_idx, "Bad span size class");
    rpmalloc_assert(!(span->flags & SPAN_FLAG_MASTER) || !(span->flags & SPAN_FLAG_SUBSPAN), "Span flag corrupted");
    rpmalloc_assert((span->flags & SPAN_FLAG_MASTER) || (span->flags & SPAN_FLAG_SUBSPAN), "Span flag corrupted");

    //We must always defer (unless finalizing) if from another heap since we cannot touch the list or counters of another heap
    if ( DEFER_DEALLOC_IF_DIFFERENT_HEAP(span) ) {
        _rpmalloc_deallocate_defer_free_span(span->owner_heap, span);
        return;
    }
    rpmalloc_assert(span->owner_heap->fully_inited_spans_count, "`heap->fully_inited_spans_count` corrupted");
    --span->owner_heap->fully_inited_spans_count;
#if ENABLE_ADAPTIVE_SPAN_L1_CACHE || ENABLE_STATISTICS
    //Decrease counter
    const size_t idx = span->span__count - 1;
    atomic_decr32(&span->owner_heap->span_use[idx].current);
#endif
    heap_t* const heap = span->owner_heap;
    rpmalloc_assert(heap, "No thread heap");

    // Either add it 2 'global span reserve' OR in2 'l1 span cache'
    const char set_as_reserved =
#if ENABLE_SPAN_L1_TCACHE || ENABLE_SPAN_L1_CCACHE
                                 (span->span__count > 1) && (0 ==
#  if ENABLE_SPAN_L1_TCACHE
                                                                  heap->span_l1_tcache.spans_bucket.count) && !heap->finalize && !heap->spans_reserve_count;
#  else /* ENABLE_SPAN_L1_CCACHE */
                                                                  (_rpmalloc_span_l1_ccache_get_slot( SPAN_CCACHE_SLOT_GET_INDEX() ))->spans_bucket.count);
#  endif /* ENABLE_SPAN_L1_TCACHE */

#else
                                ((span->span__count > 1) && !heap->finalize && !heap->spans_reserve_count);
#endif /* ENABLE_SPAN_L1_TCACHE || ENABLE_SPAN_L1_CCACHE */
    if (set_as_reserved) {
        heap->span_reserve = span;
        heap->spans_reserve_count = span->span__count;
        // Is this the master span? -> Set it
        if (span->flags & SPAN_FLAG_MASTER) {
            heap->span_reserve_master = span;
        // If not, get the master & set it
        } else { //SPAN_FLAG_SUBSPAN
            span_t* master_span = (span_t*)pointer_add_offset(span, -(intptr_t)((size_t)span->subspan_master_offset * g_config_span_size));
            heap->span_reserve_master = master_span;
            rpmalloc_assert(master_span->flags & SPAN_FLAG_MASTER, "Span flag corrupted");
            rpmalloc_assert(atomic_load32(&master_span->masterspan_remaining_spans) >= (int32_t)span->span__count, "Master span count corrupted");
        }
        _rpmalloc_stat_inc(&heap->span_use[idx].stats_spans_to_reserved);
    } else {
        //.. Insert into 'span l1 cache'
        _rpmalloc_heap_span_lx_cache_insert(heap, span);
    }
}

//! Deallocate the given huge span
static void
_rpmalloc_deallocate_huge(span_t* span) {
    rpmalloc_assert(span->owner_heap, "No span heap");
    if ( DEFER_DEALLOC_IF_DIFFERENT_HEAP(span) ) {
        _rpmalloc_deallocate_defer_free_span(span->owner_heap, span);
        return;
    }
    rpmalloc_assert(span->owner_heap->fully_inited_spans_count, "`heap->fully_inited_spans_count` corrupted");
    --span->owner_heap->fully_inited_spans_count;

    //Oversized allocation, page count is stored in span__count
    const size_t num_pages = span->span__count;
    _rpmalloc_unmap(span, num_pages * g_config_page_size, span->align_offset, num_pages * g_config_page_size);
    _rpmalloc_stat_sub(&g_stats_huge_pages_current, num_pages);
}

//! Deallocate the given block
static void
_rpmalloc_deallocate(void* p) {
    _rpmalloc_stat_add64(&g_stats_deallocation_counter, 1);
    //Grab the span (always at start of span, using span alignment)
    span_t* const span = (span_t*)((uintptr_t)p & g_config_span_mask);

    if UNEXPECTED(!span)            // Posix compliance: `free(NULL)`
        return;

    rpmalloc_assert(  span->span__count  &&  span->owner_heap, "Cannot `free` invalid span"  );

    if EXPECTED(span->block_sizeclass_idx < BLOCK_SMALL_MEDIUM_CLASS_COUNT)
        _rpmalloc_deallocate_small_or_medium(span, p);
    else if (BLOCK_SIZE_CLASS_LARGE == span->block_sizeclass_idx)
        _rpmalloc_deallocate_large(span);
    else
        _rpmalloc_deallocate_huge(span);
}

////////////
///
/// Reallocation entry points
///
//////

static size_t
_rpmalloc_usable_size(void* p);

//! Reallocate the given block to the given size
static void*
_rpmalloc_reallocate(heap_t* const heap,
                     void* const p,
                     const size_t size,
                     size_t oldsize,
                     const unsigned int flags) {
    if (p) {
        //Grab the span using guaranteed span alignment
        span_t* const span = (span_t*)((uintptr_t)p & g_config_span_mask);
        if EXPECTED(span->block_sizeclass_idx < BLOCK_SMALL_MEDIUM_CLASS_COUNT) {
            //Small-/medium sized block
            rpmalloc_assert(1 == span->span__count, "`span->span__count` corrupted");
            const void* blocks_start = pointer_add_offset(span, SPAN_HEADER_SIZE);
            const uint32_t block_offset = (uint32_t)pointer_diff(p, blocks_start);
            const uint32_t block_idx = block_offset / span->block_sizeclass_size;
            void* const block = pointer_add_offset(blocks_start, (size_t)block_idx * span->block_sizeclass_size);
            if (!oldsize)
                oldsize = (size_t)((ptrdiff_t)span->block_sizeclass_size - pointer_diff(p, block));
            if ((size_t)span->block_sizeclass_size >= size) {
                //Still fits in block, never mind trying to save memory, but preserve data if alignment changed
                if ((p != block) && !(flags & RPMALLOC_NO_PRESERVE))
                    memmove(block, p, oldsize);
                return block;
            }
        } else if (BLOCK_SIZE_CLASS_LARGE == span->block_sizeclass_idx) {
            //Large block
            const size_t total_size = size + SPAN_HEADER_SIZE;
            size_t num_spans = total_size >> g_config_span_size_shift;
            if (total_size & (g_config_span_mask - 1))
                ++num_spans;
            const size_t current_spans = span->span__count;
            void* const block = pointer_add_offset(span, SPAN_HEADER_SIZE);
            if (!oldsize)
                oldsize = (current_spans * g_config_span_size) - (size_t)pointer_diff(p, block) - SPAN_HEADER_SIZE;
            if ((current_spans >= num_spans) && (total_size >= (oldsize / 2))) {
                //Still fits in block, never mind trying to save memory, but preserve data if alignment changed
                if ((p != block) && !(flags & RPMALLOC_NO_PRESERVE))
                    memmove(block, p, oldsize);
                return block;
            }
        } else {
            //Oversized block
            const size_t total_size = size + SPAN_HEADER_SIZE;
            size_t num_pages = total_size >> g_config_page_size_shift;
            if (total_size & (g_config_page_size - 1))
                ++num_pages;
            //Page count is stored in span__count
            const size_t current_pages = span->span__count;
            void* const block = pointer_add_offset(span, SPAN_HEADER_SIZE);
            if (!oldsize)
                oldsize = (current_pages * g_config_page_size) - (size_t)pointer_diff(p, block) - SPAN_HEADER_SIZE;
            if ((current_pages >= num_pages) && (num_pages >= (current_pages / 2))) {
                //Still fits in block, never mind trying to save memory, but preserve data if alignment changed
                if ((p != block) && !(flags & RPMALLOC_NO_PRESERVE))
                    memmove(block, p, oldsize);
                return block;
            }
        }
    } else {
        oldsize = 0;
    }

    if (!!(flags & RPMALLOC_GROW_OR_FAIL))
        return NULL;

    //Size is greater than block size, need to allocate a new block & deallocate the old
    //Avoid hysteresis by overallocating if increase is small (below 37%)
    const size_t lower_bound = oldsize + (oldsize >> 2) + (oldsize >> 3);
    const size_t new_size = (size > lower_bound) ? size : ((size > oldsize) ? lower_bound : size);
    void* const block = _rpmalloc_allocate(heap, new_size);
    if (p && block) {
        if (!(flags & RPMALLOC_NO_PRESERVE))
            memcpy(block, p, oldsize < new_size ? oldsize : new_size);
        _rpmalloc_deallocate(p);
    }

    return block;
}

static void*
_rpmalloc_aligned_reallocate(heap_t* const heap,
                             void* ptr,
                             const size_t alignment,
                             const size_t size,
                             size_t oldsize,
                             const unsigned int flags) {
    if (alignment <= BLOCK_SMALL_GRANULARITY)
        return _rpmalloc_reallocate(heap, ptr, size, oldsize, flags);

    const int no_alloc = !!(flags & RPMALLOC_GROW_OR_FAIL);
    const size_t usablesize = (ptr ? _rpmalloc_usable_size(ptr) : 0);
    if ((usablesize >= size) && !((uintptr_t)ptr & (alignment - 1))) {
        if (no_alloc || (size >= (usablesize / 2)))
            return ptr;
    }
    // Aligned alloc marks span as having aligned blocks
    void* const block = (!no_alloc ? _rpmalloc_aligned_allocate(heap, alignment, size) : NULL);
    if EXPECTED(NULL != block) {
        if (!(flags & RPMALLOC_NO_PRESERVE) && ptr) {
            if (!oldsize)
                oldsize = usablesize;
            memcpy(block, ptr, oldsize < size ? oldsize : size);
        }
        _rpmalloc_deallocate(ptr);
    }
    return block;
}


////////////
///
/// Initialization, finalization & utility
///
//////

//! Get the usable size of the given block
static size_t
_rpmalloc_usable_size(void* p) {
    //Grab the span using guaranteed span alignment
    span_t* const span = (span_t*)((uintptr_t)p & g_config_span_mask);
    if (span->block_sizeclass_idx < BLOCK_SMALL_MEDIUM_CLASS_COUNT) {
        //Small/medium block
        void* const blocks_start = pointer_add_offset(span, SPAN_HEADER_SIZE);
        return span->block_sizeclass_size - ((size_t)pointer_diff(p, blocks_start) % span->block_sizeclass_size);
    }
    if (BLOCK_SIZE_CLASS_LARGE == span->block_sizeclass_idx) {
        //Large block
        const size_t current_spans = span->span__count;
        return (current_spans * g_config_span_size) - (size_t)pointer_diff(p, span);
    }
    //Oversized block, page count is stored in span__count
    const size_t current_pages = span->span__count;
    return (current_pages * g_config_page_size) - (size_t)pointer_diff(p, span);
}

//! Adjust & optimize the size class properties for the given class
static void
_rpmalloc_adjust_block_sizeclass(const size_t iclass) {
    const size_t block_size = g_config_block_sizeclasses[iclass].block_size;
    const size_t block_count = (g_config_span_size - SPAN_HEADER_SIZE) / block_size;

    g_config_block_sizeclasses[iclass].block_count = (uint16_t)block_count;
    g_config_block_sizeclasses[iclass].class_idx = (uint16_t)iclass;

    //Check if previous size classes can be merged
    if (iclass >= BLOCK_SMALL_CLASS_COUNT) {
        size_t prevclass = iclass;
        while (prevclass > 0) {
            --prevclass;
            //A class can be merged if # of pages & # of blocks are equal
            if (g_config_block_sizeclasses[prevclass].block_count == g_config_block_sizeclasses[iclass].block_count)
                _rpmalloc_memcpy_const(g_config_block_sizeclasses + prevclass, g_config_block_sizeclasses + iclass, sizeof(g_config_block_sizeclasses[iclass]));
            else
                break;
        }
    }
}

//! Initialize the allocator & setup global data
extern inline int
rpmalloc_initialize(void) {
    if (g_alloc_state_inited) {
        rpmalloc_thread_initialize();
        return 0;
    }

    return rpmalloc_initialize_config(NULL);
}

int
rpmalloc_initialize_config(const rpmalloc_config_t* const config) {
    if (g_alloc_state_inited) {
        rpmalloc_thread_initialize();
        return 0;
    }
    g_alloc_state_inited = 1;

    if (config)
        memcpy(&g_config_alloc, config, sizeof(rpmalloc_config_t));
    else
        _rpmalloc_memset_const(&g_config_alloc, 0, sizeof(rpmalloc_config_t));

    if (!g_config_alloc.memory_map_fct || !g_config_alloc.memory_unmap_fct) {
        g_config_alloc.memory_map_fct = _rpmalloc_mmap_os;
        g_config_alloc.memory_unmap_fct = _rpmalloc_unmap_os;
    }

#if PLATFORM_WINDOWS
    SYSTEM_INFO system_info;
    memset(&system_info, 0, sizeof(system_info));
    GetSystemInfo(&system_info);
    g_config_map_granularity = system_info.dwAllocationGranularity;
#else
    g_config_map_granularity = (size_t)sysconf(_SC_PAGESIZE);
#endif

#if RPMALLOC_CONFIGURABLE
    g_config_page_size = g_config_alloc.page_size;
#else
    g_config_page_size = 0;
#endif
    g_config_use_huge_pages = 0;
    if (!g_config_page_size) {
#if PLATFORM_WINDOWS
        g_config_page_size = system_info.dwPageSize;
#else
        g_config_page_size = g_config_map_granularity;
        if (g_config_alloc.enable_huge_pages) {
#  if defined(__linux__)
            size_t huge_page_size = 0;
            FILE* meminfo = fopen("/proc/meminfo", "r");
            if (meminfo) {
                char line[128];
                while (!huge_page_size && fgets(line, sizeof(line) - 1, meminfo)) {
                    line[sizeof(line) - 1] = 0;
                    if (strstr(line, "Hugepagesize:"))
                        huge_page_size = (size_t)strtol(line + 13, 0, 10) * 1024;
                }
                fclose(meminfo);
            }
            if (huge_page_size) {
                g_config_use_huge_pages = 1;
                g_config_page_size = huge_page_size;
                g_config_map_granularity = huge_page_size;
            }
#  elif defined(__FreeBSD__)
            int rc;
            size_t sz = sizeof(rc);

            if (sysctlbyname("vm.pmap.pg_ps_enabled", &rc, &sz, NULL, 0) == 0 && 1 == rc) {
                static size_t defsize = 2 * 1024 * 1024;
                int nsize = 0;
                size_t sizes[4] = {0};
                g_config_use_huge_pages = 1;
                g_config_page_size = defsize;
                if ((nsize = getpagesizes(sizes, 4)) >= 2) {
                    nsize --;
                    for (size_t csize = sizes[nsize]; nsize >= 0 && csize; --nsize, csize = sizes[nsize]) {
                        //! Unlikely, but as a precaution..
                        rpmalloc_assert(!(csize & (csize -1)) && !(csize % 1024), "Invalid page size");
                        if (defsize < csize) {
                            g_config_page_size = csize;
                            break;
                        }
                    }
                }
                g_config_map_granularity = g_config_page_size;
            }
#  elif defined(__APPLE__) || defined(__NetBSD__)
            g_config_use_huge_pages = 1;
            g_config_page_size = 2 * 1024 * 1024;
            g_config_map_granularity = g_config_page_size;
#  endif
        }
#endif
    } else {
        if (g_config_alloc.enable_huge_pages)
            g_config_use_huge_pages = 1;
    }

#if PLATFORM_WINDOWS
    if (g_config_alloc.enable_huge_pages) {
        HANDLE token = 0;
        size_t large_page_minimum = GetLargePageMinimum();
        if (large_page_minimum)
            OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
        if (token) {
            LUID luid;
            if (LookupPrivilegeValue(0, SE_LOCK_MEMORY_NAME, &luid)) {
                TOKEN_PRIVILEGES token_privileges;
                memset(&token_privileges, 0, sizeof(token_privileges));
                token_privileges.PrivilegeCount = 1;
                token_privileges.Privileges[0].Luid = luid;
                token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                if (AdjustTokenPrivileges(token, FALSE, &token_privileges, 0, 0, 0)) {
                    if (GetLastError() == ERROR_SUCCESS)
                        g_config_use_huge_pages = 1;
                }
            }
            CloseHandle(token);
        }
        if (g_config_use_huge_pages) {
            if (large_page_minimum > g_config_page_size)
                g_config_page_size = large_page_minimum;
            if (large_page_minimum > g_config_map_granularity)
                g_config_map_granularity = large_page_minimum;
        }
    }
#endif

    const size_t min_span_size = 256;
    const size_t max_page_size =
#if UINTPTR_MAX > 0xFFFFFFFF
                                 4096ULL * 1024ULL * 1024ULL;
#else
                                 4 * 1024 * 1024;
#endif
    if (g_config_page_size < min_span_size)
        g_config_page_size = min_span_size;
    if (g_config_page_size > max_page_size)
        g_config_page_size = max_page_size;
    g_config_page_size_shift = 0;
    size_t page_size_bit = g_config_page_size;
    while (page_size_bit != 1) {
        ++g_config_page_size_shift;
        page_size_bit >>= 1;
    }
    g_config_page_size = ((size_t)1 << g_config_page_size_shift);

#if RPMALLOC_CONFIGURABLE
    if (!g_config_alloc.span_size) {
        g_config_span_size = g_config_default_span_size;
        g_config_span_size_shift = g_config_default_span_size_shift;
        g_config_span_mask = g_config_default_span_mask;
    } else {
        size_t span_size = g_config_alloc.span_size;
        if (span_size > (256 * 1024))
            span_size = (256 * 1024);
        g_config_span_size = 4096;
        g_config_span_size_shift = 12;
        while (g_config_span_size < span_size) {
            g_config_span_size <<= 1;
            ++g_config_span_size_shift;
        }
        g_config_span_mask = ~(uintptr_t)(g_config_span_size - 1);
    }
#endif

    g_config_span_map_count = ( g_config_alloc.span_map_count ? g_config_alloc.span_map_count : DEFAULT_SPAN_MAP_COUNT);
    if ((g_config_span_size * g_config_span_map_count) < g_config_page_size)
        g_config_span_map_count = (g_config_page_size / g_config_span_size);
    if ((g_config_page_size >= g_config_span_size) && ((g_config_span_map_count * g_config_span_size) % g_config_page_size))
        g_config_span_map_count = (g_config_page_size / g_config_span_size);
    g_config_heap_reserve_count = (g_config_span_map_count > DEFAULT_SPAN_MAP_COUNT) ? DEFAULT_SPAN_MAP_COUNT : g_config_span_map_count;

    g_config_alloc.page_size = g_config_page_size;
    g_config_alloc.span_size = g_config_span_size;
    g_config_alloc.span_map_count = g_config_span_map_count;
    g_config_alloc.enable_huge_pages = g_config_use_huge_pages;

#if ((defined(__APPLE__) || defined(__HAIKU__)) && ENABLE_PRELOAD) || defined(__TINYC__)
    if (pthread_key_create(&g_memory_thread_heap, _rpmalloc_heap_release_raw_fc))
        return -1;
#endif
#if defined(_WIN32) && (!defined(BUILD_DYNAMIC_LINK) || !BUILD_DYNAMIC_LINK)
    fls_key = FlsAlloc(&_rpmalloc_thread_destructor);
#endif

    //Setup all small & medium size classes
    size_t iclass = 0;
    g_config_block_sizeclasses[iclass].block_size = BLOCK_SMALL_GRANULARITY;
    _rpmalloc_adjust_block_sizeclass(iclass);
    for (iclass = 1; iclass < BLOCK_SMALL_CLASS_COUNT; ++iclass) {
        size_t size = iclass * BLOCK_SMALL_GRANULARITY;
        g_config_block_sizeclasses[iclass].block_size = (uint32_t)size;
        _rpmalloc_adjust_block_sizeclass(iclass);
    }
    //At least 2 blocks per span, then fall back to large allocations
    g_config_block_medium_size_limit = (g_config_span_size - SPAN_HEADER_SIZE) >> 1;
    if (g_config_block_medium_size_limit > BLOCK_MEDIUM_SIZE_LIMIT)
        g_config_block_medium_size_limit = BLOCK_MEDIUM_SIZE_LIMIT;
    for (iclass = 0; iclass < BLOCK_MEDIUM_CLASS_COUNT; ++iclass) {
        size_t size = BLOCK_SMALL_SIZE_LIMIT + ((iclass + 1) * BLOCK_MEDIUM_GRANULARITY);
        if (size > g_config_block_medium_size_limit) {
            g_config_block_medium_size_limit = BLOCK_SMALL_SIZE_LIMIT + (iclass * BLOCK_MEDIUM_GRANULARITY);
            break;
        }
        g_config_block_sizeclasses[BLOCK_SMALL_CLASS_COUNT + iclass].block_size = (uint32_t)size;
        _rpmalloc_adjust_block_sizeclass(BLOCK_SMALL_CLASS_COUNT + iclass);
    }

    g_alloc_orphan_heaps_sll = NULL;
#if ENABLE_STATISTICS
    atomic_store32(&g_stats_memory_active_heaps, 0);
    atomic_store32(&g_stats_mapped_pages, 0);
    g_stats_mapped_pages_peak = 0;
    atomic_store32(&g_stats_master_spans, 0);
    atomic_store32(&g_stats_mapped_total, 0);
    atomic_store32(&g_stats_unmapped_total, 0);
    atomic_store32(&g_stats_mapped_pages_os, 0);
    atomic_store32(&g_stats_huge_pages_current, 0);
    g_stats_huge_pages_peak = 0;
#endif
    memset(g_alloc_heaps, 0, sizeof(g_alloc_heaps));
    SPINLOCK_RELEASE(&g_alloc_global_lock);

    rpmalloc_linker_reference();

    //Initialize this thread
    rpmalloc_thread_initialize();


#if ENABLE_SPAN_L1_CCACHE
    // 'span l1 cache' init #1  (Beware of init order: 'mmap' fct ptr must be assigned before `_rpmalloc_mmap` can be called */)
#  if SPAN_L1_CCACHE_USE_CID
    if (! rseq_mm_cid_available()) {
        LOG_ERROR_AND_DIE("Current kernel doesn't support `mm_cid`, pls recompile w/ `-DCACHE_L1_USE_CID=OFF`");
    }
#  endif

    SPINLOCK_ACQUIRE(&g_alloc_global_lock);
    int rc = -1;
    if (g_span_l1_ccache_slots_baseptr) {       // ( Opposite check + 0 == ncpus   used 2 be `assert` ->  BUT: Alloc might get reinit'ed after fin )
        rc = 0;
        goto release;
    }

    const int rc_ncpus = system_get_ncpus(0);     // TODO@phil: NOTE: Even when using cid, the cpu-set might change during runtime (either by program itself or via `taskset --pid`, THUS: Allocate 4 all cpus)
    if UNEXPECTED( -1 == rc_ncpus ) {
        goto release;
    }
    g_span_l1_ccache_ncpus = rc_ncpus;
    rpmalloc_assert(g_span_l1_ccache_ncpus > 0, "Invalid # of CPUs");

    // TODO: Consider optimizing memory footprint when using huge pages (like in `_rpmalloc_heap_allocate_new`)
    g_span_l1_ccache_slots_baseptr = (span_l1_cache_t*)_rpmalloc_mmap(_rpmalloc_mmap_round_size_up( sizeof(*g_span_l1_ccache_slots_baseptr) * g_span_l1_ccache_ncpus ), (size_t[]){0});
    if EXPECTED( g_span_l1_ccache_slots_baseptr ) {
        rc = 0;
    }
release:
    SPINLOCK_RELEASE(&g_alloc_global_lock);

    return rc;
#else
    return 0;
#endif /* ENABLE_SPAN_L1_CCACHE */
}

//! Finalize the allocator
void
rpmalloc_finalize(void) {
    rpmalloc_thread_finalize(1);

#if ENABLE_SPAN_L1_CCACHE
    // 'span l1 cache' fin #2  (!!  BEAWARE of fin order: 'span l1 cache' must be still available when releasing heap (via `rpmalloc_thread_finalize`)  !!)
    //! Unmaps spans still resident in 'span L1 ccache'
    //  No-op when alloc has been built w/ preloading support
    //  ( RATIONALE: a) dtors (depending on invocation order) may still allocate/free memory after alloc has cleaned up (triggering re-init)
    //               b) the program cannot unload the so (unless preloading is disabled) during runtime (only on program exit,
    //                  as e.g., libc + 3rd party libs still rely on it), hence skipping cleanup won't result in a leak
    //               c) program is exiting anyway -> Let OS handle cleanup )
#  if !ENABLE_PRELOAD
    SPINLOCK_ACQUIRE(&g_alloc_global_lock);
    if (! g_span_l1_ccache_slots_baseptr) {         // ( Used 2 be `assert` -> BUT: Gets invoked multiple times (during fin 'process') )
        goto release;
    }

    // Unmap spans ('cached' in 'span l1 cache')
    for (unsigned int idx = 0; idx < g_span_l1_ccache_ncpus; ++idx) {
        span_l1_cache_t* const span_l1_ccache_slot = _rpmalloc_span_l1_ccache_get_slot(idx);
        for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass) {
            span_l1_cache_bucket_t* const spans_bucket = (!iclass) ? &span_l1_ccache_slot->spans_bucket :
                                                               (span_l1_cache_bucket_t*)(span_l1_ccache_slot->superspans_buckets + (iclass - 1));
            if (!spans_bucket->count)
                continue;
            for (size_t ispan = 0; ispan < spans_bucket->count; ++ispan)
                _rpmalloc_span_unmap(spans_bucket->bin[ispan]);
            spans_bucket->count = 0;
        }
    }

    // Deallocate 'span l1 cache'
    _rpmalloc_unmap(g_span_l1_ccache_slots_baseptr, sizeof(*g_span_l1_ccache_slots_baseptr) * g_span_l1_ccache_ncpus, 0, 0);  g_span_l1_ccache_slots_baseptr = NULL;
release:
    SPINLOCK_RELEASE(&g_alloc_global_lock);
#  endif /* ENABLE_PRELOAD */
#endif /* ENABLE_SPAN_L1_CCACHE */

    if (g_alloc_global_span_reserve) {
        atomic_add32(&g_alloc_global_span_reserve_master->masterspan_remaining_spans, -(int32_t)g_alloc_global_span_reserve_count);
        g_alloc_global_span_reserve_master = NULL;
        g_alloc_global_span_reserve_count = 0;
        g_alloc_global_span_reserve = NULL;
    }
    SPINLOCK_RELEASE(&g_alloc_global_lock);

    //Free all thread caches & fully free spans
    for (size_t list_idx = 0; list_idx < HEAP_ARRAY_SIZE; ++list_idx) {
        heap_t* heap = g_alloc_heaps[list_idx];
        while (heap) {
            heap_t* id_next_sll = heap->id_next_sll;
            heap->finalize = 1;
            _rpmalloc_heap_global_finalize(heap);
            heap = id_next_sll;
        }
    }

#if ENABLE_SPAN_L2_CACHE
    //Free global caches
    for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass)
        _rpmalloc_span_l2_cache_finalize(&g_alloc_span_l2_cache[iclass]);
#endif

#if (defined(__APPLE__) || defined(__HAIKU__)) && ENABLE_PRELOAD
    pthread_key_delete(g_memory_thread_heap);
#endif
#if defined(_WIN32) && (!defined(BUILD_DYNAMIC_LINK) || !BUILD_DYNAMIC_LINK)
    FlsFree(fls_key);
    fls_key = 0;
#endif
#if 0           // TODO: Temporary workaround -- Memory leak `assert` (which is very likely a 'false alarm') will cause `SIGABRT`
#if ENABLE_STATISTICS
    //If you hit these asserts you probably have memory leaks (perhaps global scope data doing dynamic allocations) or double frees in your code
    rpmalloc_assert(atomic_load32(&g_stats_mapped_pages) == 0, "Memory leak detected");
    rpmalloc_assert(atomic_load32(&g_stats_mapped_pages_os) == 0, "Memory leak detected");
#endif
#endif

    g_alloc_state_inited = 0;
}

//! Initialize thread, assign heap
extern inline void
rpmalloc_thread_initialize(void) {
#if ENABLE_SPAN_L1_CCACHE
    /* 'span l1 cache' init #2: Each thread does this initialization max once */
    if (! g_rpmalloc_rseq_thread_registered) {         // ( Used 2 be `assert`-> BUG: Gets invoked multiple times during init process )
        g_rpmalloc_rseq_thread_registered = 1;
        DIE_WHEN_ERR( rseq_register_current_thread() );
    }
#endif

    if (!get_thread_heap_raw()) {
        heap_t* const heap = _rpmalloc_heap_alloc_orphaned_or_new();
        if (heap) {
            _rpmalloc_stat_inc(&g_stats_memory_active_heaps);
            set_thread_heap(heap);
#if defined(_WIN32) && (!defined(BUILD_DYNAMIC_LINK) || !BUILD_DYNAMIC_LINK)
            FlsSetValue(fls_key, heap);
#endif
        }
    }
}

//! Finalize thread, orphan heap
void
rpmalloc_thread_finalize(const char release_caches) {
    heap_t* const heap = get_thread_heap_raw();
    if (heap)
        _rpmalloc_heap_release_raw(heap, release_caches);
    set_thread_heap(NULL);
#if defined(_WIN32) && (!defined(BUILD_DYNAMIC_LINK) || !BUILD_DYNAMIC_LINK)
    FlsSetValue(fls_key, 0);
#endif

#if ENABLE_SPAN_L1_CCACHE
    // 'span l1 cache' fin #1: Unregister rseq_abi   (!!  BEAWARE of fin order: 'span l1 cache' must be still available when calling `_rpmalloc_heap_release_raw`  !!)
    rpmalloc_assert(g_rpmalloc_rseq_thread_registered, "Thread hasn't been init'ed yet  /  Already unit'ed");

    rseq_prepare_unload();                           // NOTE: Shouldn't be necessary (since we already 'clear' the registered CS after each rseq), but we'll do it anyways
    g_rpmalloc_rseq_thread_registered = 0;
    DIE_WHEN_ERR( rseq_unregister_current_thread() );
#endif
}

int
rpmalloc_is_thread_initialized(void) {
    return (get_thread_heap_raw() != 0) ? 1 : 0;
}

const rpmalloc_config_t*
rpmalloc_config(void) {
    return &g_config_alloc;
}

// Extern interface

extern inline RPMALLOC_ALLOCATOR void*
rpmalloc(size_t size) {
#if ENABLE_VALIDATE_ARGS
    if (size >= MAX_ALLOC_SIZE) {
        errno = EINVAL;
        return NULL;
    }
#endif
    heap_t* const heap = get_thread_heap();
    return _rpmalloc_allocate(heap, size);
}

extern inline void
rpfree(void* ptr) {
    _rpmalloc_deallocate(ptr);
}

extern inline RPMALLOC_ALLOCATOR void*
rpcalloc(size_t num, size_t size) {
    size_t total;
#if ENABLE_VALIDATE_ARGS
#if PLATFORM_WINDOWS
    const int err = SizeTMult(num, size, &total);
    if ((err != S_OK) || (total >= MAX_ALLOC_SIZE)) {
        errno = EINVAL;
        return NULL;
    }
#else
    const int err = __builtin_umull_overflow(num, size, &total);
    if (err || (total >= MAX_ALLOC_SIZE)) {
        errno = EINVAL;
        return NULL;
    }
#endif
#else
    total = num * size;
#endif
    heap_t* const heap = get_thread_heap();
    void* const block = _rpmalloc_allocate(heap, total);
    if (block)
        memset(block, 0, total);
    return block;
}

extern inline RPMALLOC_ALLOCATOR void*
rprealloc(void* ptr, size_t size) {
#if ENABLE_VALIDATE_ARGS
    if (size >= MAX_ALLOC_SIZE) {
        errno = EINVAL;
        return ptr;
    }
#endif
    heap_t* const heap = get_thread_heap();
    return _rpmalloc_reallocate(heap, ptr, size, 0, 0);
}

extern RPMALLOC_ALLOCATOR void*
rpaligned_realloc(void* ptr, size_t alignment, size_t size, size_t oldsize,
                  unsigned int flags) {
#if ENABLE_VALIDATE_ARGS
    if ((size + alignment < size) || (alignment > g_config_page_size)) {
        errno = EINVAL;
        return NULL;
    }
#endif
    heap_t* const heap = get_thread_heap();
    return _rpmalloc_aligned_reallocate(heap, ptr, alignment, size, oldsize, flags);
}

extern RPMALLOC_ALLOCATOR void*
rpaligned_alloc(size_t alignment, size_t size) {
    heap_t* const heap = get_thread_heap();
    return _rpmalloc_aligned_allocate(heap, alignment, size);
}

extern inline RPMALLOC_ALLOCATOR void*
rpaligned_calloc(size_t alignment, size_t num, size_t size) {
    size_t total;
#if ENABLE_VALIDATE_ARGS
#if PLATFORM_WINDOWS
    const int err = SizeTMult(num, size, &total);
    if ((err != S_OK) || (total >= MAX_ALLOC_SIZE)) {
        errno = EINVAL;
        return NULL;
    }
#else
    const int err = __builtin_umull_overflow(num, size, &total);
    if (err || (total >= MAX_ALLOC_SIZE)) {
        errno = EINVAL;
        return NULL;
    }
#endif
#else
    total = num * size;
#endif
    void* const block = rpaligned_alloc(alignment, total);
    if (block)
        memset(block, 0, total);
    return block;
}

extern inline RPMALLOC_ALLOCATOR void*
rpmemalign(size_t alignment, size_t size) {
    return rpaligned_alloc(alignment, size);
}

extern inline int
rpposix_memalign(void **memptr, size_t alignment, size_t size) {
    if (memptr)
        *memptr = rpaligned_alloc(alignment, size);
    else
        return EINVAL;
    return *memptr ? 0 : ENOMEM;
}

extern inline size_t
rpmalloc_usable_size(void* ptr) {
    return (ptr ? _rpmalloc_usable_size(ptr) : 0);
}

extern inline void
rpmalloc_thread_collect(void) {
}

void
rpmalloc_thread_statistics(rpmalloc_thread_statistics_t* const stats) {
    memset(stats, 0, sizeof(rpmalloc_thread_statistics_t));
    heap_t* const heap = get_thread_heap_raw();
    if (!heap)
        return;

    for (size_t iclass = 0; iclass < BLOCK_SMALL_MEDIUM_CLASS_COUNT; ++iclass) {
        block_sizeclass_t* const block_sizeclass = g_config_block_sizeclasses + iclass;
        span_t* span = heap->sizeclass_spans[iclass].partially_inited_spans_dll;
        while (span) {
            size_t free_count = span->block_freelist_deferred_count;
            const size_t block_count = (span->block_freelist_inited_count < block_sizeclass->block_count) ? span->block_freelist_inited_count : block_sizeclass->block_count;
            free_count += (block_count - span->block_freelist_used_count);
            stats->sizecache += free_count * block_sizeclass->block_size;
            span = span->next_dll;
        }
    }

#if ENABLE_SPAN_L1_TCACHE
    for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass) {
        span_l1_cache_bucket_t* spans_bucket = SPAN_L1_TCACHE_GET_BUCKET(iclass, heap);
        stats->spancache += spans_bucket->count * (iclass + 1) * g_config_span_size;
    }
#endif

    span_t* deferred_span = (span_t*)atomic_load_ptr(&heap->span_free_deferred_sll);
    while (deferred_span) {
        if (BLOCK_SIZE_CLASS_HUGE != deferred_span->block_sizeclass_idx)
            stats->spancache += (size_t)deferred_span->span__count * g_config_span_size;
        deferred_span = deferred_span->heap_span_free_deferred_sll;
    }

#if ENABLE_STATISTICS
    stats->l1_to_l2 = (size_t)atomic_load64(&heap->stats_l1_to_l2);
    stats->l2_to_l1 = (size_t)atomic_load64(&heap->stats_l2_to_l1);

    for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass) {
        stats->span_use[iclass].current = (size_t)atomic_load32(&heap->span_use[iclass].current);
        stats->span_use[iclass].peak = (size_t)atomic_load32(&heap->span_use[iclass].high);
        stats->span_use[iclass].to_global = (size_t)atomic_load32(&heap->span_use[iclass].stats_spans_to_l2);
        stats->span_use[iclass].from_global = (size_t)atomic_load32(&heap->span_use[iclass].stats_spans_from_global);
        stats->span_use[iclass].to_cache = (size_t)atomic_load32(&heap->span_use[iclass].stats_spans_to_cache);
        stats->span_use[iclass].from_cache = (size_t)atomic_load32(&heap->span_use[iclass].stats_spans_from_cache);
        stats->span_use[iclass].to_reserved = (size_t)atomic_load32(&heap->span_use[iclass].stats_spans_to_reserved);
        stats->span_use[iclass].from_reserved = (size_t)atomic_load32(&heap->span_use[iclass].stats_spans_from_reserved);
        stats->span_use[iclass].map_calls = (size_t)atomic_load32(&heap->span_use[iclass].stats_spans_map_calls);
    }
    for (size_t iclass = 0; iclass < BLOCK_SMALL_MEDIUM_CLASS_COUNT; ++iclass) {
        stats->size_use[iclass].alloc_current = (size_t)atomic_load32(&heap->stats_block_sizeclass_use[iclass].alloc_current);
        stats->size_use[iclass].alloc_peak = (size_t)heap->stats_block_sizeclass_use[iclass].alloc_peak;
        stats->size_use[iclass].alloc_total = (size_t)atomic_load32(&heap->stats_block_sizeclass_use[iclass].alloc_total);
        stats->size_use[iclass].free_total = (size_t)atomic_load32(&heap->stats_block_sizeclass_use[iclass].free_total);
        stats->size_use[iclass].spans_to_cache = (size_t)atomic_load32(&heap->stats_block_sizeclass_use[iclass].spans_to_cache);
        stats->size_use[iclass].spans_from_cache = (size_t)atomic_load32(&heap->stats_block_sizeclass_use[iclass].spans_from_cache);
        stats->size_use[iclass].spans_from_reserved = (size_t)atomic_load32(&heap->stats_block_sizeclass_use[iclass].spans_from_reserved);
        stats->size_use[iclass].map_calls = (size_t)atomic_load32(&heap->stats_block_sizeclass_use[iclass].spans_map_calls);
    }
#endif
}

void
rpmalloc_global_statistics(rpmalloc_global_statistics_t* const stats) {
    memset(stats, 0, sizeof(rpmalloc_global_statistics_t));
#if ENABLE_STATISTICS
    stats->mapped = (size_t)atomic_load32(&g_stats_mapped_pages) * g_config_page_size;
    stats->mapped_peak = (size_t)g_stats_mapped_pages_peak * g_config_page_size;
    stats->mapped_total = (size_t)atomic_load32(&g_stats_mapped_total) * g_config_page_size;
    stats->unmapped_total = (size_t)atomic_load32(&g_stats_unmapped_total) * g_config_page_size;
    stats->huge_alloc = (size_t)atomic_load32(&g_stats_huge_pages_current) * g_config_page_size;
    stats->huge_alloc_peak = (size_t)g_stats_huge_pages_peak * g_config_page_size;
#endif
#if ENABLE_SPAN_L1_CCACHE
    for (unsigned int cpu = 0; cpu < g_span_l1_ccache_ncpus; ++cpu) {
        span_l1_cache_t* const span_l1_ccache_slot = _rpmalloc_span_l1_ccache_get_slot(cpu);
        for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass) {
            span_l1_cache_bucket_t* spans_bucket = (!iclass) ? &span_l1_ccache_slot->spans_bucket : (span_l1_cache_bucket_t*)(span_l1_ccache_slot->superspans_buckets + (iclass - 1));
            stats->cached += spans_bucket->count * (iclass + 1) * g_config_span_size;
        }
    }
#endif
#if ENABLE_SPAN_L2_CACHE
    for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass)
        stats->cached += g_alloc_span_l2_cache[iclass].count * (iclass + 1) * g_config_span_size;
#endif
}

#if ENABLE_STATISTICS

static void
_memory_heap_dump_statistics(heap_t* const heap, void* const file) {
    fprintf(file, "Heap %d stats:\n", heap->id);
    fprintf(file, "Class   CurAlloc  PeakAlloc   TotAlloc    TotFree  BlkSize BlkCount SpansCur SpansPeak  PeakAllocMiB  ToCacheMiB FromCacheMiB FromReserveMiB MmapCalls\n");
    for (size_t iclass = 0; iclass < BLOCK_SMALL_MEDIUM_CLASS_COUNT; ++iclass) {
        if (!atomic_load32(&heap->stats_block_sizeclass_use[iclass].alloc_total))
            continue;
        fprintf(file, "%3u:  %10d %10d %10d %10d %8u %8u %8d %9d %13zu %11zu %12zu %14zu %9d\n", (uint32_t)iclass,
            atomic_load32(&heap->stats_block_sizeclass_use[iclass].alloc_current),
            heap->stats_block_sizeclass_use[iclass].alloc_peak,
            atomic_load32(&heap->stats_block_sizeclass_use[iclass].alloc_total),
            atomic_load32(&heap->stats_block_sizeclass_use[iclass].free_total),
            g_config_block_sizeclasses[iclass].block_size,
            g_config_block_sizeclasses[iclass].block_count,
            atomic_load32(&heap->stats_block_sizeclass_use[iclass].spans_current),
            heap->stats_block_sizeclass_use[iclass].spans_peak,
            ((size_t)heap->stats_block_sizeclass_use[iclass].alloc_peak * (size_t)g_config_block_sizeclasses[iclass].block_size) / (size_t)(1024 * 1024),
            ((size_t)atomic_load32(&heap->stats_block_sizeclass_use[iclass].spans_to_cache) * g_config_span_size) / (size_t)(1024 * 1024),
            ((size_t)atomic_load32(&heap->stats_block_sizeclass_use[iclass].spans_from_cache) * g_config_span_size) / (size_t)(1024 * 1024),
            ((size_t)atomic_load32(&heap->stats_block_sizeclass_use[iclass].spans_from_reserved) * g_config_span_size) / (size_t)(1024 * 1024),
            atomic_load32(&heap->stats_block_sizeclass_use[iclass].spans_map_calls));
    }
    fprintf(file, "Spans  Current     Peak Deferred  PeakMiB  Cached  ToCacheMiB FromCacheMiB ToReserveMiB FromReserveMiB ToGlobalMiB FromGlobalMiB  MmapCalls\n");
    for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass) {
        if (!atomic_load32(&heap->span_use[iclass].high) && !atomic_load32(&heap->span_use[iclass].stats_spans_map_calls))
            continue;
        fprintf(file, "%4u: %8d %8d %8d %8zu %7u %11zu %12zu %12zu %14zu %11zu %13zu %10d\n", (uint32_t)(iclass + 1),
            atomic_load32(&heap->span_use[iclass].current),
            atomic_load32(&heap->span_use[iclass].high),
            atomic_load32(&heap->span_use[iclass].stats_spans_deferred),
            ((size_t)atomic_load32(&heap->span_use[iclass].high) * (size_t)g_config_span_size * (iclass + 1)) / (size_t)(1024 * 1024),
#if ENABLE_SPAN_L1_TCACHE || ENABLE_SPAN_L1_CCACHE
#  if ENABLE_SPAN_L1_TCACHE
            (unsigned int)(!iclass ? heap->span_l1_tcache.spans_bucket.count : heap->span_l1_tcache.superspans_buckets[iclass - 1].count),
#  else /* ENABLE_SPAN_L1_CCACHE */
            0U,
#  endif /* ENABLE_SPAN_L1_TCACHE */
            ((size_t)atomic_load32(&heap->span_use[iclass].stats_spans_to_cache) * (iclass + 1) * g_config_span_size) / (size_t)(1024 * 1024),
            ((size_t)atomic_load32(&heap->span_use[iclass].stats_spans_from_cache) * (iclass + 1) * g_config_span_size) / (size_t)(1024 * 1024),
#else
            (size_t)0, (size_t)0,
#endif /* ENABLE_SPAN_L1_TCACHE || ENABLE_SPAN_L1_CCACHE */
            ((size_t)atomic_load32(&heap->span_use[iclass].stats_spans_to_reserved) * (iclass + 1) * g_config_span_size) / (size_t)(1024 * 1024),
            ((size_t)atomic_load32(&heap->span_use[iclass].stats_spans_from_reserved) * (iclass + 1) * g_config_span_size) / (size_t)(1024 * 1024),
            ((size_t)atomic_load32(&heap->span_use[iclass].stats_spans_to_l2) * (size_t)g_config_span_size * (iclass + 1)) / (size_t)(1024 * 1024),
            ((size_t)atomic_load32(&heap->span_use[iclass].stats_spans_from_global) * (size_t)g_config_span_size * (iclass + 1)) / (size_t)(1024 * 1024),
            atomic_load32(&heap->span_use[iclass].stats_spans_map_calls));
    }
    fprintf(file, "Full spans: %zu\n", heap->fully_inited_spans_count);
    fprintf(file, "L1ToL2MiB L2ToL1MiB\n");
    fprintf(file, "%17zu %17zu\n", (size_t)atomic_load64(&heap->stats_l1_to_l2) / (size_t)(1024 * 1024), (size_t)atomic_load64(&heap->stats_l2_to_l1) / (size_t)(1024 * 1024));
}

#endif

void
rpmalloc_dump_statistics(void* const file) {
#if ENABLE_STATISTICS
    for (size_t list_idx = 0; list_idx < HEAP_ARRAY_SIZE; ++list_idx) {
        heap_t* heap = g_alloc_heaps[list_idx];
        while (heap) {
            int need_dump = 0;
            for (size_t iclass = 0; !need_dump && (iclass < BLOCK_SMALL_MEDIUM_CLASS_COUNT); ++iclass) {
                if (!atomic_load32(&heap->stats_block_sizeclass_use[iclass].alloc_total)) {
                    rpmalloc_assert(!atomic_load32(&heap->stats_block_sizeclass_use[iclass].free_total), "Heap statistics counter mismatch");
                    rpmalloc_assert(!atomic_load32(&heap->stats_block_sizeclass_use[iclass].spans_map_calls), "Heap statistics counter mismatch");
                    continue;
                }
                need_dump = 1;
            }
            for (size_t iclass = 0; !need_dump && (iclass < BLOCK_LARGE_CLASS_COUNT); ++iclass) {
                if (!atomic_load32(&heap->span_use[iclass].high) && !atomic_load32(&heap->span_use[iclass].stats_spans_map_calls))
                    continue;
                need_dump = 1;
            }
            if (need_dump)
                _memory_heap_dump_statistics(heap, file);
            heap = heap->id_next_sll;
        }
    }
    fprintf(file, "Global stats:\n");
    const size_t huge_current = (size_t)atomic_load32(&g_stats_huge_pages_current) * g_config_page_size;
    const size_t huge_peak = (size_t)g_stats_huge_pages_peak * g_config_page_size;
    fprintf(file, "HugeCurrentMiB HugePeakMiB\n");
    fprintf(file, "%14zu %11zu\n", huge_current / (size_t)(1024 * 1024), huge_peak / (size_t)(1024 * 1024));

#  if ENABLE_SPAN_L1_CCACHE
    fprintf(file, "CPUCache stats:\n");

#    if !defined(NDEBUG)
    fprintf(file, "Operation  rseq_fin  rseq_abort  spans_requested  spans_carried_out  (over-/underflows)\n"
                  "     push%10zu  %10zu   %14zu     %14zu  (%16zu)\n"
                  "      pop%10zu  %10zu   %14zu     %14zu  (%16zu)\n",
            (size_t)atomic_load64(&g_span_l1_ccache_rseq_push_success_count), (size_t)atomic_load64(&g_span_l1_ccache_rseq_push_abort_count), (size_t)atomic_load64(&g_span_l1_ccache_spans_push_requested_count), (size_t)atomic_load64(&g_span_l1_ccache_spans_push_count), (size_t)(atomic_load64(&g_span_l1_ccache_spans_push_requested_count) - atomic_load64(&g_span_l1_ccache_spans_push_count)),
            (size_t)atomic_load64(&g_span_l1_ccache_rseq_pop_success_count), (size_t)atomic_load64(&g_span_l1_ccache_rseq_pop_abort_count), (size_t)atomic_load64(&g_span_l1_ccache_spans_pop_requested_count), (size_t)atomic_load64(&g_span_l1_ccache_spans_pop_count), (size_t)(atomic_load64(&g_span_l1_ccache_spans_pop_requested_count) - atomic_load64(&g_span_l1_ccache_spans_pop_count)));
#    endif

    fprintf(file, "Class    CurCount   CurAllocMiB (fullness)  BlkSize  BlkCount\n");
    // Each slot (CPU)
    size_t span_l1_ccache_mem_sum = 0,
            span_l1_ccache_mem_total = 0;
    for (unsigned int cpu = 0; cpu < g_span_l1_ccache_ncpus; ++cpu) {

        span_l1_cache_t* const span_l1_ccache_slot = _rpmalloc_span_l1_ccache_get_slot(cpu);
        size_t span_l1_ccache_slot_mem_sum = 0,
                span_l1_ccache_slot_mem_total = 0;
        char printed_already_cpu = 0;
        // Each "size class"
        for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass) {
            span_l1_cache_bucket_t* const spans_bucket = (!iclass) ? &span_l1_ccache_slot->spans_bucket :
                                                         (span_l1_cache_bucket_t*)(span_l1_ccache_slot->superspans_buckets + (iclass - 1));
            const size_t span_bucket_capacity = 0 == iclass ? SPAN_L1_CACHE_SPANS_BUCKET_CAPACITY : SPAN_L1_CACHE_SUPERSPANS_BUCKET_CAPACITY;
            const size_t span_l1_ccache_slot_class_mem_total = span_bucket_capacity * (iclass + 1) * g_config_span_size;
            span_l1_ccache_slot_mem_total += span_l1_ccache_slot_class_mem_total;

            if (! spans_bucket->count) {
                continue;
            }
            const size_t span_l1_ccache_slot_class_mem_sum = spans_bucket->count * (iclass + 1) * g_config_span_size;
            span_l1_ccache_slot_mem_sum += span_l1_ccache_slot_class_mem_sum;

            if (! printed_already_cpu) {
                fprintf(file, "Slot #%3u:\n", cpu);
                printed_already_cpu = 1;
            }
            fprintf(file, "  %2zu:     %3zu/%zu  %6.2f/%6.2f (%6.2f%%)     %4u      %4u\n",
                    iclass +1,
                    spans_bucket->count,
                    span_bucket_capacity,
#  define UNIT_BYTE_2_MIB (1024 * 1024.0)
                    span_l1_ccache_slot_class_mem_sum / UNIT_BYTE_2_MIB,
                    span_l1_ccache_slot_class_mem_total / UNIT_BYTE_2_MIB,
#  define UNIT_PERCENT (100)
                    (spans_bucket->count / (span_bucket_capacity *1.0)) *UNIT_PERCENT,
                    g_config_block_sizeclasses[iclass].block_size,
                    g_config_block_sizeclasses[iclass].block_count);
        }
        if (printed_already_cpu) {
            fprintf(file, "  (TotalSlotMiB = %.2f/%.2f (%.2f%%))\n",
                    span_l1_ccache_slot_mem_sum / UNIT_BYTE_2_MIB,
                    span_l1_ccache_slot_mem_total / UNIT_BYTE_2_MIB,
                    span_l1_ccache_slot_mem_sum / (span_l1_ccache_slot_mem_total *1.0) *UNIT_PERCENT);
        }
        span_l1_ccache_mem_sum += span_l1_ccache_slot_mem_sum;
        span_l1_ccache_mem_total += span_l1_ccache_slot_mem_total;
    }
    fprintf(file, "(TotalMiB = %.2f/%.2f (%.2f%%))\n",
            span_l1_ccache_mem_sum / UNIT_BYTE_2_MIB,
            span_l1_ccache_mem_total / UNIT_BYTE_2_MIB,
            (span_l1_ccache_mem_sum / (span_l1_ccache_mem_total *1.0)) *UNIT_PERCENT);
#  endif /* ENABLE_SPAN_L1_CCACHE */

#  if ENABLE_SPAN_L2_CACHE
    fprintf(file, "GlobalCacheMiB\n");
    for (size_t iclass = 0; iclass < BLOCK_LARGE_CLASS_COUNT; ++iclass) {
        span_l2_cache_t* const l2_cache = g_alloc_span_l2_cache + iclass;
        const size_t global_cache = (size_t)l2_cache->count * iclass * g_config_span_size;

        size_t global_overflow_cache = 0;
        span_t* span = l2_cache->overflow_dll;
        while (span) {
            global_overflow_cache += iclass * g_config_span_size;
            span = span->next_dll;
        }
        if (global_cache || global_overflow_cache || l2_cache->stats_insert_count || l2_cache->stats_extract_count)
            fprintf(file, "%4zu: %8zuMiB (%8zuMiB overflow) %14zu insert %14zu extract\n", iclass + 1, global_cache / (size_t)(1024 * 1024), global_overflow_cache / (size_t)(1024 * 1024), l2_cache->stats_insert_count, l2_cache->stats_extract_count);
    }
#  endif

    const size_t mapped = (size_t)atomic_load32(&g_stats_mapped_pages) * g_config_page_size;
    const size_t mapped_os = (size_t)atomic_load32(&g_stats_mapped_pages_os) * g_config_page_size;
    const size_t mapped_peak = (size_t)g_stats_mapped_pages_peak * g_config_page_size;
    const size_t mapped_total = (size_t)atomic_load32(&g_stats_mapped_total) * g_config_page_size;
    const size_t unmapped_total = (size_t)atomic_load32(&g_stats_unmapped_total) * g_config_page_size;
    fprintf(file, "MappedMiB MappedOSMiB MappedPeakMiB MappedTotalMiB UnmappedTotalMiB\n");
    fprintf(file, "%9zu %11zu %13zu %14zu %16zu\n",
        mapped / (size_t)(1024 * 1024),
        mapped_os / (size_t)(1024 * 1024),
        mapped_peak / (size_t)(1024 * 1024),
        mapped_total / (size_t)(1024 * 1024),
        unmapped_total / (size_t)(1024 * 1024));

    fprintf(file, "\n");
#  if 0
    int64_t allocated = atomic_load64(&g_stats_allocation_counter);
    int64_t deallocated = atomic_load64(&g_stats_deallocation_counter);
    fprintf(file, "Allocation count: %lli\n", allocated);
    fprintf(file, "Deallocation count: %lli\n", deallocated);
    fprintf(file, "Current allocations: %lli\n", (allocated - deallocated));
    fprintf(file, "Master spans: %d\n", atomic_load32(&g_stats_master_spans));
    fprintf(file, "Dangling master spans: %d\n", atomic_load32(&g_stats_unmapped_master_spans));
#  endif
#else
    WARN_SUPPRESS_UNUSED(file);
#endif /* ENABLE_STATISTICS */
}



#if ENABLE_PRELOAD || ENABLE_OVERRIDE

#  include "malloc.c"

#endif

void
rpmalloc_linker_reference(void) {
    WARN_SUPPRESS_UNUSED(g_alloc_state_inited);
}
