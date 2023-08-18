#ifndef INCLUDE_COMMON_H_
#define INCLUDE_COMMON_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#if defined(__linux__)
#  if defined(__linux__) && !defined(_GNU_SOURCE)
#    error "Requires `-D_GNU_SOURCE`"
#  endif
#  include <sched.h>
#endif /* __linux__ */

#include <pthread.h>      // Required 4 `pthread_getaffinity_np`

#include <assert.h>
#include <stdint.h>


#ifdef __cplusplus
namespace gg {
#endif


// ---------------------------------------------------------------------
// Taken from `compiler.h`

#if defined(__GNUC__) || defined(__clang__)
#  define BRANCH_UNLIKELY(x)     (__builtin_expect(!!(x),0))
#elif (defined(__cplusplus) && (__cplusplus >= 202002L)) || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#  define BRANCH_UNLIKELY(x)     (x) [[unlikely]]
#else
#  define BRANCH_UNLIKELY(x)     (x)
#endif


// ---------------------------------------------------------------------
// Taken from `preproc.h`

#define EXPANDSTR(str) #str
#define STRINGIFY(str) EXPANDSTR(str)


// ---------------------------------------------------------------------
// Taken from `error.h`

#ifdef __clang__
#  pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"   // Ignore "error: token pasting of ',' and __VA_ARGS__ is a GNU extension [-Werror,-Wgnu-zero-variadic-macro-arguments]"
#endif /* __clang__ */


#ifdef LOG_NO_LIBC_BUFFERING
ATTR_EXTERNC void ___FWRITE_LOG__(const int fd, const char* const fmt, ...);

#  define ___WRITE_LOG__(LOG_TYPE, FMT, ...)\
  do {\
    ___FWRITE_LOG__(STDERR_FILENO, "[" LOG_TYPE "] `%s` (" __FILE__ ":" STRINGIFY(__LINE__) "): " FMT ".\n", __func__, ##__VA_ARGS__);\
  } while(0)
#else
#  define ___WRITE_LOG__(LOG_TYPE, FMT, ...)\
  do {\
    if BRANCH_UNLIKELY( fprintf(stderr, "[" LOG_TYPE "] `%s` (" __FILE__ ":" STRINGIFY(__LINE__) "): " FMT ".\n", __func__, ##__VA_ARGS__)  <  0 ) {\
      _exit(EXIT_FAILURE);\
    }\
  } while(0)
#endif /* LOG_NO_LIBC_BUFFERING */



// --  Error handling macros  --
#ifndef NDEBUG
#  define LOG_DEBUG(FMT, ...) ___WRITE_LOG__("DEBUG", FMT, ##__VA_ARGS__)
#else
#  define LOG_DEBUG(FMT, ...) do { } while(0)
#endif /* NDEBUG */

#define LOG_WARN(FMT, ...) ___WRITE_LOG__("WARN", FMT, ##__VA_ARGS__)

#define LOG_ERROR_AND_DIE(FMT, ...)\
  do {\
    ___WRITE_LOG__("ERROR", FMT, ##__VA_ARGS__);\
    exit(EXIT_FAILURE);\
  } while(0)


/* To be used for library functions which make use of `errno` and
 * return an int, where `-1` indicates an error condition
 */
#define DIE_WHEN_ERRNO(FUNC) __extension__({ ({\
    __typeof__(FUNC) __val = (FUNC);\
    (BRANCH_UNLIKELY(-1 == __val) ? ({ LOG_ERROR_AND_DIE("%s", strerror(errno)); -1; }) : __val);\
  }); })

/* To be used for non-library functions which return an int, where
 * `-1` indicates an error condition
 */
#define DIE_WHEN_ERR(FUNC) __extension__({ ({\
    __typeof__(FUNC) __val = (FUNC);\
    (BRANCH_UNLIKELY(-1 == __val) ? ({ LOG_ERROR_AND_DIE(#FUNC); -1; }) : __val);\
  }); })

/* To be used for library functions which make use of `errno` and
 * return a void pointer, where `NULL` indicates an error condition
 */
#define DIE_WHEN_ERRNO_VPTR(FUNC) __extension__({ ({\
    __typeof__(FUNC) __val = (FUNC);\
    (BRANCH_UNLIKELY(NULL == __val) ? ({ LOG_ERROR_AND_DIE("%s", strerror(errno)); (__typeof__(FUNC))NULL; }) : __val);\
  }); })

/* To be used for non-library functions which return an void pointer,
 * where `NULL` indicates an error condition
 */
#define DIE_WHEN_ERR_VPTR(FUNC) __extension__({ ({\
    __typeof__(FUNC) __val = (FUNC);\
    (BRANCH_UNLIKELY(NULL == __val) ? ({ LOG_ERROR_AND_DIE(#FUNC); (__typeof__(FUNC))NULL; }) : __val);\
  }); })


// ---------------------------------------------------------------------
// Taken from `os.h`
// Derived from: https://github.com/jemalloc/jemalloc/blob/e8f9f13811c16acb1ab8771fd2ffe4437e1b8620/src/jemalloc.c#L723
static inline int system_get_ncpus(const char only_avail_cpus) {
    long result = -1;

    if (only_avail_cpus) {
#ifdef CPU_COUNT    /* NOTE: glibc >= 2.6 has the `CPU_COUNT` macro */
{
        cpu_set_t set;
  /* Typically ONLY supported on GNU/Linux  (https://linux.die.net/man/2/sched_getaffinity)
   * IMPORTANT: Requires CMake check:
   *   ```
   *   include(CheckSymbolExists)
   *   list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
   *   check_symbol_exists(sched_getaffinity "sched.h" HAVE_SCHED_GETAFFINITY)
   *   list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
   *   ```
   */
#  ifndef HAVE_SCHED_GETAFFINITY
#    define HAVE_SCHED_GETAFFINITY 0
#  endif
#  if HAVE_SCHED_GETAFFINITY
        sched_getaffinity(0, sizeof(set), &set);
#  else
        pthread_getaffinity_np(pthread_self(), sizeof(set), &set);
#  endif /* HAVE_SCHED_GETAFFINITY */

        result = CPU_COUNT(&set);
}
#else
#  warning "The current platform doesn't support retrieving the # of available CPUs"
#endif /* CPU_COUNT */

    } else {
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        result = si.dwNumberOfProcessors;
#else
        result = sysconf(_SC_NPROCESSORS_ONLN);
#endif
    }

    return result;
}


#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_COMMON_H_ */
