# jemalloc prototype w/ ccache

Prototype DERIVED FROM: https://github.com/jemalloc/jemalloc/pull/2264/files
  <pre>
  <b>ccache: Implement per-CPU cache</b>
  An overview of the implementation:
  Ccache by itself is very similar to the tcache. It serves a fixed (so far)
  amount of size classes on top of tcache_maxclass, there is no overlap in
  size classes served by Ccache and Tcache. The pointers are stored and
  allocated out of stack, flush/fill logic is reused too. Except for the
  flush, ccache flushes pointers in LIFO order. If an allocation
  overflows/underflows, the thread transfers the ccache into a 'special
  state', preventing anyone else from touching the underlying data
  structre, and performs refill/flush.
  </pre>

- Relevant files (AGAIN: SEE PR):
  - [`include/jemalloc/internal/ccache.h`](include/jemalloc/internal/ccache.h)  &rarr; Public API
  - [`include/jemalloc/internal/ccache_types.h`](include/jemalloc/internal/ccache_types.h)  &rarr; includes `linux/rseq.h`
  - ( [`src/arena.c`](src/arena.c) )
  - [`src/ccache.c`](src/ccache.c)

- NOTE: Relevant changes are marked w/ `/* $$$  cid addition  $$$ */`


## Build
- ( See [INSTALL.md](./INSTALL.md) 4 available options )
- ccache:
  ```bash
  # IN-SOURCE BUILD:
  ./autogen.sh --enable-cpu-cache  ( --enable-debug )
  make -j

  # OUT-OF-SOURCE BUILD:
  ./autogen.sh --enable-cpu-cache  ( --enable-debug )
  mkdir -p build  && cd build
  ../configure --enable-cpu-cache  ( --enable-debug )
  make -j
  ```


## Runtime configuration
-  ( ~~OFFICIAL DOC.: https://github.com/jemalloc/jemalloc/wiki/Getting-Started~~ (outdated), MAN PAGE: https://man.archlinux.org/man/extra/jemalloc/jemalloc.3.en )
  ```
  # SEE: `src/ctl.c`
  export MALLOC_CONF="ccache:true,ccache_force_cpu_id:false"
  ```
  * `ccache`: Enables / Disables CPU cache (by default `false`. i.e., disabled)
  * `ccache_force_cpu_id`: Don't use concurrency id (if supported; by default `false` - unless the cid isn't supported by the kernel)

### ( VALIDATION (whether ccache is being used) )
```bash
# Run from testing dir
gdb   -ex 'set args 10 7 500 1000 10000 1 2'     -ex 'set env MALLOC_CONF ccache:true'  -ex 'set env LD_PRELOAD ../ccache-alloc/jemalloc/lib/libjemalloc.so' -ex 'r' -ex 'b tsd_ccache_init' -ex 'b je_ccache_init' -ex 'b je_ccache_alloc' -ex 'b je_ccache_free'  -ex 'r'  -ex 'p /u opt_ccache' ./build/benchmarks/3rd_party/mimalloc-bench/larson
```
