# Examples
* [Multi-Producer, Single-Consumer ring buffer](./mpsc_rb_demo.c)
* Memory allocators:
  * [jemalloc](memory_allocators/jemalloc)
  * [rpmalloc](memory_allocators/rpmalloc)


## Build
* Prerequisites:
  * Installed `cmake` & optionally `ccmake`:
    * Debian/Ubuntu: `sudo apt install -y cmake cmake-curses-gui`

* Out-of-source build:
  1. `mkdir build && cd build`
  2. `cmake -DRSEQ_USE_CID=OFF ..` (or `ON` if target system uses Linux 6.3.0+)
  3. `make -j`
