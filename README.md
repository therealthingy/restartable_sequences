

# Restartable Sequences (RSEQs)
## Motivation
The potential use cases of RSEQs in user space are:
  * Efficiently retrieving the CPU on which the thread is currently running on, e.g., for indexing in per-CPU data structures
  * Modifying per-CPU data structures which are protected by spinlocks

The following paragraphs focus on the latter use case (which also relies on the first use case).


### Per-CPU data structures
* **Access** to shared data must be **synchronized** to **avoid *race conditions*** in case the data is modified concurrently by multiple threads
* This problem can be solved by protecting the *critical section* (*CS*) (where the shared data is modified) via a *synchronization primitive* (e.g., a mutex lock or a semaphore)
* Introducing synchronization in a highly parallel application can however result in **high contention** (= many threads block and try to acquire the lock which deteriorates performance)
* A popular approach of **reducing contention** is the use of **per-CPU data structures**

* Example of a (per-CPU data structure): [**Multi-Producer, Single-Consumer (MPSC) ring buffer** implementation](examples/mpsc_rb_demo.c)
  * Supported operations (of the data structure):
    * *Offering*:
      * Inserts a new item
      * Requires the producer to &mldr;
        * 1.) read the current write position (a.k.a., the *head*),
        * 2.) write the new item and
        * 3.) update the head. Updating the head effectively commits the change, making the item visible to the consumer.
    * *Polling*:
      * Reads an item
      * Requires the consumer to &mldr;
        * 1.) read the current read position (a.k.a., the *tail*),
        * 2.) read the item and
        * 3.) update the read position.

### Synchronization when working w/ per-CPU data structures
* This data structure is "inherently" (as each SW thread running on a HW thread has its own data structure) *thread safe* with respect to parallel access
* HOWEVER, it's not "inherently" (as long as no synchronization primitive is used) thread safe with respect to other threads running on the same CPU
  * Hence, the following sequence of events could occur:
    * 1.) Producer A finished writing a new item but gets preempted by the OS before it could commit
    * 2.) Producer B, running on the same CPU, reads the old head, starts overwriting Producer A's uncommitted item and commits its own
    * 3.) Producer A continues and tries to commit its now overwritten item
  * &rarr; Synchronization is thus needed to enforce **atomicity with respect to preemption**

* There are different "approaches" for mitigating this synchronization issue:
  * Commiting items using e.g., an atomic instruction like *CAS*:
    ```
    bool CAS(object: pointer, expected: int, desired: int):
      if *object == expected:
        *object = desired
        return true
      return false
    ```
    * This approach has a few downsides:
      * Performance penalty
      * ABA problem

  * Disabling preemption altogether while manipulating per-CPU data structures
    * This ability is limited to kernel space

  * RSEQs (developed by Paul Turner and Andrew Hunter at Google and Mathieu Desnoyers at EfficiOS)
    * Idea: ***Detect preemption** (with the help of the OS scheduler) and if necessary, restart the preempted operation
    * RSEQ = the implementation of aforesaid concept in the Linux kernel
    * This mechanism has been part of the Linux kernel since version 4.18


## RSEQ ABI
### [`struct rseq`](https://github.com/torvalds/linux/blob/f7b01bb0b57f994a44ea6368536b59062b796381/include/uapi/linux/rseq.h#L62)
* Serves as **kernel- &harr; user space interface** which is used to manage RSEQs in each thread individually
* "Lifecycle":
  * Setup:
    * ~~It's the responsibility of each user space thread (which wants to use RSEQs) to:~~
      * ~~a) allocate the `struct` as a **global TLS variable**~~
      * ~~b) perform the thread registration using the [RSEQ syscall](#RSEQ-syscall)~~
      This is handled automatically since glibc 2.35  (can be disabled using the [`glibc.pthread.rseq` tunable](https://www.gnu.org/software/libc/manual/html_node/POSIX-Thread-Tunables.html#index-glibc_002epthread_002erseq))
  * Usage:
    * Once registration is complete: Scheduler will update the member fields (which then can be read by the user space thread)
    * THINGS TO KEEP IN MIND when accessing the `struct` (after successful registration):
      * Should be done using a macro like: **`define RSEQ_ACCESS_ONCE(x) (*(__volatile__ __typeof__(x) *)&(x))`**
        * Necessary as a compiler might optimize out memory reads pertaining `struct rseq` member fields  (the struct is updated externally by the kernel. This happens unbeknownst to the compiler, which assumes the struct never changes, as it's never written to by the user space program)
      * NOTE: Program running with a glibc version &ge; 2.35 must take an additional **step of indirection** when accessing `struct rseq`
        * Glibc maintains the registered `struct rseq` within the Thread Control Block (TCB)
          * Accessing it requires adding an offset, exported as [symbol `__rseq_offset`](https://www.gnu.org/software/libc/manual/html_node/Restartable-Sequences.html#index-_005f_005frseq_005foffset), to the thread pointer
          * This pointer can be obtained using the gcc builtin `__builtin_thread_pointer`

* "Layout":
  ```C
  struct rseq {             // Taken from Linux 6.3 source tree
      __u32 cpu_id_start;
      __u32 cpu_id;
      __u64 rseq_cs;
      __u32 flags;
      __u32 node_id;
      __u32 mm_cid;
      char end[];
  } __attribute__((aligned(4 * sizeof(__u64))));
  ```

  * Fields for e.g., **indexing** in per-CPU data structures:
    * `cpu_id_start`/`cpu_id`:
      * Both hold current CPU number on which the registered thread is running on
        * Range: <pre>0 &le; `cpu_id` &lt; # of CPUs</pre>
      * They essentially only differ with their init values:
        * `cpu_id_start` always holds a valid CPU number (even when `struct rseq` hasn't been registered yet)
        * `cpu_id` is initialized with `-1`
    * Additions (as of Linux 6.3):
      * `node_id`:
        * Initialized with `0`
        * Holds (once inited) the current NUMA ID
      * `mm_cid`:
        * Abbreviation for *memory map concurrency id* (*cid*)
        * Holds unique, temporarily assigned value, which is allotted by the scheduler to each actively running thread within a process
          * Range: <pre>0 &le; `mm_cid` &lt; # of actively running threads &le; # of CPUs</pre>
        * The main beneficiaries of this new field are processes which have fewer threads than cores or which have been restricted to run on fewer cores through scheduler affinity or cgroup cpusets
          * The cid is closer to `0` (v.s., `cpu_id`), allowing for a more efficient (re-)use of memory when indexing in per-CPU data structures (e.g., in memory allocators)
  * `rseq_cs`: Pointer to data [structure which **describes the CS** (a.k.a., the *CS descriptor*)](#struct-rseq_cs)
  * ~~`flags`: Deprecated as of Linux 6.1~~

### [RSEQ syscall](https://github.com/torvalds/linux/blob/f7b01bb0b57f994a44ea6368536b59062b796381/kernel/rseq.c#L365)
* Registers / unregisters `struct rseq` for invoking thread

* Args of syscall:
  ```C
  SYSCALL_DEFINE4(rseq,             // Taken from Linux 6.3 source tree
                  struct rseq __user *, rseq,       // Address of allocated `struct rseq`
                  u32, rseq_len,                    // Length of structure (tells kernel which `struct rseq` fields need to be updated -- ensures backward compatibility (as the user space program might still use an older definition of the struct, which doesn't include fields like `mm_cid`))
                  int, flags,                       // `0` = perform the registration / `RSEQ_FLAG_UNREGISTER` = unregister already registered struct
                  u32, sig)                         // Used for thwarting binary exploitation attacks
  ```

  * NOTE: As of glibc 2.35, there's no glibc syscall wrapper  (there *shouldn't* be a need anyways, as registration is handled by glibc)
    * Therefore, must be invoked either using the
      * [`syscall` function](https://man7.org/linux/man-pages/man2/syscall.2.html) or
      * inline asm

### [`getauxval`(3)](https://github.com/torvalds/linux/blob/317c8194e6aeb8b3b573ad139fc2a0635856498e/fs/binfmt_elf.c#L292)
* Allows the user space program to detect which feature fields (in `struct rseq`) are supported by the kernel  (e.g., kernels &le; 6.3 don't support the `mm_cid`)
  ```C
  #include <sys/auxv.h>

  #define rseq_sizeof_field(TYPE, MEMBER) sizeof((((TYPE*)0)->MEMBER))
  #define rseq_offsetofend(TYPE, MEMBER) (offsetof(TYPE, MEMBER) + rseq_sizeof_field(TYPE, MEMBER))

  const unsigned long auxv_rseq_feature_size = getauxval(AT_RSEQ_FEATURE_SIZE);
  const bool mm_cid_is_supported = (int)auxv_rseq_feature_size >= (int)rseq_offsetofend(struct rseq, mm_cid);
  ```

### [`struct rseq_cs`](https://github.com/torvalds/linux/blob/f7b01bb0b57f994a44ea6368536b59062b796381/include/uapi/linux/rseq.h#L45)  (a.k.a., the *CS descriptor*)
* Difference: *Critical section* (*CS*) v.s., *CS descriptor*:
  * ***Critical section***:
    * The CS itself contains the operations which shall be carried out to modify the per-CPU data structures
    * This CS is **guarded against interruptions** by RSEQ mechanism
      * An active CS may either be interrupted by
        * migration to another CPU
        * unmasked / non-maskable signals or
        * preemption
    * Limitations (of CS):
      * Consist of **two stages**:
        * *Preparatory* stage:
          * The to be committed changes are prepared
          * Must be carried out in a discrete manner, such that they're **invisible to other threads**  (until they're finally commited)
        * *Commit* stage:
          * Publishes made changes
          * Must consist of a **single atomic instruction**
      * Must be **written in asm**
        The generated machine instructions must faithfully follow the *program order* (as defined in the source).
        This is an issue in high-level languages, as reorders of stores might occur by the compiler (for optimization purposes).
        Such optimizations can change the program order by e.g., preponing the store associated with the commit phase into the preparatory phase.
      * Should **never invoke syscalls**
      * **No function calls**
        Doing so would move the IP outside the CS, making the detection (whether a CS was active) impossible.
      * Stack operations should be limited to reserved stack space  (e.g., local variables defined in the C code preceding the inline assembly block)
        Pushing elements also requires an attendant undo operation upon exit.
        However, undoing the operation with `pop` could result in stack memory corruption if the CS was interrupted prior to the `push` operation.
      * CS must be kept ***brief**
        A too long CS will be perpetually restarted as the time slice (allotted by the scheduler) is always expiring before the CS can finish.
      * CS **cannot be debugged**
        Setting a breakpoint within the CS would later interrupt it, causing it to be restarted indefinitely.
        RSEQ CSs should therefore be declared in the dedicated ELF sections `__rseq_cs_ptr_array` and `__rseq_exit_point_array`.
        Debuggers like `gdb` can simply read these sections and skip all CS when single stepping.

  * ***CS descriptor***: `struct` **describing the *critical section***
    * This includes e.g., where the CS starts & ends  (see Ex. down below)

  * Example: [MPSC ring buffer]((examples/rseq_mpsc_rb_demo.c)) (in C-like pseudolanguage for better intelligibility):
    * Critical section (this includes only the pseudocode after `start:`):
      ![CS: Ring buffer offer example](_assets/rb-ex-cs.png)
    * Attendant descriptor of CS  (describing the ):
      ```C
      struct rseq_cs descriptor = {
          .version = 0,
          .flags = 0,
          .start_ip = &&start,                                                      // Points to first machine instruction in CS
          .post_commit_offset = (uintptr_t)&&post_commit - (uintptr_t)&&start,      // Length of CS in bytes
          .abort_ip = &&abort
      };
      ```

* Lifecycle / USAGE:
  * Allocated ……………………………………………………


* Simplified scheduler check:
  ![RSEQ: (Simplified) scheduler check](_assets/rseq-simplified_restart_check.png)
  * When scheduling a thread, the Linux scheduler will check whether
    * a CS descriptor has been set in the `rseq_cs` field of `struct rseq`
    * If this is the case, the kernel will check whether the saved IP address is falling in the range `start_ip` &le; IP address &lt; `start_ip` + `post_commit_offset`
























---
## [Memory allocator prototypes](ccache_protos)
* These prototypes **utilize RSEQs** to **implement *CPU caches*** (*ccaches*)
* CPU caches have
  * The ccaches serve as a substitute for *thread caches* (*tcaches*)
* `free`d memory is moved to the ccache corresponding to the CPU on which , where e

