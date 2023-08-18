* NOTEs:
  * Work partially derived from thesis
  * The folder
    * [docs](docs/) contains the MPSC ring-buffer example + defense slides
    * [ccache_protos](ccache_protos/) contains the source of the allocators + build instructions


# Restartable Sequences (RSEQs)
## Background
* **Access** to shared data must be **synchronized** to **avoid *race conditions*** in case the data is modified concurrently by multiple threads
* This problem can be solved by protecting the *critical section* (*CS*) (where the shared data is modified) via a *synchronization primitive* (e.g., a mutex lock or a semaphore)
* Introducing synchronization in a highly parallel application can however result in **high contention** (= many threads block and try to acquire the lock which deteriorates performance)
* A popular approach of **reducing contention** is the use of **per-CPU data structures**
  * Example: Naïve Multi-Producer, Single-Consumer (MPSC) ring buffer implementation
    * Operations:
      * *Offering*:
        * Inserts a new item
        * Requires the producer to
          * 1) read the current write position (a.k.a., the *head*),
          * 2) write the new item and
          * 3) update the head. Updating the head effectively commits the change, making the item visible to the consumer.
      * *Polling*
        * Reads an item
        * Requires the consumer to
          * 1) read the current read position (a.k.a., the *tail*),
          * 2) read the item and
          * 3) update the read position.
  * This data structure is *thread safe* with respect to parallel access
  * HOWEVER: Not thread safe with respect to other threads running on the same CPU in case no synchronization primitive is used
    * Suppose,
      * 1. Producer A finished writing a new item but gets preempted by the OS before it could commit
      * 2. Producer B, running on the same CPU, reads the old head, starts overwriting Producer A's uncommitted item and commits its own
      * 3. Producer A continues and tries to commit its now overwritten item
    * Thus, synchronization is needed to enforce **atomicity with respect to preemption**
* Thread safety can be achieved by commiting items using e.g., an atomic instruction like *CAS*:
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
* Alternatively, preemption can be disabled altogether while manipulating per-CPU data structures
  * This ability is limited to kernel space
  * User space has to rely on detecting preemption (with the help of the OS scheduler) and if necessary, restart the preempted operation
* RSEQs (developed by Paul Turner and Andrew Hunter at Google and Mathieu Desnoyers at EfficiOS) are the implementation of aforesaid concept in the Linux kernel
  * This mechanism has been part of the Linux kernel since version 4.18


## RSEQ ABI
### `struct rseq`
* Serves as **kernel- &harr; user space interface**:
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
* Member fields:
  * Fields for e.g., **indexing** in per-CPU data structures:
    * `cpu_id_start`/`cpu_id`:
      * Holds current CPU number on which the registered thread is running on
        * Range: 0 &le; `cpu_id` < # of CPUs.
      * Difference: 
        * `cpu_id_start` always holds a valid CPU number (even when `struct rseq` hasn't been registered yet)
        * `cpu_id` is initialized with `-1`
    * As of Linux 6.3:
      * `node_id`: 
        * Initialized with `0`
        * Holds once inited the current NUMA ID 
      * `mm_cid`:
        * Abbreviation for *memory map concurrency id* (*cid*)
        * Holds a unique, temporarily assigned value, which is allotted by the scheduler to each actively running thread within a process
          * Range: 0 &le; `mm_cid` &lt; # of actively running threads &le; # of CPUs
        * The main beneficiaries of this new field are processes which have fewer threads than cores or which have been restricted to run on fewer cores through scheduler affinity or cgroup cpusets
          * The cid is closer to `0` (v.s., `cpu_id`), allowing for a more efficient (re-)use of memory when indexing in per-\gls{acr:CPU} data structures (e.g., in memory allocators)
  * `rseq_cs`: Pointer to data structure which **describes the CS** (a.k.a., the *CS descriptor*)
  * ~~`flags`: Deprecated as of Linux 6.1~~
* Thread registration is performed using RSEQ syscall for EACH thread individually
  * Handled automatically since glibc 2.35  (this behavior can be disabled using the `glibc.pthread.rseq` tunable)
  * Once registration is complete: Scheduler will update the member fields (which then can be read by the user space thread)
* Things to keep in mind:
  * The `struct` must be allocated as **global TLS variable**
  * Accessing the struct (after successful registration):
    * Done using the **macro `define RSEQ_ACCESS_ONCE(x) (*(__volatile__ __typeof__(x) *)&(x))`**
      * Necessary as a compiler might optimize out memory reads pertaining `struct rseq` member fields  (The struct is updated externally by the kernel. This happens unbeknownst to the compiler, which assumes the struct never changes, as it's never written to by the user space program)
    * Program running with a glibc version &ge; 2.35 must take an additional **step of indirection** when accessing `struct rseq`
      * Glibc maintains the registered `struct rseq` within the Thread Control Block (TCB)
        * Accessing it requires adding an offset, exported as symbol `__rseq_offset`, to the thread pointer
        * This pointer can be obtained using the gcc builtin `__builtin_thread_pointer`

### RSEQ syscall
* Atm there's no glibc syscall wrapper
  * Must be invoked either using the
    * [`syscall` function](https://man7.org/linux/man-pages/man2/syscall.2.html) or
    * inline asm
* Args of syscall:
  ```C
  SYSCALL_DEFINE4(rseq,             // Taken from Linux 6.3 source tree
                  struct rseq __user *, rseq,       // Address of allocated data structure
                  u32, rseq_len,                    // Length of structure (tells kernel which fields need to be updated)
                  int, flags,                       // `0` = perform the registration / `RSEQ_FLAG_UNREGISTER` = unregister already registered struct
                  u32, sig)                         // Used for thwarting binary exploitation attacks
  ```
* Registers `struct rseq` for invoking thread

### `struct rseq_cs` (a.k.a., the *CS descriptor*)
* This struct **describes a CS**
* Critical sections:
  * Contain the operations which are carried out on per-CPU data structures
  * Guarded against interruptions by RSEQ mechanism
    * An active CS may either be interrupted by 
      * migration to another CPU
      * unmasked / non-maskable signals or
      * preemption
  * Limitations (of CS):
    * Consist of two stages:
      * Preparatory stage: 
        * The to be committed changes are prepared
        * Must be carried out in a discrete manner, such that they're invisible to other threads
      * Commit stage:
        * Publishes made changes 
        * Must consist of a single atomic instruction
    * Written in asm since:
      The generated machine instructions must faithfully follow the *program order* as defined in the source
      Issue in high-level languages, where the compiler might reorder stores for optimization purposes.
      Such optimizations can change the program order by e.g., preponing the store associated with the commit phase into the preparatory phase.
    * Should never invoke syscalls
    * Function calls within aren't permitted
      Doing so would move the IP outside the CS, making the detection (whether a \gls{acr:CS} was active) impossible.}
    * Stack operations should be limited to reserved stack space  (e.g., local variables defined in the C code preceding the inline assembly block).
      Pushing elements also requires an attendant undo operation upon exit.
      However, undoing the operation with `pop` could result in stack memory corruption if the CS was interrupted prior to the `push` operation.
    * CS must be kept brief
      A too long CS will be perpetually restarted as the time slice (allotted by the scheduler) is always expiring before the \gls{acr:CS} can finish.
    * CS cannot be debugged
      Setting a breakpoint within the CS would later interrupt it, causing it to be restarted indefinitely.
      RSEQ CSs should therefore be declared in the dedicated ELF sections `__rseq_cs_ptr_array` and `__rseq_exit_point_array`.
      Debuggers like gdb can simply read these sections and skip all CS when single stepping.

* Example: MPSC ring buffer (in C-like pseudolanguage for better intelligibility): 
  * CS of ring-buffer:
    ![CS: Ring buffer offer example](_assets/rb-ex-cs.png)
    * Attendant descriptor of CS:
      ```C
      struct rseq_cs descriptor = {
          .version = 0,
          .flags = 0,
          .start_ip = &&start,                                                      // Points to first machine instruction in CS
          .post_commit_offset = (uintptr_t)&&post_commit - (uintptr_t)&&start,      // Length of CS in bytes
          .abort_ip = &&abort
      };
      ```

* Simplified scheduler check:
  ![RSEQ: (Simplified) scheduler check](_assets/rseq-simplified_restart_check.png)
  * When scheduling a thread, the Linux scheduler will check whether
    * a CS descriptor has been set in the `rseq_cs` field of `struct rseq`
    * If this is the case, the kernel will check whether the saved IP address is falling in the range `start_ip` &le; IP address < `start_ip` + `post_commit_offset`
















## [Memory allocator prototypes](ccache_protos)
* These prototypes **utilize RSEQs** to **implement *CPU caches*** (*ccaches*)
* CPU caches have
  * The ccaches serve as a substitute for *thread caches* (*tcaches*)
* `free`d memory is moved to the ccache corresponding to the CPU on which , where e

