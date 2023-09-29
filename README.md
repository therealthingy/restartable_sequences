# Restartable Sequences (RSEQs)

## Motivation
The potential use cases of RSEQs in user space are:
  * Efficiently **retrieving the CPU** on which the thread is currently running on, e.g., for indexing in per-CPU data structures
  * **Modifying per-CPU data structures** which are protected by spinlocks

The following paragraphs focus on the latter use case (which implicitly relies on the first use case).


### Per-CPU data structures
* **Access** to shared data must be **synchronized** to **avoid *race conditions*** in case the data is modified concurrently by multiple threads
* This problem can be solved by protecting the *critical section* (*CS*) (where the shared data is modified) via a *synchronization primitive*, e.g., using a mutex lock or a semaphore
* Introducing synchronization in a highly parallel application can however result in **high contention** (= many threads block and try to acquire the lock which deteriorates performance)
* A popular approach of **reducing contention** is the use of **per-CPU data structures**

* Example (of a per-CPU data structure): **Ring buffer (rb)** implementation
  * Supported operations (of the data structure):
    * *Offering*:
      * Inserts a new item
      * Requires the producer to &mldr;
        * (1.) read the current write position (a.k.a., the *head*),
        * (2.) write the new item and
        * (3.) update the head. Updating the head effectively commits the change, making the item visible to the consumer.
    * *Polling*:
      * Reads an item
      * Requires the consumer to &mldr;
        * (1.) read the current read position (a.k.a., the *tail*),
        * (2.) read the item and
        * (3.) update the read position.

### Synchronizing the access on per-CPU data structures
* The rb is "inherently" (as each user space thread running on a CPU has its own data structure) *thread safe* with respect to parallel access
* HOWEVER, it's **not** "inherently" (as long as no synchronization primitive is used) thread safe with respect to other threads running on the same CPU
  * Hence, the following sequence of events could occur:
    * (1.) Producer A finished writing a new item but gets preempted by the OS before it could commit
    * (2.) Producer B, running on the same CPU, reads the old head, starts overwriting Producer A's uncommitted item and commits its own
    * (3.) Producer A continues and tries to commit its now overwritten item
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
      * [ABA problem](https://en.wikipedia.org/wiki/ABA_problem)

  * ~~Disabling preemption altogether while manipulating per-CPU data structures~~
    * This ability is limited to kernel space

  * RSEQs (developed by Paul Turner and Andrew Hunter at Google and Mathieu Desnoyers at EfficiOS)
    * Idea: **Detect preemption** (with the help of the OS scheduler) and if necessary, restart the preempted operation
    * *RSEQ* = the implementation of aforesaid concept in the Linux kernel
    * This mechanism has been part of the Linux kernel since version 4.18


## RSEQ ABI
* The relevant data structure definitions (for user space) can be found in the header file:
  * `linux/rseq.h`, provided by [`linux-libc-dev`](https://packages.debian.org/de/sid/linux-libc-dev)  (may contain outdated definitions depending on libc version)
  * [`rseq/rseq.h`](https://github.com/compudj/librseq/blob/8dd73cf99b9bd3dbbbbe7268088ffd3e66b2e50a/include/rseq/rseq.h), provided by [librseq](#librseq)

### `struct rseq`
* Definition in kernel source tree (as of 6.3): [`include/uapi/linux/rseq.h`](https://github.com/torvalds/linux/blob/f7b01bb0b57f994a44ea6368536b59062b796381/include/uapi/linux/rseq.h#L62)
* Serves as **kernel- &harr; user space interface** which is used to manage RSEQs in each thread individually
* "Lifecycle":
  * Setup:
    * ~~It's the responsibility of each user space thread (which wants to use RSEQs) to:~~
      * ~~(a) allocate the `struct` as a **global TLS variable**~~
      * ~~(b) perform the thread registration using the [RSEQ syscall](#RSEQ-syscall)~~
      This is handled automatically since glibc 2.35  (can be disabled using the [`glibc.pthread.rseq` tunable](https://www.gnu.org/software/libc/manual/html_node/POSIX-Thread-Tunables.html#index-glibc_002epthread_002erseq))

    &rarr; The scheduler will update the member fields once the registration has been complete

  * Usage:
    * A user space thread can &mldr;
      * obtain information (e.g., on which CPU it's running) by reading the `struct`
      * register / unregister a RSEQ *critical section* (*CS*) by writing to the `struct`
    * THINGS TO KEEP IN MIND when accessing the `struct` (after successful registration):
      * Should be done via a macro like: **`define RSEQ_ACCESS_ONCE(x) (*(__volatile__ __typeof__(x) *)&(x))`**.
        This is necessary as a compiler might optimize out memory reads pertaining `struct rseq` member fields  (the `struct` is updated externally by the kernel.
        This happens unbeknownst to the compiler, which might assume that the `struct` never changes, as it may never be written to by the user space thread.)
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

  * <span id="rseq_abi-struct_rseq-cpu_id">`cpu_id_start`/`cpu_id`</span>:
    * Both hold current CPU number on which the registered thread is running on
      * Range: <pre>0 &le; `cpu_id` &lt; # of CPUs</pre>
    * They essentially only differ with their init values:
      * `cpu_id_start` always holds a valid CPU number (even when `struct rseq` hasn't been registered yet)
      * `cpu_id` is initialized with `-1`
    * Use case:
      * Get CPU number on which the user space thread is running on (faster than `sched_getcpu`(3), even with vDSO)
      * Index (using the obtained CPU number) in per-CPU data structures
  * `node_id`:
    * Available on Linux 6.3+
    * Initialized with `0`
    * Holds (once inited) the current NUMA ID
    * Use case: Same as `cpu_id`, but on the NUMA domain level
  * <span id="rseq_abi-struct_rseq-mm_id">`mm_cid`:</span>
    * Available on Linux 6.3+
    * Abbreviation for *memory map concurrency id* (*cid*)
    * Holds unique, temporarily assigned value, which is allotted by the scheduler to each actively running thread within a process
      * Range: <pre>0 &le; `mm_cid` &lt; # of actively running threads &le; # of CPUs</pre>
    * Use case: Indexing in per-CPU data structures (`cpu_id` alternative)
      * Advantage (compared to `cpu_id`): The cid is closer to `0` (v.s., `cpu_id`), allowing for a more efficient (re-)use of memory when indexing in per-CPU data structures (e.g., in [memory allocators](#examples-memory_allocators-motivation))
        * The main beneficiaries of this new field are processes which have &mldr;
          * fewer threads than cores or which have
          * been restricted to run on fewer cores through scheduler affinity or cgroup cpusets
  * `rseq_cs`: Pointer to [data structure which **describes the CS** (a.k.a., the *CS descriptor*)](#struct-rseq_cs)
  * ~~`flags`~~ (deprecated as of Linux 6.1)

### RSEQ syscall
* Implementation in kernel source tree (as of 6.3): [`kernel/rseq.c`](https://github.com/torvalds/linux/blob/f7b01bb0b57f994a44ea6368536b59062b796381/kernel/rseq.c#L365)
* Registers / unregisters `struct rseq` for invoking thread
* Args of syscall:
  ```C
  SYSCALL_DEFINE4(rseq,             // Taken from Linux 6.3 source tree
                  struct rseq __user *, rseq,
                  u32, rseq_len,
                  int, flags,
                  u32, sig)
  ```
    * `rseq`: Address of allocated `struct rseq`
    * `rseq_len`: Length of structure
      * Tells kernel which `struct rseq` fields need to be updated (this ensures backward compatibility, as the user space program might still use an older definition of the `struct`, which doesn't include fields like `mm_cid`)
    * `flags`: `0` = perform the registration / `RSEQ_FLAG_UNREGISTER` = unregister already registered struct
    * `sig`: Used for thwarting binary exploitation attacks

  * NOTE: As of glibc 2.35, there's no glibc syscall wrapper  (there *shouldn't* be a need anyways, as registration is handled by glibc)
    * Can be invoked manually using the &mldr;
      * [`syscall` function](https://man7.org/linux/man-pages/man2/syscall.2.html) or &mldr;
      * inline asm

### `getauxval`(3)
* Implementation in kernel source tree (as of 6.3): [`fs/binfmt_elf.c`](https://github.com/torvalds/linux/blob/317c8194e6aeb8b3b573ad139fc2a0635856498e/fs/binfmt_elf.c#L292)
* Allows the user space program to detect which feature fields (in `struct rseq`) are supported by the kernel  (e.g., kernels &le; 6.3 don't support the `mm_cid`)
  ```C
  #include <sys/auxv.h>

  #define rseq_sizeof_field(TYPE, MEMBER) sizeof((((TYPE*)0)->MEMBER))
  #define rseq_offsetofend(TYPE, MEMBER) (offsetof(TYPE, MEMBER) + rseq_sizeof_field(TYPE, MEMBER))

  const unsigned long auxv_rseq_feature_size = getauxval(AT_RSEQ_FEATURE_SIZE);
  const bool mm_cid_is_supported = (int)auxv_rseq_feature_size >= (int)rseq_offsetofend(struct rseq, mm_cid);
  ```

### `struct rseq_cs`
* A.k.a., the *CS descriptor*
* Definition in kernel source tree (as of 6.3): [`include/uapi/linux/rseq.h`](https://github.com/torvalds/linux/blob/f7b01bb0b57f994a44ea6368536b59062b796381/include/uapi/linux/rseq.h#L45)
* Difference: *Critical section* v.s., *CS descriptor*:
  * ***Critical section***:
    * The CS itself **contains the operations** which shall be carried out to modify the per-CPU data structures
    * This CS is **guarded against interruptions** by RSEQ mechanism
      * An active CS may either be interrupted by
        * migration to another CPU,
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
      * Must be **written in [asm](#rseq-asm-basics)**.

        The generated machine instructions must faithfully follow the *program order* (as defined in the source).
        This is an issue in high-level languages, as reorders of stores might occur by the compiler (for optimization purposes).
        Such optimizations can change the program order by e.g., preponing the store associated with the commit phase into the preparatory phase.
      * Should **never invoke syscalls**
      * **No function calls**

        Doing so would move the Instruction Pointer (IP) outside the CS, making the detection (whether a CS was active) impossible.
      * Stack operations should be limited to reserved stack space  (e.g., local variables defined in the C code preceding the inline assembly block).

        Pushing elements also requires an attendant undo operation upon exit.
        However, undoing the operation with `pop` could result in stack memory corruption if the CS was interrupted prior to the `push` operation.
      * CS must be kept **brief**.

        A too long CS will be perpetually restarted as the time slice (allotted by the scheduler) is always expiring before the CS can finish.
      * CS **cannot be debugged**.

        Setting a breakpoint within the CS would later interrupt it, causing it to be restarted indefinitely.
        RSEQ CSs should therefore be declared in the dedicated ELF sections `__rseq_cs_ptr_array` and `__rseq_exit_point_array`.
        Debuggers like `gdb` can simply read these sections and skip all CS when single stepping.

  * ***CS descriptor***: `struct` **describing the *critical section***
    * This includes e.g., where the CS starts and ends  (see Ex. down below)

  * Example: Ring buffer (in C-like pseudocode for better intelligibility):
    * <span id="rseq-ex-cs">Critical section (this includes only the pseudocode after `start:`):</span>
      ![CS: Ring buffer offer example](_assets/rb-ex-cs.png)
    * Attendant descriptor of CS:
      ```C
      struct rseq_cs descriptor = {
        .version = 0,
        .flags = 0,
        .start_ip = &&start,                                                  // Points to first machine instruction in CS
        .post_commit_offset = (uintptr_t)&&post_commit - (uintptr_t)&&start,  // Length of CS in bytes
        .abort_ip = &&abort
      };
      ```

* Lifecycle / USAGE:
  * To 'start' a RSEQ, `struct rseq`'s `rseq_cs` is set to the CS descriptor
  * Scheduler check:
    ![RSEQ: (Simplified) scheduler check](_assets/rseq-simplified_restart_check.png)
    * Note that the diagram has been simplified (the [`RSEQ_SIG` security check](https://github.com/torvalds/linux/blob/f7b01bb0b57f994a44ea6368536b59062b796381/kernel/rseq.c#L194) e.g., has been omitted)
    * When scheduling a thread, the Linux scheduler will check whether
      * (1.) a [CS descriptor has been set in the `rseq_cs` field of `struct rseq`](https://github.com/torvalds/linux/blob/f7b01bb0b57f994a44ea6368536b59062b796381/kernel/rseq.c#L281). If this is the case, the kernel will check whether
      * (2.) the saved IP address is [falling in the range `start_ip` &le; IP address &lt; `start_ip` + `post_commit_offset`](https://github.com/torvalds/linux/blob/f7b01bb0b57f994a44ea6368536b59062b796381/kernel/rseq.c#L271)
    * The RSEQ CS must be restarted if this condition also holds true.
      This is automatically handled by the kernel by [setting the IP to `abort_ip`](https://github.com/torvalds/linux/blob/f7b01bb0b57f994a44ea6368536b59062b796381/kernel/rseq.c#L300), which is the address of the first instruction in the abort handler.


## RSEQ asm basics
* As already mentioned, CSs are typically implemented using inline assembly.
* Note that the C language doesn't have a standardized syntax for including assembler in C source files.
  Its inclusion in the compiler is considered an extension to the C language.

* The *[gcc extended asm syntax](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html)* (which will be used in this example) is best suitable for mixing C and assembly (as it supports input- and output operands in the form of C variables and jumps to C labels):
  ```C
  asm asm-qualifiers ( AssemblerTemplate
                        : OutputOperands
                        : InputOperands
                        : Clobbers
                        : GotoLabels)
  ```

  * Relevant `asm-qualifiers` for RSEQ CSs are `volatile` and `goto`:
    * `volatile` is required for asm statements which don't use output operands and instead produce the desired result by performing side effects.
      E.g., the CS of the `offer`ing operation takes a reference to the rb as input operand.
      It then writes the new item into its buffer and updates the head.
      Hence, the memory referenced by the input operand is manipulated to produce the desired result.
      The gcc optimizer may discard the asm statement, which is prevented by this keyword.
      It also prevents reordering of statements by the compiler.
    * `goto` allows the asm statement to perform a jump to any C label in the `GotoLabels` list.
      The CS `offer`ing operation may use such a jump to block in case the rb is full and return an appropriate error code to the caller.

  * `AssemblerTemplate` contains the actual assembly instructions and assembler directives as a string literal.
     It's a template which may contain tokens.
     These tokens refer to e.g., operands and goto labels and need to be replaced by the compiler.
     Once replaced, it's passed to the assembler, which produces the machine code.
     Gcc supports both Intel- and AT&T x86 assembler dialects with the latter being the default.

    * Writing asm:
      * Assembler directives are prefixed with a dot (`.`, e.g., `.popsection`)

      * *Local label*s:
        * Declaration: `<int>:`, e.g., `1:`
        * Referencing it &mldr;
          * after its 'declaration line' requires `b` (“backwards”) as suffix, e.g., `1b`
          * before its 'declaration line' requires `f` (“forwards”) as suffix, e.g., `1f`

      * The AT&T syntax has these relevant traits:
        * Immediate operands are prefixed with `$`, whereas registers are prefixed with `%`
        * Instruction mnemonics follow the order `source, destination`. This only pertains to mnemonics with two operands.
        * Instruction mnemonics are typically suffixed with a character indicating the size of the operands. Common suffixes are
          * `b` for byte (8 bit),
          * `w` for word (16 bit),
          * `l` for long (32 bit) and
          * `q` for quadruple word (64 bit).

  * `InputOperands` are passed as follows:
    ```C
    [ [asmSymbolicName] ] constraint (cexpression)
    ```
    * This allows passing a `cexpression` (which may be a C variable or expression) to the `AssemblerTemplate`, which then can be referenced via the symbolic name `asmSymbolicName`
    * Multiple operands are separated using a comma
    * `constraint` specifies where the parameter should be placed by gcc. Common constraints are
      * `m` for *memory*,
      * `r` for a *general-purpose register* and
      * `i` for *immediate integer operands* whose value is known during assembly time.

  * `Clobbers` lists all locations, such as used scratch registers, which are modified by the assembly.
     This causes the compiler to exempt the listed locations when e.g., choosing registers for the `InputOperands`.
     The `flags` register is listed using the special clobber `cc`.
     In case memory is read and written by the assembly, the special clobber `memory` must be used (which effectively forms a memory barrier for the compiler).

  * `GotoLabels` lists all C labels to which the assembly might jump to (this requires the previously mentioned `goto` qualifier).


## Librseq
* [Available on GitHub](https://github.com/compudj/librseq)
* Library which makes it easier to integrate RSEQs into applications by providing:
  * [Header containing the latest RSEQ ABI definitions](https://github.com/compudj/librseq/blob/8dd73cf99b9bd3dbbbbe7268088ffd3e66b2e50a/include/rseq/rseq.h)

  * Functions like &mldr;
    * `rseq_register_current_thread`, `rseq_unregister_current_thread`, `rseq_clear_rseq_cs`, `rseq_prepare_unload` for handling the RSEQ lifecycle
    * `rseq_available`, `rseq_mm_cid_available`, `rseq_node_id_available`, etc., for checking which `struct rseq` fields are supported
    * `rseq_current_cpu_raw`, `rseq_cpu_start`, `rseq_current_mm_cid`, `rseq_current_node_id` for reading `struct rseq` fields

  * **Prewritten CSs** which are supported on many ISAs (thus eliminating portability issues)
    * For instance, [`rseq_cmpeqv_trymemcpy_storev(intptr_t * v, intptr_t expect, void * dst, void * src, size_t len, intptr_t newv, int cpu)`](https://github.com/compudj/librseq/blob/8dd73cf99b9bd3dbbbbe7268088ffd3e66b2e50a/include/rseq/rseq.h#L400) may be used to implement a rb, where e.g., the producer would pass
      * a pointer to the `head` as `v`,
      * the previously read value of `head` as `expect`,
      * the next index in the buffer as `dst`,
      * a pointer to the item pointer as `src`,
      * the size of the pointer as `len` and
      * the next `head` value as `newv`.

  * **Macros `RSEQ_ASM_*`** for writing own CSs (which eliminate boilerplate code):
    * [`RSEQ_ASM_DEFINE_TABLE(<cs_label>, <start_ip>f, <post_commit_ip>f, <abort_ip>f)`](https://github.com/compudj/librseq/blob/809f5ee3a5f5852e532ee4e406d5e700652b9ab3/include/rseq/rseq-x86.h#L71):
      ```C
      // Expands to asm directives which emit the CS descriptor (`struct rseq_cs`)
      // for the ensuing CS + debugging information:
      ".pushsection __rseq_cs, \"aw\"\n\t"
      ".balign 32\n\t"
      "<cs_label>:\n\t"                                                        // Local label for referencing this CS descriptor
      ".long 0x0, 0x0\n\t"                                                     // `version`, `flags`
      ".quad <start_ip>f, (<post_commit_ip>f - <start_ip>f), <abort_ip>f\n\t"  // `start_ip`, `post_commit_ip`, `abort_ip`
      ".popsection\n\t"
      ".pushsection __rseq_cs_ptr_array, \"aw\"\n\t"                           // Debugging information
      ".quad 3b\n\t"
      ".popsection\n\t"
      ```
    * [`RSEQ_ASM_DEFINE_EXIT_POINT(<start_ip>f, %l[<c_label_exit_point>])`](https://github.com/compudj/librseq/blob/809f5ee3a5f5852e532ee4e406d5e700652b9ab3/include/rseq/rseq-x86.h#L83):
      ```C
      // (Optional) Expands to asm directives which emit debugging information
      // (may be used by e.g., `gdb`) of RSEQ CS exit points in an ELF section:
      ".pushsection __rseq_exit_point_array, \"aw\"\n\t"
      ".quad <start_ip>f, %l[<c_label_exit_point>]\n\t"
      ".popsection\n\t"
      ```
    * [`RSEQ_ASM_STORE_RSEQ_CS(<start_ip>, <cs_label>b, <struct_rseq_cs_ptr>)`](https://github.com/compudj/librseq/blob/809f5ee3a5f5852e532ee4e406d5e700652b9ab3/include/rseq/rseq-x86.h#L88):
      ```C
      // Expands to ASM which 'registers' the CS by setting `rseq_cs`
      // in `struct rseq` to point to the defined CS descriptor:
      "leaq <cs_label>b(%%rip), %%rax\n\t"                                     // (Uses RIP-relative addressing due to ASLR)
      "movq %%rax, <struct_rseq_cs_ptr>\n\t"
      "<start_ip>:\n\t"
      ```
    * [`RSEQ_ASM_CMP_CPU_ID(<cpu_input_operand>, <struct_rseq_hw_thread>, <abort_ip>f)`](https://github.com/compudj/librseq/blob/809f5ee3a5f5852e532ee4e406d5e700652b9ab3/include/rseq/rseq-x86.h#L94):
      ```C
      // Expands to asm which checks and aborts when the current `cpu_id` / `mm_cid`
      // doesn't match `cpu` (only necessary when indexing into the per-CPU data
      // structure OUTSIDE of the CS):
      "cmpl %[<cpu_input_operand>], <struct_rseq_hw_thread>\n\t"
      "jnz <abort_ip>f\n\t"
      ```
    * [`RSEQ_ASM_DEFINE_ABORT(<abort_ip>, <teardown>, <c_label_abort>)`](https://github.com/compudj/librseq/blob/809f5ee3a5f5852e532ee4e406d5e700652b9ab3/include/rseq/rseq-x86.h#L99):
      ```C
      // Expands to asm + asm directives for emitting the abort handler
      // "signature" + instructions into an eXecutable ELF section
      ".pushsection __rseq_failure, \"ax\"\n\t"
      ".byte 0x0f, 0xb9, 0x3d\n\t"                                             // (Documented undefined instruction (UD1) for trapping speculative execution)
      ".long 0x53053053\n\t"                                                   // `RSEQ_SIG` (used to thwart binary exploitation attacks)
      "<abort_ip>:\n\t"                                                        // Local label required for defining `abort_ip` in CS descriptor
      teardown                                                                 // Additional optional asm for teardown
      "jmp %l[<c_label_abort>]\n\t"                                            // `c_label_abort` = C label to jump to
      ".popsection\n\t"
      ```


## Examples
### Per-CPU Multi-Producer, Single-Consumer (MPSC) ring buffer
* The rb is defined as a global data structure which is allocated during program startup:
  ```C
  struct rb* rb_baseptr;                                            // Global var

  int main(void) {
    rb_baseptr = malloc( get_ncpus() * sizeof(*rb_baseptr) );       // Alloc global structure during startup
    // …
  }
  ```
  ![Ring buffer data structure on quad core system](_assets/rb-ex-data_structure.png)

* Operations:
  * NOTE: This implementation uses a [power-of-2 size](https://www.kernel.org/doc/html/latest/core-api/circular-buffers.html#measuring-power-of-2-buffers)
  * `rb_poll`:
    * No need for a RSEQ CS, as there's only one consumer (Single-Producer implementation)

  * `rb_offer`:
    * Has to be guarded via a RSEQ CS, as there are multiple producers (Multi-Producer implementation)
    * Pseudocode for better intelligibility:
      ```C
      int rb_offer(void* item) {                                        // Arg `item_ptr` = Item to be added
        // -  Index into per-CPU data structure
        const unsigned int cpu = rseq.mm_cid;                           // Read current HW thread from `struct rseq`
        struct rb* rb_ptr = (rb_baseptr + sizeof(*rb_baseptr) * cpu);   // Get rb for the CPU on which this thread is currently executing on

        // -  Register CS by setting the CS descriptor in `struct rseq`
        rseq.rseq_cs = &descriptor;

        // -  BEGIN CS  -
      start:                                                            // Begin of CS
        // Check whether the current 'HW thread' still matches the previously used `cpu` (which was used for indexing)
        if (rseq.mm_cid != cpu) goto abort;

        // - Prepare
        // Check whether there's ample space available
        if ((rb.tail & (RB_CAPACITY_BYTES -1)) == (rb.head & (RB_CAPACITY_BYTES -1))  &&  (rb.head > rb.tail)) {
          return -1;                                                    // `block`
        }
        // Copy item into rb
        const int idx = (rb_ptr->head & (RB_CAP_BYTES -1)) / sizeof(rb_ptr->buf[0]);
        rb_ptr->buf[idx] = item;

        // - Commit  (by writing new head, which makes copied item visible to consumers)
        rb_ptr->head += sizeof(rb_ptr->buf[0]);
      post_commit:                                                      // End of CS
        // -  END CS  -

        return 0;
        // -  ABORT HANDLER  -
      abort:
        return 1;
      }
      ```
    * The actual implementation (which leverages librseq) can be found [here](examples/mpsc_rb_demo.c)


### Memory allocators
#### <span id="examples-memory_allocators-motivation">Motivation</span>
##### *Thread-level caches* (*tcaches*)
* Modern memory allocators (e.g., Google's *tcmalloc* (*Thread-Caching Malloc*)) (used to) use ***tcaches* for optimizing performance on multi-core systems**
* PRO: Reduced lock contention.

  Each thread can obtain 'cached' memory for allocations from an own thread-local heap (instead of a single global heap).
  The threads thus don't have to contend for the global lock when allocating / deallocating memory.
* CON: Memory may be "tied up" in tcaches.
  * Consequence: Inefficient use of memory (a.k.a., *heap blowup*)
  * This issue mostly arises with programs that use a high number of threads which exceeds the number of CPUs available on the system.
    This applies e.g., to server SW, where performance is hampered most by I/O.
    Some threads will therefore run concurrently, i.e., interleaved, rather than in parallel.
    A subset of the threads will be idling in the ready- or waiting state as a consequence.
    The memory cached in the tcache of an idling thread therefore isn't being used.
    Also, running threads which need to allocate memory cannot use the already available free memory as it's tied up in the tcaches of idling threads.
    This forces running threads to request additional memory from the OS, thereby needlessly increasing the memory footprint of the program.
  * One remedy to this issue are so called ***CPU-level caches* (*ccaches*)**

##### *CPU-level caches* (*ccaches*)
* Heap memory caches are maintained on the CPU-, rather than the thread level
  * The heaps (for each thread) are now allocated as part of a global per-CPU data structure which is modified using RSEQ CSs
* PRO: **Reduced memory footprint** as threads can now always allocate memory from the ccache corresponding to the CPU on which they're currently running on.

* A thread can access its corresponding heap by indexing via [`cpu_id`](#rseq_abi-struct_rseq-cpu_id) or [`mm_cid`](#rseq_abi-struct_rseq-mm_id) into the global data structure
  * `cpu_id` has pathological usage patterns though which can also lead to heap blowup:
    ![Memory allocators: cpu_id v.s., mm_cid](_assets/rseq-mem_alloc-cpu_id-vs-mm_cid.png)

    When indexing with `cpu_id`, the single thread will fill and deplete the ccache of every CPU it's scheduled on.
    The thread might run on a CPU whose ccache is currently empty when it tries to allocate memory.
    A ccache of a different CPU however might be full.
    Memory is therefore available, but cannot be accessed by the thread.
    This forces the thread to request additional memory from the OS, resulting in heap blowup (again).
    Indexing with `mm_cid` avoids this issue.

#### Prototypes
* [Both](examples/memory_allocators) rpmalloc and jemalloc have been adapted to support ccaches  (indexable with `cpu_id` and `mm_cid`)
* Rpmalloc e.g., supports both a *Level 1 cache* (which can be either a tcache or a ccache) and an optional *Level 2 cache* (global)
    * L1 tcache:
      ![L1 tcache](_assets/rpmalloc-tcache.png)
    * L1 ccache:
      ![L1 tcache](_assets/rpmalloc-ccache.png)
