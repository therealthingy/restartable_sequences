# Restartable Sequences (RSEQs)

## Motivation
The potential use cases of RSEQs in user space are:
  * Efficiently **retrieving the CPU** on which the thread is currently running on, e.g., for indexing in per-CPU data structures
  * **Modifying per-CPU data structures** which are protected by spinlocks

The following paragraphs focus on the latter use case (which relies on the first use case).


### Per-CPU data structures
* **Access** to shared data must be **synchronized** to **avoid *race conditions*** in case the data is modified concurrently by multiple threads
* This problem can be solved by protecting the *critical section* (*CS*) (where the shared data is modified) via a *synchronization primitive* (e.g., a mutex lock or a semaphore)
* Introducing synchronization in a highly parallel application can however result in **high contention** (= many threads block and try to acquire the lock which deteriorates performance)
* A popular approach of **reducing contention** is the use of **per-CPU data structures**

* Example (of a per-CPU data structure): **Multi-Producer, Single-Consumer (MPSC) ring buffer** implementation
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

### Synchronization when working w/ per-CPU data structures
* This data structure is "inherently" (as each SW thread running on a HW thread has its own data structure) *thread safe* with respect to parallel access
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

  * Disabling preemption altogether while manipulating per-CPU data structures
    * This ability is limited to kernel space

  * RSEQs (developed by Paul Turner and Andrew Hunter at Google and Mathieu Desnoyers at EfficiOS)
    * Idea: ***Detect preemption** (with the help of the OS scheduler) and if necessary, restart the preempted operation
    * *RSEQ* = the implementation of aforesaid concept in the Linux kernel
    * This mechanism has been part of the Linux kernel since version 4.18


## RSEQ ABI
* The relevant definitions can be found in the header file:
  * `linux/rseq.h`, provided by [`linux-libc-dev`](https://packages.debian.org/de/sid/linux-libc-dev)  (may include outdated definitions)
  * `rseq/rseq.h`, provided by [librseq](https://github.com/compudj/librseq/blob/8dd73cf99b9bd3dbbbbe7268088ffd3e66b2e50a/include/rseq/rseq.h)

### [`struct rseq`](https://github.com/torvalds/linux/blob/f7b01bb0b57f994a44ea6368536b59062b796381/include/uapi/linux/rseq.h#L62)
* Serves as **kernel- &harr; user space interface** which is used to manage RSEQs in each thread individually
* "Lifecycle":
  * Setup:
    * ~~It's the responsibility of each user space thread (which wants to use RSEQs) to:~~
      * ~~(a) allocate the `struct` as a **global TLS variable**~~
      * ~~(b) perform the thread registration using the [RSEQ syscall](#RSEQ-syscall)~~
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
      * Must be **written in [asm](#rseq-asm-basics)**
        The generated machine instructions must faithfully follow the *program order* (as defined in the source).
        This is an issue in high-level languages, as reorders of stores might occur by the compiler (for optimization purposes).
        Such optimizations can change the program order by e.g., preponing the store associated with the commit phase into the preparatory phase.
      * Should **never invoke syscalls**
      * **No function calls**
        Doing so would move the IP (Instruction Pointer) outside the CS, making the detection (whether a CS was active) impossible.
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
    * This includes e.g., where the CS starts and ends  (see Ex. down below)

  * Example: MPSC ring buffer (in C-like pseudocode for better intelligibility):
    * <span id="rseq-ex-cs">Critical section (this includes only the pseudocode after `start:`):</span>
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
  This necessitates a basic understanding of gcc's inline asm syntax.

* Note that the C language doesn't have a standardized syntax for including assembler in C source files.
  Its inclusion in the compiler is considered an extension to the C language.

* The *gcc extended asm syntax* (which will be used in this example) is best suitable for mixing C and assembly (as it supports input- and output operands in the form of C variables and jumps to C labels):
  ```C
  asm asm-qualifiers ( AssemblerTemplate
                        : OutputOperands
                        : InputOperands
                        : Clobbers
                        : GotoLabels)
  ```

  * Relevant `asm-qualifiers` for RSEQ CSs are `volatile` and `goto`:
    * `volatile` is required for asm statements which don't use output operands and instead produce the desired result by performing side effects.
      E.g., the CS of the `offer`ing operation takes a reference to the ring buffer as input operand.
      It then writes the new item into its buffer and updates the head.
      Hence, the memory referenced by the input operand is manipulated to produce the desired result.
      The gcc optimizer may discard the asm statement, which is prevented by this keyword.
      It also prevents reordering of statements by the compiler.
    * `goto` allows the asm statement to perform a jump to any C label in the `GotoLabels` list.
      The CS `offer`ing operation may use such a jump to block in case the ring buffer is full and return an appropriate error code to the caller.

  * `AssemblerTemplate` contains the actual assembly instructions and assembler directives as a string literal.
     It's a template which may contain tokens. These tokens refer to e.g., operands and goto labels and need to be replaced by the compiler.
     Once replaced, it's passed to the assembler, i.e., [g]as (GNU Assembler), which produces the machine code.
     Gcc supports both Intel- and [AT&T](#at&t-syntax) x86 assembler dialects with the latter being the default.

  * `InputOperands` are separated using a comma:
    ```C
    [ [asmSymbolicName] ] constraint (cexpression)
    ```
    * This allows passing a `cexpression` to the `AssemblerTemplate`, which then can be referenced via the symbolic name `asmSymbolicName`.
      * A `cexpression` may be a C variable or expression.
    * `constraint` specifies where the parameter should be placed by gcc. Common constraints are
      * `m` for *memory*,
      * `r` for a *general-purpose register* and
      * `i` for *immediate integer operands* whose value is known during assembly time.
    * `Clobbers` lists all locations, such as used scratch registers, which are modified by the assembly.
       This causes the compiler to exempt the listed locations when e.g., choosing registers for the `InputOperands`.
       The `flags` register is listed using the special clobber `cc`.
       In case memory is read and written by the assembly, the special clobber memory must be used, which effectively forms a memory barrier for the compiler.
       More specifically, “cached” memory writes in registers must be flushed to memory by the compiler before the asm statement.
       This ensures that memory has the latest values.
       Loads of clobbered memory locations after the asm statement require a reload by the compiler, as they might have been changed.
    * `GotoLabels` lists all C labels to which the assembly might jump to. This however requires the `goto` qualifier.

* Assembler directives are prefixed with a dot (`.`, e.g., `.popsection`)

* *Local label*s:
  * Declaration: `<int>:`, e.g., `1:`
  * Referencing it &mldr;
    * after its declaration line requires `b` (“backwards”) as suffix, e.g., `1b`
    * before its declaration line requires `f` (“forwards”) as suffix, e.g., `1f`

* The [examples](TODO) will use the AT&T syntax (in the `AssemblerTemplate`), which has these relevant traits:
  * Immediate operands are prefixed with `$`, whereas registers are prefixed with `%`
  * Instruction mnemonics follow the order `source, destination`. This only pertains to mnemonics with two operands.
  * Instruction mnemonics are typically suffixed with a character indicating the size of the operands. Common suffixes are
    * `b` for byte (8 bit),
    * `w` for word (16 bit),
    * `l` for long (32 bit) and
    * `q` for quadruple word (64 bit).


## [Librseq](https://github.com/compudj/librseq) library
* Makes it easier to integrate RSEQs into applications by offering:
  * [header file containing the latest RSEQ ABI definitions](https://github.com/compudj/librseq/blob/8dd73cf99b9bd3dbbbbe7268088ffd3e66b2e50a/include/rseq/rseq.h)
  * functions like
    * `rseq_register_current_thread`, `rseq_unregister_current_thread`, `rseq_clear_rseq_cs`, `rseq_prepare_unload` for handling the RSEQ lifecycle
    * `rseq_available`, `rseq_mm_cid_available`, `rseq_node_id_available`, &mldr; for checking which `struct rseq` fields are supported
    * `rseq_current_cpu_raw`, `rseq_cpu_start`, `rseq_current_mm_cid`, `rseq_current_node_id` for reading `struct rseq` fields
  * **prewritten CSs** which are supported on many ISAs (thus eliminating portability issues)
    * E.g., [`rseq_cmpeqv_trymemcpy_storev(intptr_t * v, intptr_t expect, void * dst, void * src, size_t len, intptr_t newv, int cpu)`](https://github.com/compudj/librseq/blob/8dd73cf99b9bd3dbbbbe7268088ffd3e66b2e50a/include/rseq/rseq.h#L400) may be used to implement a MPSC rb, where the producer would pass a pointer to the `head` as `v`, the previously read value of `head` as `expect`, the next index in the buffer as `dst`, a pointer to the item pointer as `src`, the size of the pointer as `len` and the next `head` value as `newv`.
  * macros `RSEQ_ASM_*` for writing own CSs (thus eliminating boilerplate code):
    * `RSEQ_ASM_DEFINE_TABLE(<cs_label>, <start_ip>f, <post_commit_ip>f, <abort_ip>f)`:
      ```C
      // Expands to ASM DIRECTIVES which emit the CS descriptor (`struct rseq_cs`) for the ensuing CS + debugging information:
      ".pushsection __rseq_cs, \"aw\"\n\t"
      ".balign 32\n\t"
      "<cs_label>:\n\t"                                                         // Local label which will be used for referencing this CS descriptor
      ".long 0x0, 0x0\n\t"                                                      // `version`, `flags`
      ".quad <start_ip>f, (<post_commit_ip>f - <start_ip>f), <abort_ip>f\n\t"   // `start_ip`, `post_commit_ip`, `abort_ip`
      ".popsection\n\t"
      ".pushsection __rseq_cs_ptr_array, \"aw\"\n\t"                            // Debugging information
      ".quad 3b\n\t"
      ".popsection\n\t"
      ```
    * `RSEQ_ASM_DEFINE_EXIT_POINT(<start_ip>f, %l[<c_label_exit_point>])`
      ```C
      // (Optional) Expands to ASM DIRECTIVES which emit debugging information (may be used by e.g., `gdb`) of RSEQ CS exit points in an ELF section
      ".pushsection __rseq_exit_point_array, \"aw\"\n\t"
      ".quad <start_ip>f, %l[<c_label_exit_point>]\n\t"
      ".popsection\n\t"
      ```
    * `RSEQ_ASM_STORE_RSEQ_CS(<start_ip>, <cs_label>b, <struct_rseq_cs_ptr>)`
      ```C
      // Expands to ASM which 'registers' the CS by setting `rseq_cs` in `struct rseq` to point to the defined CS descriptor
      "leaq <cs_label>b(%%rip), %%rax\n\t"                                      // (Uses RIP-relative addressing due to ASLR)
      "movq %%rax, <struct_rseq_cs_ptr>\n\t"
      "<start_ip>:\n\t"
      ```
    * `RSEQ_ASM_CMP_CPU_ID(<cpu_input_operand>, <struct_rseq_hw_thread>, <abort_ip>f)`
      ```C
      // Expands to ASM which checks and aborts when the current 'HW thread' doesn't match the 'HW thread' `cpu`
      // Only necessary when indexing into the per-CPU data structure OUTSIDE of the CS
      "cmpl %[<cpu_input_operand>], <struct_rseq_hw_thread>\n\t"
      "jnz <abort_ip>f\n\t"
      ```
    * `RSEQ_ASM_DEFINE_ABORT(<abort_ip>, <teardown>, <c_label_abort>)`
      ```C
      ".pushsection __rseq_failure, \"ax\"\n\t"
      ".byte 0x0f, 0xb9, 0x3d\n\t"                                              // (Documented undefined instruction UD1 which shall trap speculative execution)
      ".long 0x53053053\n\t"                                                    // RSEQ_SIG (used to thwart binary exploitation attacks)
      "<abort_ip>:\n\t"
      "jmp %l[<c_label_abort>]\n\t"
      ".popsection\n\t"
      ```


## Examples
### Per-CPU MPSC ring buffer
* The source can be found [here](examples/mpsc_rb_demo.c)

* The rb is defined as a global data structure which is allocated during program startup:
  ```C
  struct rb* rb_baseptr;                                            // Global var

  int main(void) {
    rb_baseptr = malloc( get_ncpus() * sizeof(*rb_baseptr) );       // Alloc global structure during startup
    // …
  }
  ```

* Operations:
  * `rb_poll`:
    * No need for a RSEQ CS, as there's only one consumer (Single-Producer implementation)
    * (The implementation can be found here  TODO)

  * `rb_offer`:
    * Has to be guarded via a RSEQ CS, as there are multiple producers (Multi-Producer implementation)
    * Pseudocode for better intelligibility (as [already shown above](#rseq-ex-cs)):
      ```C
      int rb_offer(void* item) {                                        // Arg `item_ptr` = Item to be added
        // -  Index into per-CPU data structure
        const unsigned int cpu = rseq.mm_cid;                           // Read current HW thread from `struct rseq`
        struct rb* rb_ptr = (rb_baseptr + sizeof(*rb_baseptr) * cpu);   // Get rb for the HW thread on which this SW thread is currently executing on

        // -  Register CS by setting the CS descriptor in `struct rseq`
        rseq.rseq_cs = &descriptor;

        // -  BEGIN CS  -
      start:                                                            // Begin of CS
        // Check whether the current 'HW thread' still matches the previously used `cpu` (which was used for indexing)
        if (rseq.mm_cid != cpu) goto abort;

        // - Prepare
        if (0 == free_slots(rb.head, rb.tail, rb.capacity))             // Check whether ample space is available
          return -1;

        rb.buf[rb.head % rb.capacity] = item;                           // Copy item into rb

        // - Commit  (by writing new head, which makes copied item visible to consumers)
        rb.head += sizeof(item);
      post_commit:                                                      // End of CS
        // -  END CS  -

        return 0;
        // -  ABORT HANDLER  -
      abort:
        return 1;
      }
    ```


### Memory allocators
* These prototypes **utilize RSEQs** to **implement *CPU caches*** (*ccaches*)
* CPU caches have
  * The ccaches serve as a substitute for *thread caches* (*tcaches*)
* `free`d memory is moved to the ccache corresponding to the CPU on which , where e

