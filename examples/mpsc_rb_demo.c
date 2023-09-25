/*
 * Very simple MPSC ring-buffer (rb) demo built using RSEQs
 *   Works atm only on amd64
 */
#include <stdio.h>
#include <stdlib.h>

#include <rseq/rseq.h>      // We use librseq for setting up RSEQs & reducing boilerplate code

#include <common.h>         // Error handling macros, etc.


// --  Data structures  --
#define RB_CAPACITY_ITEMS (1 << 2)
struct rb {
    unsigned long head,
                  tail;
    void* buf[RB_CAPACITY_ITEMS];
};
#define RB_CAPACITY_BYTES  sizeof(((struct rb*)0)->buf)
_Static_assert( RB_CAPACITY_BYTES && ( (RB_CAPACITY_BYTES & -RB_CAPACITY_BYTES) == RB_CAPACITY_BYTES), "Not a power of 2" );


// --  Globals  --
struct rb* g_rb_baseptr;


// --  Operations  --
static inline int rb_offer(void* const item_ptr,
                           const unsigned int cpu) {
    struct rb* const rb_ptr = (struct rb*)((uintptr_t)g_rb_baseptr + sizeof(*g_rb_baseptr) * cpu);  // Get rb for the HW thread on which this SW thread is currently executing on

    __asm__ __volatile__ goto (
        // (Librseq macro producing) ASM DIRECTIVES which emit the CS descriptor for the ensuing CS in an ELF section
        RSEQ_ASM_DEFINE_TABLE(3,                            /* Local label `cs_label` -> Used for referencing this CS descriptor */
                              1f, 2f,                       /* 'Forward references' defining the field `start_ip` (= start of CS = `1f`) and `post_commit_ip` (= length of CS = `2f` - `1f`) */
                              4f)                           /* 'Forward reference' defining `abort_ip` (= start address of abort handler) */
        // (Optional; Librseq macro producing) ASM DIRECTIVES which emit debugging information (may be used by e.g., `gdb`) in an ELF section
        RSEQ_ASM_DEFINE_EXIT_POINT(1f,                      /* `start_ip` */
                                   %l[block])               /* exit_ip */

        // (Librseq macro producing) ASM which registers the CS by setting `rseq_cs` in `struct rseq` to point to the defined CS descriptor  (!!  clobbers rax  !!)
        RSEQ_ASM_STORE_RSEQ_CS(1,                           /* Local label defining the start of the CS (= `start_ip`) */
                               3b,                          /* 'Backward reference' to CS descriptor (`cs_label`) */
                               RSEQ_ASM_TP_SEGMENT:RSEQ_CS_OFFSET(%[rseq_offset]))  /* Field `rseq_cs` in `struct rseq` */

        // (Librseq macro producing) ASM which checks and aborts when the current 'HW thread' doesn't match the 'HW thread' `cpu`
        RSEQ_ASM_CMP_CPU_ID(cpu_id,                         /* `cpu` function arg */
                            RSEQ_ASM_TP_SEGMENT:RSEQ_MM_CID_OFFSET(%[rseq_offset]),  /* `mm_cid` in `struct rseq` (contains current 'HW thread') */
                            4f)                             /* Forward reference to abort handler (`abort_ip`) which will be invoked if no match */

        // -  BEGIN ACTUAL CS  -
        // - Prepare  (copy item)
        // Check whether ample space is available
        "movq   %c[rb_off_tail](%[rb_ptr]),  %%rax\n\t"
        "and    $%c[rb_cap_mask],            %%rax\n\t"     // ( rax = mod reduced tail )
        "movq   %c[rb_off_head](%[rb_ptr]),  %%rbx\n\t"
        "and    $%c[rb_cap_mask],            %%rbx\n\t"     // ( rbx = mod reduced head )
        "cmpq   %%rax,                       %%rbx\n\t"     // Check whether head & tail DON'T "overlap" (i.e., rb isn't full) …
        "movq   %c[rb_off_head](%[rb_ptr]),  %%rax\n\t"     // ( rax = CURRENT head )
        "jne    11f\n\t"                                    // IN CASE they don't overlap: proceed w/ copying
        "cmpq   %c[rb_off_tail](%[rb_ptr]),  %%rax\n\t"     // OTHERWISE: Check whether head & tail "overlap" due to producer lapping the consumer  (required, otherwise head = tail = 0 would indicate a full rb) …
        "jg     %l[block]\n\t"
        "11:\n\t"

        // Copy item's pointer into rb
        "addq   %[rb_ptr],                   %%rbx\n\t"
        "addq   $%c[rb_off_buf],             %%rbx\n\t"     // ( rbx = write offset )
        "movq   %[item_ptr],                 (%%rbx)\n\t"

        "addq   $%c[item_ptr_size],          %%rax\n\t"     // ( rax = NEXT head )
        // - Commit  (by writing new head, which makes copied item visible 2 consumers)
        "movq    %%rax,                      %c[rb_off_head](%[rb_ptr])\n\t"
        "2:\n\t"                                            // Local label indicating end of CS (used for defining CS descriptor)

        // (Librseq macro producing) ASM directives for emitting the abort handler "signature" + actual ASM for the abort handler into an eXecutable ELF section
        RSEQ_ASM_DEFINE_ABORT(4,                            /* Local label referring to start of abort handler (required for defining `abort_ip` in CS descriptor) */
                              "",                           /* Additional (optional) asm for teardown */
                              abort)                        /* C label to jump to */

        :
        : [cpu_id]         "r"   (cpu),
          [rseq_offset]    "r"   (rseq_offset),
          [item_ptr]       "r"   (item_ptr),
          [item_ptr_size]  "i"   (sizeof(item_ptr)),
          [rb_ptr]         "r"   (rb_ptr),
          [rb_off_head]    "i"   (offsetof(struct rb, head)),
          [rb_off_tail]    "i"   (offsetof(struct rb, tail)),
          [rb_off_buf]     "i"   (offsetof(struct rb, buf)),
          [rb_cap_mask]    "i"   (RB_CAPACITY_BYTES -1)
        : "memory", "cc", "rax", "rbx"
        : block, abort
    );

    return 0;
abort:
    rseq_after_asm_goto();      // Workaround  provided by librseq) for asm goto miscompilation issues on older compilers
    return 1;
block:
    rseq_after_asm_goto();
    return -1;
}


/* This is a MPSC rb implementation
 *   -> The consumer (which uses `rb_poll`) thus doesn't need to be protected
 *      against preemption using RSEQ (as there's only 1 consumer anyways)
 *   -> RSEQ would be necessity though in a MPMC implementation
 */
int rb_poll(void** const item_ptr,
               const unsigned int cpu) {
    struct rb* const rb_ptr = (struct rb*)((uintptr_t)g_rb_baseptr + sizeof(*g_rb_baseptr) * cpu);

    if (rb_ptr->head > rb_ptr->tail) {
        const int idx = (rb_ptr->tail & (RB_CAPACITY_BYTES - 1)) / sizeof(rb_ptr->buf[0]);
        *item_ptr = rb_ptr->buf[idx];
        rb_ptr->tail += sizeof(rb_ptr->buf[0]);
        if (0) {
            return 1;   // WOULD indicate failed RSEQ
        }
        return 0;       // Success
    }
    return -1;          // block
}




// --------------------- ---------------------  TEST DRIVER  --------------------- ---------------------
int main(void) {
// setup
    g_rb_baseptr = DIE_WHEN_ERRNO_VPTR( malloc(DIE_WHEN_ERR( system_get_ncpus(0) ) * sizeof(*g_rb_baseptr)) );
    DIE_WHEN_ERR( rseq_register_current_thread() );


// --  UNIT TESTs  --
#define TEST_ASSERT(TRUTH, MSG_FMT, ...) do { \
    if (! (TRUTH) ) { \
        fprintf(stderr, "ASSERT FAILED @ " __FILE__ ":" STRINGIFY(__LINE__) ": " MSG_FMT "\n", ##__VA_ARGS__); \
        abort(); \
    } \
 } while(0)

    struct rb_item {
        unsigned int val;
    };

// consumer shouldn't overtake producer
{   struct rb_item *polled_item = NULL; int rc;
    while ( 1 == (rc = rb_poll((void*)&polled_item, rseq_current_mm_cid())) ) {
        fprintf(stderr, "rseq failed\n");
    }
    TEST_ASSERT( -1 == rc, "`rb_poll` rc must be -1" );
}

// `rb_offer` & `rb_poll`
    for (unsigned int i = 0; i < (RB_CAPACITY_ITEMS << 1); ++i) {
        struct rb_item* offered_item = DIE_WHEN_ERRNO_VPTR( malloc( sizeof(*offered_item) ) );
        offered_item->val = i;
        int rc;
        while ( 1 == (rc = rb_offer((void*)offered_item, rseq_current_mm_cid())) ) {
            fprintf(stderr, "rseq failed\n");
        }
        TEST_ASSERT( 0 == rc, "`rb_offer` rc must be 0" );

        struct rb_item *polled_item = NULL;
        while ( 1 == (rc = rb_poll((void*)&polled_item, rseq_current_mm_cid())) ) {
            fprintf(stderr, "rseq failed\n");
        }
        TEST_ASSERT( 0 == rc, "`rb_poll` rc must be 0" );
        TEST_ASSERT( polled_item == offered_item  &&  polled_item->val == offered_item->val, "`polled_item` must be eq 2 `offered_item`" );
        free(polled_item);  offered_item = NULL; polled_item = NULL;
    }

// producer should block before lapping consumer
    for (unsigned int i = 0; i <= RB_CAPACITY_ITEMS; ++i) {
        int rc;
        while ( 1 == (rc = rb_offer((void*)NULL, rseq_current_mm_cid())) ) {
            fprintf(stderr, "rseq failed\n");
        }
        TEST_ASSERT( ((i < RB_CAPACITY_ITEMS) ? 0 : -1) == rc, "`rb_offer` invalid rc" );
    }

    fprintf(stdout, "PASSED tests\n");


// finalize
    free(g_rb_baseptr);  g_rb_baseptr = NULL;
    DIE_WHEN_ERR( rseq_unregister_current_thread() );

    return 0;
}
