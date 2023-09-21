/*
 * Very simple RSEQ MPSC ring-buffer demo
 *   WORKS ONLY ON amd64 !
 */
#include <stdio.h>
#include <stdlib.h>

#include <rseq/rseq.h>      // Librseq

#include <common.h>         // rpmalloc


// --  Data structures  --
struct rb_item {
    unsigned int val;
};

#define RB_CAPACITY_ITEMS (1 << 2)
struct rb {
    unsigned long head,
                  tail;
    struct rb_item* buf[RB_CAPACITY_ITEMS];           //TODO: Mention in text that this implementation holds pointers (instead of the items themselves)
};
#define RB_CAPACITY_BYTES  sizeof(((struct rb*)0)->buf)
_Static_assert( RB_CAPACITY_BYTES && ( (RB_CAPACITY_BYTES & -RB_CAPACITY_BYTES) == RB_CAPACITY_BYTES), "Not a power of 2" );

// --  Globals  --
struct rb* g_rb_baseptr;


// --  Operations  --
static inline int rb_offer(struct rb_item* const item_ptr,
                           const unsigned int cpu) {
    struct rb* const rb_ptr = (struct rb*)((uintptr_t)g_rb_baseptr + sizeof(*g_rb_baseptr) * cpu);

    __asm__ __volatile__ goto (
        RSEQ_ASM_DEFINE_TABLE(3/* cs_label */, 1f/* start_ip */, 2f/* post_commit_ip */, 4f/* abort_ip */)
        RSEQ_ASM_DEFINE_EXIT_POINT(1f/* start_ip */, %l[block]/* exit_ip */)

        //  - Register CS  (!!  clobbers rax  !!)
        RSEQ_ASM_STORE_RSEQ_CS(1/* start_ip */, 3b/* cs_label */, RSEQ_ASM_TP_SEGMENT:RSEQ_CS_OFFSET(%[rseq_offset]))

        //  - Check CPU
        RSEQ_ASM_CMP_CPU_ID(cpu_id, RSEQ_ASM_TP_SEGMENT:RSEQ_MM_CID_OFFSET(%[rseq_offset]), 4f/* abort_ip */)

        // - Prepare  (copy item)
        // Check whether ring-buffer is full
        "movq   %c[rb_off_tail](%[rb_ptr]),  %%rax\n\t"
        "and    $%c[rb_cap_mask],            %%rax\n\t"
        "movq   %c[rb_off_head](%[rb_ptr]),  %%rbx\n\t"                                // rbx = mod reduced head
        "and    $%c[rb_cap_mask],            %%rbx\n\t"
        "cmpq   %%rax,                       %%rbx\n\t"                                // Compare mod reduced heads
        "movq   %c[rb_off_head](%[rb_ptr]),  %%rax\n\t"                                // Check whether they "overlap" due 2 producer lapping the consumer ; rax = CURRENT head
        "jne    11f\n\t"                                                               //   Required, otherwise head = tail = 0 (I.E., @ the start) would indicate a full RB
        "cmpq   %c[rb_off_tail](%[rb_ptr]),  %%rax\n\t"
        "jg     %l[block]\n\t"
        "11:\n\t"

        // Copy items pointer in2 rb
        "addq   %[rb_ptr],                   %%rbx\n\t"
        "addq   $%c[rb_off_buf],             %%rbx\n\t"                                // rbx = write offset
        "movq   %[item_ptr],                 (%%rbx)\n\t"

        "addq   $%c[item_ptr_size],          %%rax\n\t"                                // rax = NEXT head
        // - Commit  (by writing new head, which makes copied item visible 2 consumers)
        "movq    %%rax,                      %c[rb_off_head](%[rb_ptr])\n\t"
        "2:\n\t"
        RSEQ_ASM_DEFINE_ABORT(4/* abort_ip */, ""/* teardown */, abort/* abort_label */)

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
    rseq_after_asm_goto();
    return 1;
block:
    rseq_after_asm_goto();
    return -1;
}


/* This is a MPSC ring-buffer implementation
 *   -> The consumer (which uses `rb_poll`) thus doesn't need to be protected
 *      against preemption using RSEQ (as there's only 1 consumer anyways)
 *   -> RSEQ would be necessity though in a MPMC implementation
 */
int rb_poll(struct rb_item** const item_ptr,
               const unsigned int cpu) {
    struct rb* const rb_ptr = (struct rb*)((uintptr_t)g_rb_baseptr + sizeof(*g_rb_baseptr) * cpu);

    if (rb_ptr->head > rb_ptr->tail) {
        const int idx = (rb_ptr->tail & (RB_CAPACITY_BYTES - 1)) / sizeof(rb_ptr->buf[0]);
        *item_ptr = rb_ptr->buf[idx];
        rb_ptr->tail += sizeof(rb_ptr->buf[0]);
        if (0) {
            return 1;   // WOULD indicate failed rseq
        }
        return 0;       // Success
    }
    return -1;          // block
}




// --------------------- ---------------------  TEST DRIVER  --------------------- ---------------------
int main(void) {
#define TEST_ASSERT(TRUTH, MSG_FMT, ...) do { \
    if (! (TRUTH) ) { \
        fprintf(stderr, "ASSERT FAILED @ " __FILE__ ":" STRINGIFY(__LINE__) ": " MSG_FMT "\n", ##__VA_ARGS__); \
        abort(); \
    } \
 } while(0)

// setup
    g_rb_baseptr = DIE_WHEN_ERRNO_VPTR( malloc(DIE_WHEN_ERR( system_get_ncpus(0) ) * sizeof(*g_rb_baseptr)) );
    DIE_WHEN_ERR( rseq_register_current_thread() );


// consumer shouldn't overtake producer
{   struct rb_item *polled_item = NULL; int rc;
    while ( 1 == (rc = rb_poll(&polled_item, rseq_current_mm_cid())) ) {
        fprintf(stderr, "rseq failed\n");
    }
    TEST_ASSERT( -1 == rc, "`rb_poll` rc must be -1" );
}

// `rb_offer` & `rb_poll`
    for (unsigned int i = 0; i < (RB_CAPACITY_ITEMS << 1); ++i) {
        struct rb_item* offered_item = DIE_WHEN_ERRNO_VPTR( malloc( sizeof(*offered_item) ) );
        offered_item->val = i;
        int rc;
        while ( 1 == (rc = rb_offer(offered_item, rseq_current_mm_cid())) ) {
            fprintf(stderr, "rseq failed\n");
        }
        TEST_ASSERT( 0 == rc, "`rb_offer` rc must be 0" );

        struct rb_item *polled_item = NULL;
        while ( 1 == (rc = rb_poll(&polled_item, rseq_current_mm_cid())) ) {
            fprintf(stderr, "rseq failed\n");
        }
        TEST_ASSERT( 0 == rc, "`rb_poll` rc must be 0" );
        TEST_ASSERT( polled_item == offered_item  &&  polled_item->val == offered_item->val, "`polled_item` must be eq 2 `offered_item`" );
        free(polled_item);  offered_item = NULL; polled_item = NULL;
    }

// producer should block before lapping consumer
    for (unsigned int i = 0; i <= RB_CAPACITY_ITEMS; ++i) {
        int rc;
        while ( 1 == (rc = rb_offer((struct rb_item*)NULL, rseq_current_mm_cid())) ) {
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
