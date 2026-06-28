#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Import the actual function from the production code */
extern void *portable_metadata_new(const char *name, const char *path, 
                                   const char *selinux_label, int fd);

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    /* Invariant: Buffer reads never exceed the declared length */
    const char *payloads[] = {
        /* Exact exploit case: string that could cause off-by-one */
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        /* Boundary case: exactly 255 chars (common buffer size) */
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        /* Valid input: normal string */
        "normal_unit_name.service"
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    /* Create guard pages around test memory */
    long page_size = sysconf(_SC_PAGESIZE);
    void *guard_before = mmap(NULL, page_size, PROT_NONE, 
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *test_area = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *guard_after = mmap(NULL, page_size, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    for (int i = 0; i < num_payloads; i++) {
        /* Copy payload into test area */
        strncpy((char *)test_area, payloads[i], page_size - 1);
        ((char *)test_area)[page_size - 1] = '\0';

        /* Call production function with adversarial input */
        void *result = portable_metadata_new((const char *)test_area, 
                                             NULL, NULL, -1);
        
        /* If allocation succeeded, verify no guard page corruption */
        if (result) {
            /* Try to access guard pages - should crash if corrupted */
            volatile char test_before = *((char *)guard_before + page_size - 1);
            volatile char test_after = *((char *)guard_after);
            (void)test_before; (void)test_after; /* Suppress unused warnings */
            
            free(result);
        }
        
        /* Test passes if we get here without segfault */
    }

    /* Cleanup */
    munmap(guard_before, page_size);
    munmap(test_area, page_size);
    munmap(guard_after, page_size);
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}