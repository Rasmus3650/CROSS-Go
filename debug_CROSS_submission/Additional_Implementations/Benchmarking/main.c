#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "CROSS.h"

//printf(KEYPAIR_SEED_LENGTH_BYTES);
//printf("CROSS_sig_t size: \n");
//print("%u", sizeof(CROSS_sig_t));

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

// Placeholder for actual CROSS library
#include "CROSS.h" // You need to define this based on your CROSS implementation

#define ITERATIONS 1000

// Timing helper
long long time_diff_ns(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
}

int main() {
    long long totalKeyGen = 0;
    long long totalSign = 0;
    long long totalVerify = 0;

    const unsigned char msg[] = "Hello, world!";
    const size_t msg_len = sizeof(msg) - 1;

    for (int i = 0; i < ITERATIONS; i++) {
        struct timespec start, end;
        sk_t *SK = malloc(sizeof(sk_t));
        pk_t *PK = malloc(sizeof(pk_t));
        // KeyGen timing
        clock_gettime(CLOCK_MONOTONIC, &start);
        CROSS_keygen(SK, PK);
        clock_gettime(CLOCK_MONOTONIC, &end);
        totalKeyGen += time_diff_ns(start, end);

        // Sign timing
        CROSS_sig_t *SIG = malloc(sizeof(CROSS_sig_t));
        if (SIG) {
            memset(SIG, 0, sizeof(CROSS_sig_t));
        }
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        CROSS_sign(SK, "Hello, World!", 13, SIG);
        clock_gettime(CLOCK_MONOTONIC, &end);
        totalSign += time_diff_ns(start, end);

        // Verify timing
        clock_gettime(CLOCK_MONOTONIC, &start);
        int ok = CROSS_verify(PK, "Hello, World!", 13, SIG);
        clock_gettime(CLOCK_MONOTONIC, &end);
        totalVerify += time_diff_ns(start, end);

        if (ok != 1) {
            fprintf(stderr, "Signature verification failed at iteration %d\n", i);
            continue;
        }
    }

    printf("Average KeyGen time: %.2f ms\n", totalKeyGen / (ITERATIONS * 1e6));
    printf("Average Sign time:   %.2f ms\n", totalSign / (ITERATIONS * 1e6));
    printf("Average Verify time: %.2f ms\n", totalVerify / (ITERATIONS * 1e6));

    return 0;
}