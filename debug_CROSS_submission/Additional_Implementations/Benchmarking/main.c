#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "CROSS.h"

void print_array(uint8_t *arr, size_t size) {
    int ctr = 0;
    for (size_t i = 0; i < size; i++) {
        printf("%u, ", arr[i]);
        ctr++;
    }
    printf("\n");
}

void print_pk(FZ_ELEM s[DENSELY_PACKED_FP_SYN_SIZE]){
    for (int i = 0; i < DENSELY_PACKED_FP_SYN_SIZE; i++) {
        printf("%u, ", s[i]);
    }
    printf("\n");
    return;
}

void print_large_array(uint8_t *arr, size_t size) {
    int ctr = 0;
    for (size_t i = 0; i < size; i++) {
        if (ctr % 64 == 0){
            printf("\n");
        }
        printf("%u, ", arr[i]);
        ctr++;
    }
    printf("\n");
}

int main() {
    sk_t *SK = malloc(sizeof(sk_t));
    pk_t *PK = malloc(sizeof(pk_t));
    CROSS_keygen(SK, PK);
    printf("seed_SK: \n");
    print_array(SK->seed_sk, KEYPAIR_SEED_LENGTH_BYTES);
    printf("seed_PK: \n");
    print_array(PK->seed_pk, KEYPAIR_SEED_LENGTH_BYTES);
    printf("PK->s: \n");
    print_pk(PK->s);
    CROSS_sig_t *SIG = malloc(sizeof(CROSS_sig_t));
    if (SIG) {
        memset(SIG, 0, sizeof(CROSS_sig_t));
    }
    CROSS_sign(SK, "Hello, World!", 13, SIG);
    printf("------ Signature ------\n");
    printf("Salt: ");
    print_array(SIG->salt, SALT_LENGTH_BYTES);
    printf("\n");
    printf("Digest CMT: ");
    print_array(SIG->digest_cmt, HASH_DIGEST_LENGTH);
    printf("\n");
    printf("Digest Chall 2: ");
    print_array(SIG->digest_chall_2, HASH_DIGEST_LENGTH);
    printf("\n");
    //Variate next two if in speed
    printf("Path: \n");
    print_large_array(SIG->path, TREE_NODES_TO_STORE*SEED_LENGTH_BYTES);
    printf("\n");
    printf("Proof: \n");
    print_large_array(SIG->proof, TREE_NODES_TO_STORE*HASH_DIGEST_LENGTH);
    //
    printf("\n");
    printf("Resp 1: \n");
    for (int i = 0; i < T-W; i++) {
        print_array(SIG->resp_1[i], HASH_DIGEST_LENGTH);
    }
    printf("\n");
    printf("Resp 0: \n");
    printf("y: ");
    for (int i = 0; i < T-W; i++) {
        print_array(SIG->resp_0[i].y, DENSELY_PACKED_FP_VEC_SIZE);
    }
    printf("v_bar: ");
    for (int i = 0; i < T-W; i++) {
    print_array(SIG->resp_0[i].v_bar, DENSELY_PACKED_FZ_VEC_SIZE);
    }
    
    printf("\n");
    return 0;
}