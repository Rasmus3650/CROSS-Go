#include "csprng_hash.h"
#include <stdio.h>
#include <stdint.h>

void print_csprng_state(const CSPRNG_STATE_T *csprng_state, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%u ", ((unsigned char*)csprng_state)[i]);  // Print byte as decimal
    }
    printf("\n");
}

void print_seed_array(uint8_t seed_e_seed_pk[2][KEYPAIR_SEED_LENGTH_BYTES]) {
    printf("seed_e_seed_pk:\n");
    for (int i = 0; i < 2; i++) {
        printf("Row %d: ", i);
        for (int j = 0; j < KEYPAIR_SEED_LENGTH_BYTES; j++) {
            printf("%u ", seed_e_seed_pk[i][j]);  // Print in hex format
        }
        printf("\n");
    }
}

void print_hash(const uint8_t *digest, size_t length) {
    printf("Digest message: ");
    for (size_t i = 0; i < length; i++) {
        printf("%u ", digest[i]);  // Print each byte as a two-digit hexadecimal
    }
    printf("\n");
}

void test_csprng(){
    printf("Testing csprng\n");
    const uint16_t dsc_csprng_seed_pk = CSPRNG_DOMAIN_SEP_CONST + (3*T+2);
    //printf("dsc_csprng_seed_pk: %u\n", dsc_csprng_seed_pk);
    CSPRNG_STATE_T csprng_state_mat;
    const char * restrict seed_sk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    csprng_initialize(&csprng_state_mat, seed_sk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
    //printf("Hash generated\n");
    //print_csprng_state(&csprng_state_mat, sizeof(csprng_state_mat));
    //print_csprng_state(&csprng_state_mat, 32);
    uint8_t seed_e_seed_pk[2][KEYPAIR_SEED_LENGTH_BYTES];
    csprng_randombytes((uint8_t *)seed_e_seed_pk, 2*KEYPAIR_SEED_LENGTH_BYTES, &csprng_state_mat);
    print_seed_array(seed_e_seed_pk);
    return;
}

void test_hash(){
    printf("Testing hash\n");
    uint8_t digest_msg_cmt_salt[2*HASH_DIGEST_LENGTH+SALT_LENGTH_BYTES];
    printf("HASH DOMAIN SEP CONST: %u\n", HASH_DOMAIN_SEP_CONST);
    printf("SALT LENGTH BYTES: %u\n", SALT_LENGTH_BYTES);
    const char *const m = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const uint64_t mlen = 32;
    /* place digest_msg at the beginning of the input of the hash generating digest_chall_1 */
    hash(digest_msg_cmt_salt, (uint8_t*) m, mlen, HASH_DOMAIN_SEP_CONST);
    print_hash(digest_msg_cmt_salt, 2*HASH_DIGEST_LENGTH+SALT_LENGTH_BYTES);
    //print_csprng_state(digest_msg_cmt_salt, 2*HASH_DIGEST_LENGTH+SALT_LENGTH_BYTES);
    return;
}

int main() {
    test_hash();
    return 0;
}

//Row 0: 15 121 106 185 65 60 38 57 192 11 100 5 36 234 50 253 115 61 99 71 54 20 106 223 64 83 75 131 107 171 179 163 
//Row 1: 197 184 200 221 6 37 92 70 124 127 54 125 11 163 142 207 26 21 208 178 226 28 152 49 104 87 51 136 32 87 109 243 


