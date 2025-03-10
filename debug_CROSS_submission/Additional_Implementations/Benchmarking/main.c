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
int test_csprng(){
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
    return 0;
}

int main() {
    return test_csprng();
}




// 65 32 72 101 108 108 111 44 32 109 105 115 116 101 114 46 32 73 32 97 109 32 97 32 115 101 101 100 115 115 32 116 2 3 31
// 65 32 72 101 108 108 111 44 32 109 105 115 116 101 114 46 32 73 32 97 109 32 97 32 115 101 101 100 115 115 115 115 2 3 31
