#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "CROSS.h"

//printf(KEYPAIR_SEED_LENGTH_BYTES);
//printf("CROSS_sig_t size: \n");
//print("%u", sizeof(CROSS_sig_t));

int main() {
    //printf("%u", KEYPAIR_SEED_LENGTH_BYTES+DENSELY_PACKED_FP_SYN_SIZE);
    printf("PK size: \n");
    printf("%lu \n", sizeof(pk_t));
    printf("CROSS_sig_t size: \n");
    printf("%lu \n", sizeof(CROSS_sig_t));
    return 0;
}