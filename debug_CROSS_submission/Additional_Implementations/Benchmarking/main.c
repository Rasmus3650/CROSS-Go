#include <stdio.h>
#include <stdint.h>
#include "CROSS.h"  // Make sure this is the correct header file

int main() {
    printf("Generating CROSS keypair...\n");

    // Declare secret and public key structures
    sk_t SK;
    pk_t PK;

    // Generate key pair
    CROSS_keygen(&SK, &PK);
    printf("New and improved!");
    // Print Secret Key (as hex)
    printf("Secret Key (seed_sk): ");
    for (size_t i = 0; i < KEYPAIR_SEED_LENGTH_BYTES; i++) {
        printf("%02X", SK.seed_sk[i]);
    }
    printf("\n");

    // Print Public Key (seed_pk)
    printf("Public Key (seed_pk): ");
    for (size_t i = 0; i < KEYPAIR_SEED_LENGTH_BYTES; i++) {
        printf("%02X", PK.seed_pk[i]);
    }
    printf("\n");

    return 0;
}

