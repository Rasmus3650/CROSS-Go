#include "csprng_hash.h"
#include <stdio.h>
#include <stdint.h>
#include "seedtree.h"


void print_array(uint8_t *arr, size_t size) {
    int ctr = 0;
    printf("Array contents: ");
    for (size_t i = 0; i < size; i++) {
        if (ctr % 128 == 0) {
            printf("\n");
        }
        printf("%u, ", arr[i]);
        ctr++;
    }
    printf("\n");
}

void seedLeavesSeedPathTestSpeed(){
    //SeedPath part
    const char *seeds[] = {
        "AAAAAAAAAAAAAAAA",
        "HMMMMMMMMMMMMMMM",
        "ZZZZZZZZZZZZZZZZ"
    };
    // Iterate over each seed
    for (int i = 0; i < 3; i++) {
        printf("START!!!");
        uint8_t root_seed[SEED_LENGTH_BYTES] = {231, 221, 225, 64, 121, 143, 37, 241, 138, 71, 192, 51, 249, 204, 213, 132};
        uint8_t salt[SALT_LENGTH_BYTES] = {238, 169, 90, 166, 30, 38, 152, 213, 77, 73, 128, 111, 48, 71, 21, 189, 87, 208, 83, 98, 5, 78, 40, 139, 212, 111, 142, 127, 45, 164, 151, 255};
        //randombytes(root_seed,SEED_LENGTH_BYTES);
        //randombytes(salt,SALT_LENGTH_BYTES);
        printf("Root and salt: \n");
        print_array(root_seed, SEED_LENGTH_BYTES);
        print_array(salt, SALT_LENGTH_BYTES);
        
        
        //No trees
        unsigned char round_seeds[T*SEED_LENGTH_BYTES] = {0};
        seed_leaves(round_seeds,root_seed,salt);
        printf("Leaves: \n");
        print_array(round_seeds, T*SEED_LENGTH_BYTES);
        
        uint8_t chall_2[T] = {0};
        uint8_t digest_chall_2[HASH_DIGEST_LENGTH] = {0};
        const char *input = seeds[i];
        // Process the seed (hashing, expanding, printing)
        hash(digest_chall_2, input, 32, HASH_DOMAIN_SEP_CONST);
        expand_digest_to_fixed_weight(chall_2, digest_chall_2);
        printf("Chall2: \n");
        print_array(chall_2, T);
        //notrees
        uint8_t path[W*SEED_LENGTH_BYTES] = {0};
        seed_path(path, round_seeds, chall_2);
        printf("Path: \n");
        print_array(path, TREE_NODES_TO_STORE*SEED_LENGTH_BYTES);
    }
}

/*void seedLeavesSeedPathTest() {
    //SeedPath part
    const char *seeds[] = {
        "AAAAAAAAAAAAAAAA",
        "HMMMMMMMMMMMMMMM",
        "ZZZZZZZZZZZZZZZZ"
    };

    // Iterate over each seed
    for (int i = 0; i < 3; i++) {
        printf("START!!!");
        uint8_t root_seed[SEED_LENGTH_BYTES];
        uint8_t salt[SALT_LENGTH_BYTES];
        randombytes(root_seed,SEED_LENGTH_BYTES);
        randombytes(salt,SALT_LENGTH_BYTES);
        printf("Root and salt: \n");
        print_array(root_seed, SEED_LENGTH_BYTES);
        print_array(salt, SALT_LENGTH_BYTES);
        //With trees
        uint8_t seed_tree[SEED_LENGTH_BYTES*NUM_NODES_SEED_TREE] = {0};
        gen_seed_tree(seed_tree,root_seed,salt);
        unsigned char round_seeds[T*SEED_LENGTH_BYTES] = {0};
        seed_leaves(round_seeds, seed_tree);
        printf("Leaves: \n");
        print_array(round_seeds, T*SEED_LENGTH_BYTES);
        
        uint8_t chall_2[T] = {0};
        uint8_t digest_chall_2[HASH_DIGEST_LENGTH] = {0};
        const char *input = seeds[i];
        // Process the seed (hashing, expanding, printing)
        hash(digest_chall_2, input, 32, HASH_DOMAIN_SEP_CONST);
        expand_digest_to_fixed_weight(chall_2, digest_chall_2);
        printf("Chall2: \n");
        print_array(chall_2, T);
        //with trees
        uint8_t path[TREE_NODES_TO_STORE*SEED_LENGTH_BYTES] = {0};
        //notrees
        //uint8_t path[W*SEED_LENGTH_BYTES] = {0};
        seed_path(path, seed_tree, chall_2);
        printf("Path: \n");
        print_array(path, TREE_NODES_TO_STORE*SEED_LENGTH_BYTES);
    }
}*/




int main() {
    seedLeavesSeedPathTestSpeed();
    return 0;
}