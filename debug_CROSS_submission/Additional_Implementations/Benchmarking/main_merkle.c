#include "csprng_hash.h"
#include <stdio.h>
#include <stdint.h>
#include "merkle_tree.h"
/*
void print_array(uint8_t *arr, size_t size) {
    int ctr = 0;
    for (size_t i = 0; i < size; i++) {
        printf("%u, ", arr[i]);
        ctr++;
    }
    printf("\n");
}

void merkleTestSpeed(){
    const char *seeds[] = {
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "HMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM",
        "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    };
    for (int j = 0; j < 3; j++) {
        uint8_t root[HASH_DIGEST_LENGTH];
    uint8_t leaves[T][HASH_DIGEST_LENGTH];
    for (int i = 0; i < T; i++) {
        randombytes(leaves[i],HASH_DIGEST_LENGTH);
    }
    printf("Leaves: \n");
   for (int i = 0; i < T; i++) {
        print_array(leaves[i], HASH_DIGEST_LENGTH);
    }
    tree_root(root, leaves);
    printf("Root: \n");
    print_array(root,HASH_DIGEST_LENGTH);
    printf("Chall_2: \n");
    

    //tree_proof
    uint8_t chall_2[T]={0};
    const char *input = seeds[j];
    expand_digest_to_fixed_weight(chall_2,input);
    uint8_t proof[W*HASH_DIGEST_LENGTH];
    print_array(chall_2,T);
    tree_proof(proof,leaves,chall_2);
    printf("Proof: \n");
    for (int i = 0; i < W; i++) {
        print_array(proof + i*HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
    }
    }
}

void merkleTest(){
    const char *seeds[] = {
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "HMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM",
        "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    };
    for (int j = 0; j < 3; j++) {
        uint8_t root[HASH_DIGEST_LENGTH];
        uint8_t leaves[T][HASH_DIGEST_LENGTH];
        for (int i = 0; i < T; i++) {
            randombytes(leaves[i],HASH_DIGEST_LENGTH);
        }
        printf("Leaves: \n");
        for (int i = 0; i < T; i++) {
            print_array(leaves[i], HASH_DIGEST_LENGTH);
        }
        uint8_t tree[NUM_NODES_MERKLE_TREE * HASH_DIGEST_LENGTH] = {0};
        tree_root(root, tree, leaves);
        printf("Root: \n");
        print_array(root,HASH_DIGEST_LENGTH);
        printf("Chall_2: \n");
    

        //tree_proof
        uint8_t chall_2[T]={0};
        const char *input = seeds[j];
        expand_digest_to_fixed_weight(chall_2,input);
        uint8_t proof[HASH_DIGEST_LENGTH*TREE_NODES_TO_STORE] = {0};
        print_array(chall_2,T);
        tree_proof(proof, tree, chall_2);
        printf("Proof: \n");
        for (int i = 0; i < TREE_NODES_TO_STORE; i++) {
            print_array(proof + i*HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
        }
    }
}
*/

int main() {
    //merkleTest();
    return 0;
}