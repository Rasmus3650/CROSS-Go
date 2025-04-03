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
    return 0;
}