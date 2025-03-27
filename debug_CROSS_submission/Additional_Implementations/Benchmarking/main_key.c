#include "csprng_hash.h"
#include <stdio.h>
#include <stdint.h>
#include "fp_arith.h"
#include "CROSS.h"
/*
void print_csprng_state(const CSPRNG_STATE_T *csprng_state, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%u ", ((unsigned char*)csprng_state)[i]);
    }
    printf("\n");
}

void print_seed_array(uint8_t seed_e_seed_pk[2][KEYPAIR_SEED_LENGTH_BYTES]) {
    printf("seed_e_seed_pk:\n");
    for (int i = 0; i < 2; i++) {
        printf("Row %d: ", i);
        for (int j = 0; j < KEYPAIR_SEED_LENGTH_BYTES; j++) {
            printf("%u, ", seed_e_seed_pk[i][j]);
        }
        printf("\n");
    }
}

void print_V_tr(FP_ELEM V_tr[K][N-K]){
    printf("V_tr:\n");
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N-K; j++) {
            printf("%u, ", V_tr[i][j]);
        }
        printf("\n");
    }
    return;
}

void print_z_vec(FP_ELEM z[N]){
    printf("z:\n");
    for (int i = 0; i < N; i++) {
        printf("%u, ", z[i]);
    }
    printf("\n");
    return;
}

void print_hash(const uint8_t *digest, size_t length) {
    printf("Digest message: ");
    for (size_t i = 0; i < length; i++) {
        printf("%u, ", digest[i]); 
    }
    printf("\n");
}

/*void test_csprng(){
    printf("Testing csprng\n");
    const uint16_t dsc_csprng_seed_pk = CSPRNG_DOMAIN_SEP_CONST + (3*T+2);
    printf("T: %u\n", T);
    printf("dsc_csprng_seed_pk: %u\n", dsc_csprng_seed_pk);
    printf("KEYPAIR_SEED_LENGTH_BYTES: %u\n", KEYPAIR_SEED_LENGTH_BYTES);
    CSPRNG_STATE_T csprng_state_mat;
    //32 A's
    //const char * restrict seed_sk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const char * restrict seed_sk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    csprng_initialize(&csprng_state_mat, seed_sk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
    //printf("Hash generated\n");
    //print_csprng_state(&csprng_state_mat, sizeof(csprng_state_mat));
    //print_csprng_state(&csprng_state_mat, 32);
    uint8_t seed_e_seed_pk[2][KEYPAIR_SEED_LENGTH_BYTES];
    print_seed_array(seed_e_seed_pk);
    csprng_randombytes((uint8_t *)seed_e_seed_pk, 2*KEYPAIR_SEED_LENGTH_BYTES, &csprng_state_mat);
    print_seed_array(seed_e_seed_pk);
    return;
}

void test_hash(){
    printf("Testing hash\n");
    uint8_t digest_msg_cmt_salt[HASH_DIGEST_LENGTH] = {0};
    printf("HASH DOMAIN SEP CONST: %u\n", HASH_DOMAIN_SEP_CONST);
    printf("SALT LENGTH BYTES: %u\n", SALT_LENGTH_BYTES);
    const char *const m = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const uint64_t mlen = 32;
    // place digest_msg at the beginning of the input of the hash generating digest_chall_1
    print_hash(digest_msg_cmt_salt, HASH_DIGEST_LENGTH);
    hash(digest_msg_cmt_salt, (uint8_t*) m, mlen, HASH_DOMAIN_SEP_CONST);
    print_hash(digest_msg_cmt_salt, HASH_DIGEST_LENGTH);
    //print_csprng_state(digest_msg_cmt_salt, 2*HASH_DIGEST_LENGTH+SALT_LENGTH_BYTES);
    return;
}

void test_keygen(){
    printf("Testing keygen\n");
    
}

void print_V_tr(FP_ELEM V_tr[K][N-K]){
    printf("V_tr:\n");
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N-K; j++) {
            printf("%u, ", V_tr[i][j]);
        }
        printf("\n");
    }
    return;
}

void test_csprng_fp_mat(){
    FP_ELEM V_tr[K][N-K];
    printf("Testing CSPRNG - fp_mat\n");
    const uint16_t dsc_csprng_seed_pk = CSPRNG_DOMAIN_SEP_CONST + (3*T+2);
    CSPRNG_STATE_T csprng_state_mat;
    const char * restrict seed_pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    csprng_initialize(&csprng_state_mat, seed_pk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
    //print_csprng_state(&csprng_state_mat, sizeof(csprng_state_mat));
    csprng_fp_mat(V_tr,&csprng_state_mat);
    print_V_tr(V_tr);
    return;
}

void print_z_vec(FP_ELEM z[N]){
    printf("z:\n");
    for (int i = 0; i < N; i++) {
        printf("%u, ", z[i]);
    }
    printf("\n");
    return;
}

void test_csprng_fz_vec(){
    printf("Testing CSPRNG - fz_vec\n");
    FZ_ELEM z[N];
    const uint16_t dsc_csprng_seed_pk = CSPRNG_DOMAIN_SEP_CONST + (3*T+3);
    CSPRNG_STATE_T csprng_state_mat;
    const char * restrict seed_pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    csprng_initialize(&csprng_state_mat, seed_pk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
    //print_csprng_state(&csprng_state_mat, sizeof(csprng_state_mat));
    csprng_fz_vec(z,&csprng_state_mat);
    print_z_vec(z);
    return;
}

void test_csprng_fp_vec(){
    printf("Testing CSPRNG - fp_vec\n");
    FP_ELEM z[N];
    const uint16_t dsc_csprng_seed_pk = CSPRNG_DOMAIN_SEP_CONST + (2*T-1);
    CSPRNG_STATE_T csprng_state_mat;
    const char * restrict seed_pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    csprng_initialize(&csprng_state_mat, seed_pk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
    //print_csprng_state(&csprng_state_mat, sizeof(csprng_state_mat));
    csprng_fp_vec(z,&csprng_state_mat);
    print_z_vec(z);
    return;
}

void print_chall_1(FP_ELEM chall_1[T]){
    printf("chall_1:\n");
    for (int i = 0; i < T; i++) {
        printf("%u, ", chall_1[i]);
    }
    printf("\n");
    return;
}

void test_csprng_fp_vec_chall_1(){
    printf("Testing CSPRNG - fp_vec_chall_1\n");
    FP_ELEM chall_1[T];
    const uint16_t dsc_csprng_seed_pk = CSPRNG_DOMAIN_SEP_CONST + (3*T-1);
    CSPRNG_STATE_T csprng_state_mat;
    const char * restrict seed_pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    csprng_initialize(&csprng_state_mat, seed_pk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
    //print_csprng_state(&csprng_state_mat, sizeof(csprng_state_mat));
    csprng_fp_vec_chall_1(chall_1,&csprng_state_mat);
    print_chall_1(chall_1);
    return;
}

void print_e_G_bar(FZ_ELEM e_G_bar[M]){
    printf("e_G_bar:\n");
    for (int i = 0; i < M; i++) {
        printf("%u, ", e_G_bar[i]);
    }
    printf("\n");
    return;
}

//Reminder, this test only works in RSDP-G
void test_csprng_fz_inf_w(){
    printf("Testing CSPRNG - fz_inf_w\n");
    FZ_ELEM e_G_bar[M];
    const uint16_t dsc_csprng_seed_pk = CSPRNG_DOMAIN_SEP_CONST + (3*T+3);
    CSPRNG_STATE_T csprng_state_mat;
    const char * restrict seed_pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    csprng_initialize(&csprng_state_mat, seed_pk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
    //print_csprng_state(&csprng_state_mat, sizeof(csprng_state_mat));
    csprng_fz_inf_w(e_G_bar,&csprng_state_mat);
    print_e_G_bar(e_G_bar);
    return;
}



void test_expand_digest_to_fixed_weight(){
    printf("Testing expand_digest_to_fixed_weight\n");
    uint8_t chall_2[T]={0};
    const char * restrict digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expand_digest_to_fixed_weight(chall_2, (uint8_t*) digest);
    printf("chall_2:\n");
    for (int i = 0; i < T; i++) {
        printf("%u, ", chall_2[i]);
    }
    printf("\n");
    return;
}*/

/*


void print_W_mat(FZ_ELEM W_mat[M][N-M]){
    printf("W_mat:\n");
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N-M; j++) {
            printf("%u, ", W_mat[i][j]);
        }
        printf("\n");
    }
    return;
}

void expand_sk_RSDPG(FZ_ELEM e_bar[N],
    FZ_ELEM e_G_bar[M],
    FP_ELEM V_tr[K][N-K],
    FZ_ELEM W_mat[M][N-M],
    const uint8_t seed_sk[KEYPAIR_SEED_LENGTH_BYTES]){

uint8_t seed_e_seed_pk[2][KEYPAIR_SEED_LENGTH_BYTES];
CSPRNG_STATE_T csprng_state;

// Expansion of sk->seed, explicit domain separation for CSPRNG, as in keygen
const uint16_t dsc_csprng_seed_sk = CSPRNG_DOMAIN_SEP_CONST + (3*T+1);

csprng_initialize(&csprng_state, seed_sk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_sk);
csprng_randombytes((uint8_t *)seed_e_seed_pk,
          2*KEYPAIR_SEED_LENGTH_BYTES,
          &csprng_state);

expand_pk_RSDPG(V_tr,W_mat,seed_e_seed_pk[1]);

// Expansion of seede, explicit domain separation for CSPRNG as in keygen
const uint16_t dsc_csprng_seed_e = CSPRNG_DOMAIN_SEP_CONST + (3*T+3);

CSPRNG_STATE_T csprng_state_e_bar;
csprng_initialize(&csprng_state_e_bar, seed_e_seed_pk[0], KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_e);
csprng_fz_inf_w(e_G_bar,&csprng_state_e_bar);
fz_inf_w_by_fz_matrix(e_bar,e_G_bar,W_mat);

fz_dz_norm_n(e_bar);
}


void test_expand_pk_RSDPG(){
    printf("Testing expand_pk\n");
    FP_ELEM V_tr[K][N-K];
    FZ_ELEM W_mat[M][N-M];
    const char * restrict seed_pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expand_pk_RSDPG(V_tr, W_mat, (uint8_t*) seed_pk);
    print_V_tr(V_tr);
    print_W_mat(W_mat);
    return;
}*/
/*
void print_e_G_bar(FZ_ELEM e_G_bar[M]){
    printf("e_G_bar:\n");
    for (int i = 0; i < M; i++) {
        printf("%u, ", e_G_bar[i]);
    }
    printf("\n");
    return;
}

void print_e_bar(FZ_ELEM e_bar[N]){
    printf("e_bar:\n");
    for (int i = 0; i < N; i++) {
        printf("%u, ", e_bar[i]);
    }
    printf("\n");
    return;
}

void print_s(FZ_ELEM s[N-K]){
    printf("s:\n");
    for (int i = 0; i < N-K; i++) {
        printf("%u, ", s[i]);
    }
    printf("\n");
    return;
}

void test_expand_sk_RSDPG(){
    printf("Testing expand_sk\n");
    FZ_ELEM e_bar[N];
    FZ_ELEM e_G_bar[M];
    FP_ELEM V_tr[K][N-K];
    FZ_ELEM W_mat[M][N-M];
    const char * restrict seed_sk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expand_sk_RSDPG(e_bar, e_G_bar, V_tr, W_mat, (uint8_t*) seed_sk);
    print_V_tr(V_tr);
    print_W_mat(W_mat);
    print_e_bar(e_bar);
    print_e_G_bar(e_G_bar);
    return;
}
void expand_pk_RSDP(FP_ELEM V_tr[K][N-K],
    const uint8_t seed_pk[KEYPAIR_SEED_LENGTH_BYTES]){

// Expansion of pk->seed, explicit domain separation for CSPRNG as in keygen
const uint16_t dsc_csprng_seed_pk = CSPRNG_DOMAIN_SEP_CONST + (3*T+2);

CSPRNG_STATE_T csprng_state_mat;
csprng_initialize(&csprng_state_mat, seed_pk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
csprng_fp_mat(V_tr,&csprng_state_mat);
}

void test_expand_pk_RSDP(){
    printf("Testing expand_pk\n");
    FP_ELEM V_tr[K][N-K];
    const char * restrict seed_pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expand_pk_RSDP(V_tr, (uint8_t*) seed_pk);
    print_V_tr(V_tr);
    return;
}

void expand_sk_RSDP(FZ_ELEM e_bar[N],
    FP_ELEM V_tr[K][N-K],
    const uint8_t seed_sk[KEYPAIR_SEED_LENGTH_BYTES]){

uint8_t seed_e_seed_pk[2][KEYPAIR_SEED_LENGTH_BYTES];

// Expansion of sk->seed, explicit domain separation for CSPRNG, as in keygen
const uint16_t dsc_csprng_seed_sk = CSPRNG_DOMAIN_SEP_CONST + (3*T+1);

CSPRNG_STATE_T csprng_state;
csprng_initialize(&csprng_state, seed_sk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_sk);
csprng_randombytes((uint8_t *)seed_e_seed_pk,
          2*KEYPAIR_SEED_LENGTH_BYTES,
          &csprng_state);

expand_pk_RSDP(V_tr,seed_e_seed_pk[1]);
//Expansion of seede, explicit domain separation for CSPRNG as in keygen
const uint16_t dsc_csprng_seed_e = CSPRNG_DOMAIN_SEP_CONST + (3*T+3);

CSPRNG_STATE_T csprng_state_e_bar;
csprng_initialize(&csprng_state_e_bar, seed_e_seed_pk[0], KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_e);
csprng_fz_vec(e_bar,&csprng_state_e_bar);
}

*/

/*
void test_expand_sk_RSDP(){
    printf("Testing expand_sk\n");
    FZ_ELEM e_bar[N];
    FP_ELEM V_tr[K][N-K];
    const char * restrict seed_sk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expand_sk_RSDP(e_bar, V_tr, (uint8_t*) seed_sk);
    //print_V_tr(V_tr);
    //print_z_vec(e_bar);
    return;
}

void print_pk(FZ_ELEM s[DENSELY_PACKED_FP_SYN_SIZE]){
    printf("s:\n");
    for (int i = 0; i < DENSELY_PACKED_FP_SYN_SIZE; i++) {
        printf("%u, ", s[i]);
    }
    printf("\n");
    return;
}

void test_keygen_RSDP(){
    const char * restrict seed_sk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    sk_t *SK = malloc(sizeof(sk_t));    
    pk_t *PK = malloc(sizeof(pk_t));    
    memcpy(SK->seed_sk, seed_sk, 32);

    uint8_t seed_e_seed_pk[2][KEYPAIR_SEED_LENGTH_BYTES];
    const uint16_t dsc_csprng_seed_sk = CSPRNG_DOMAIN_SEP_CONST + (3*T+1);
      
    CSPRNG_STATE_T csprng_state;
    csprng_initialize(&csprng_state, SK->seed_sk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_sk);
    csprng_randombytes((uint8_t *)seed_e_seed_pk,
                        2*KEYPAIR_SEED_LENGTH_BYTES,
                        &csprng_state);
    memcpy(PK->seed_pk,seed_e_seed_pk[1],KEYPAIR_SEED_LENGTH_BYTES);
    FP_ELEM V_tr[K][N-K];
    expand_pk_RSDP(V_tr,PK->seed_pk);
    const uint16_t dsc_csprng_seed_e = CSPRNG_DOMAIN_SEP_CONST + (3*T+3);
    CSPRNG_STATE_T csprng_state_e_bar;
    csprng_initialize(&csprng_state_e_bar, seed_e_seed_pk[0], KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_e);

    FZ_ELEM e_bar[N];
    csprng_fz_vec(e_bar,&csprng_state_e_bar);
    FP_ELEM s[N-K];
    restr_vec_by_fp_matrix(s,e_bar,V_tr);
    fp_dz_norm_synd(s);
    pack_fp_syn(PK->s,s);
    print_pk(PK->s);
}



void expand_pk_RSDPG(FP_ELEM V_tr[K][N-K],
               FZ_ELEM W_mat[M][N-M],
               const uint8_t seed_pk[KEYPAIR_SEED_LENGTH_BYTES]){

  // Expansion of pk->seed, explicit domain separation for CSPRNG as in keygen
  const uint16_t dsc_csprng_seed_pk = CSPRNG_DOMAIN_SEP_CONST + (3*T+2);

  CSPRNG_STATE_T csprng_state_mat;
  csprng_initialize(&csprng_state_mat, seed_pk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
  //print_csprng_state(&csprng_state_mat, sizeof(csprng_state_mat));
  csprng_fz_mat(W_mat,&csprng_state_mat);
  //print_csprng_state(&csprng_state_mat, sizeof(csprng_state_mat));
  csprng_fp_mat(V_tr,&csprng_state_mat);
  //print_csprng_state(&csprng_state_mat, sizeof(csprng_state_mat));
}
void print_s_RSDPG(uint16_t s[N-K]){
    printf("s:\n");
    for (int i = 0; i < N-K; i++) {
        printf("%u, ", s[i]);
    }
    printf("\n");
    return;
}


//TODO: Implement this!!!
void test_keygen_RSDPG(){
    const unsigned char seed_sk[] = {231, 221, 225, 64, 121, 143, 37, 241, 138, 71, 192, 51, 249, 204, 213, 132, 238, 169, 90, 166, 30, 38, 152, 213, 77, 73, 128, 111, 48, 71, 21, 189};
    sk_t *SK = malloc(sizeof(sk_t));    
    pk_t *PK = malloc(sizeof(pk_t));    
    memcpy(SK->seed_sk, seed_sk, 32);

    uint8_t seed_e_seed_pk[2][KEYPAIR_SEED_LENGTH_BYTES];
    const uint16_t dsc_csprng_seed_sk = CSPRNG_DOMAIN_SEP_CONST + (3*T+1);
      
    CSPRNG_STATE_T csprng_state;
    csprng_initialize(&csprng_state, SK->seed_sk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_sk);
    csprng_randombytes((uint8_t *)seed_e_seed_pk,
                        2*KEYPAIR_SEED_LENGTH_BYTES,
                        &csprng_state);
    memcpy(PK->seed_pk,seed_e_seed_pk[1],KEYPAIR_SEED_LENGTH_BYTES);
    FP_ELEM V_tr[K][N-K];
    FZ_ELEM W_mat[M][N-M];
    expand_pk_RSDPG(V_tr, W_mat,PK->seed_pk);

    const uint16_t dsc_csprng_seed_e = CSPRNG_DOMAIN_SEP_CONST + (3*T+3);
    CSPRNG_STATE_T csprng_state_e_bar;
    csprng_initialize(&csprng_state_e_bar, seed_e_seed_pk[0], KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_e);

    FZ_ELEM e_G_bar[M];
    FZ_ELEM e_bar[N];
    csprng_fz_inf_w(e_G_bar,&csprng_state_e_bar);
    fz_inf_w_by_fz_matrix(e_bar,e_G_bar,W_mat);
    //print_e_bar(e_bar);
    fz_dz_norm_n(e_bar);
    //print_e_bar(e_bar);
    FP_ELEM s[N-K];
    //print_V_tr(V_tr);
    restr_vec_by_fp_matrix(s,e_bar,V_tr);
    print_s_RSDPG(s);
    fp_dz_norm_synd(s);
    print_s_RSDPG(s);
    pack_fp_syn(PK->s,s);
    print_pk(PK->s);
}

void FP_ELEM_CMOV_test(){
    FP_ELEM BIT = 1;
    FP_ELEM TRUE_V = 384;
    FP_ELEM FALSE_V = 1;
    printf("BIT: %u\n", BIT);
    printf("TRUE_V: %u\n", TRUE_V);
    printf("FALSE_V: %u\n", FALSE_V);
    printf("Mask: %u\n", ((FP_ELEM)0 - (BIT)));
    printf("First part: %u\n", (((FP_ELEM)0 - (BIT)) & (TRUE_V)));
    printf("Second part: %u\n", (~((FP_ELEM)0 - (BIT)) & (FALSE_V)));
    printf("result: %u\n",(((FP_ELEM)0 - (BIT)) & (TRUE_V)) | (~((FP_ELEM)0 - (BIT)) & (FALSE_V)));
    //return (((FP_ELEM)0 - (BIT)) & (TRUE_V)) | (~((FP_ELEM)0 - (BIT)) & (FALSE_V));
    }


void FPRED_SINGLE_test(){
    uint16_t x = 3000;
    printf("x*2160140723: %u\n", (uint64_t)(x) * 2160140723);
    printf("After bitshift %u\n", (((uint64_t)(x) * 2160140723) >> 40));
    printf("Final: %u\n", (((x) - (((uint64_t)(x) * 2160140723) >> 40) * P)));
    }

void RESTR_TO_VAL_test(){
    uint16_t x = 44;
    uint32_t res1, res2, res3, res4;
    res1 = ( FP_ELEM_CMOV(((x >> 0) &1),RESTR_G_GEN_1 ,1)) *
           ( FP_ELEM_CMOV(((x >> 1) &1),RESTR_G_GEN_2 ,1)) ;
    res2 = ( FP_ELEM_CMOV(((x >> 2) &1),RESTR_G_GEN_4 ,1)) *
           ( FP_ELEM_CMOV(((x >> 3) &1),RESTR_G_GEN_8 ,1)) ;
    res3 = ( FP_ELEM_CMOV(((x >> 4) &1),RESTR_G_GEN_16,1)) *
           ( FP_ELEM_CMOV(((x >> 5) &1),RESTR_G_GEN_32,1)) ;
    res4 =   FP_ELEM_CMOV(((x >> 6) &1),RESTR_G_GEN_64,1);
    printf("res1 = %u\n",res1);
    printf("res2 = %u\n",res2);
    printf("res3 = %u\n",res3);
    printf("res4 = %u\n",res4);
    // * Two intermediate reductions necessary:
    // *     RESTR_G_GEN_1*RESTR_G_GEN_2*RESTR_G_GEN_4*RESTR_G_GEN_8    < 2^32
    // *     RESTR_G_GEN_16*RESTR_G_GEN_32*RESTR_G_GEN_64               < 2^32 
    printf("res1 * res2 = %u\n", res1 * res2);
    printf("lhs: %u\n", FPRED_SINGLE(res1 * res2));
    printf("res3 * res4 = %u\n", res3 * res4);
    printf("rhs: %u\n", FPRED_SINGLE(res3 * res4));
    printf("combined: %u\n", FPRED_SINGLE(res1 * res2) * FPRED_SINGLE(res3 * res4));
    printf("result %u \n", FPRED_SINGLE( FPRED_SINGLE(res1 * res2) * FPRED_SINGLE(res3 * res4) ));
}
*/

void print_array(uint8_t array[], int length) {
    for (int i = 0; i < length; i++) {
        printf("%u, ", array[i]);
    }
    printf("\n");
}

void print_pk(FZ_ELEM s[DENSELY_PACKED_FP_SYN_SIZE]){
    printf("s:\n");
    for (int i = 0; i < DENSELY_PACKED_FP_SYN_SIZE; i++) {
        printf("%u, ", s[i]);
    }
    printf("\n");
    return;
}

int main() {
    //test_hash();
    //test_csprng();
    //test_csprng_fp_mat();
    //test_csprng_fz_vec();
    //test_csprng_fp_vec();
    //test_csprng_fp_vec_chall_1();
    //test_expand_digest_to_fixed_weight();
    //test_expand_pk_RSDP();
    //test_expand_sk_RSDP();
    //test_expand_sk_RSDPG();
    //test_keygen_RSDPG();
    //FPRED_SINGLE_test();
    //FP_ELEM_CMOV_test();
    //RESTR_TO_VAL_test();
    /*for (int i = 0; i < 20; i++) {
        sk_t *SK = malloc(sizeof(sk_t));
        pk_t *PK = malloc(sizeof(pk_t));
        CROSS_keygen(SK, PK);
        printf("seed_SK: \n");
        print_array(SK->seed_sk, KEYPAIR_SEED_LENGTH_BYTES);
        printf("seed_PK: \n");
        print_array(PK->seed_pk, KEYPAIR_SEED_LENGTH_BYTES);
        printf("PK->s: \n");
        print_pk(PK->s);
    }*/
    return 0;
}