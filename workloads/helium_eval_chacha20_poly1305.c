#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h> 
#include <string.h> 

#include "eval_util.h"

#define EXPECTED_ARGC 2
#define MSG_ARG_IDX 1

extern int sodium_init();
extern size_t crypto_aead_chacha20poly1305_ietf_npubbytes(void);
extern size_t crypto_aead_chacha20poly1305_ietf_keybytes(void);
extern size_t crypto_aead_chacha20poly1305_ietf_abytes(void);
extern int crypto_aead_chacha20poly1305_ietf_encrypt(
    unsigned char *c, unsigned long long *clen_p, const unsigned char *m,
    unsigned long long mlen, const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub,
    const unsigned char *k);
extern int crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char *m,
          unsigned long long *mlen_p, unsigned char *nsec,
          const unsigned char *c, unsigned long long clen,
          const unsigned char *ad, unsigned long long adlen,
          const unsigned char *npub, const unsigned char *k);
extern void crypto_aead_chacha20poly1305_ietf_keygen(unsigned char *);

int
main(int argc, char** argv)
{
  if (argc < EXPECTED_ARGC) {
    printf("Usage: %s <message>\n", argv[0]);
    exit(-1);
  }

  
  // init libsodium, must be called before other libsodium functions are called
  const int sodium_init_success = 0;
  const int sodium_already_initd = 1;
//  int sodium_init_result = sodium_init();
//  assert((sodium_init_success == sodium_init_result ||
//	  sodium_already_initd == sodium_init_result) &&
//	 "Error initializing lib sodium");

  unsigned char* msg = (unsigned char*)argv[MSG_ARG_IDX];
  unsigned long long msg_sz = strlen(argv[MSG_ARG_IDX]);

  // allocate space for opened message
  printf("msg size: %llu\n", msg_sz);
  unsigned char* opened_msg = malloc(msg_sz);
  assert(opened_msg && "Couldn't allocate opened_msg bytes in eval_chacha20-poly1305-encrypt.c");

  // allocate space for additional data
  int additional_data_sz = 0;
  unsigned char* additional_data = NULL; // malloc(additional_data_sz);
  // assert(additional_data && "Couldn't allocate msg bytes in eval_aesni256gcm_encrypt.c");

  // allocate space for signed message buffer
  unsigned long long ciphertext_sz = msg_sz + crypto_aead_chacha20poly1305_ietf_abytes();
  unsigned char* ciphertext = malloc(ciphertext_sz);
  assert(msg && "Couldn't allocate signed msg bytes in eval_chacha20-poly1305-encrypt.c");
    
  // allocate space for secret and private keys
  int key_size = crypto_aead_chacha20poly1305_ietf_keybytes();
  unsigned char* privk = malloc(key_size);
  printf("key_size: %d\n", key_size);
  assert(privk && "Couldn't allocate private key bytes in eval_chacha20-poly1305-encrypt.c");


  // allocate space for decrypted message
  unsigned char* decrypted_msg = malloc(msg_sz);
  assert(decrypted_msg &&
    "Couldn't allocate decrypted_msg bytes in eval_chacha20-poly1305-encrypt.c");

  // allocate space for nonce
  int nonce_size = crypto_aead_chacha20poly1305_ietf_npubbytes();
  unsigned char* nonce = malloc(nonce_size);
  printf("nonce_size %d\n", nonce_size);

  // generate private key
  crypto_aead_chacha20poly1305_ietf_keygen(privk);

  // generate nonce
  //ciocc_eval_rand_fill_buf(nonce, sizeof nonce);
  unsigned char fixed_nonce[12] = {0x74, 0x02, 0xaf, 0x8e, 0x90, 0xe4,0xe5, 0xb9, 0xab, 0xb3, 0x66, 0xf7};
  if (nonce_size >= 12) {
      memcpy(nonce, fixed_nonce, 12);
  } else {
      fprintf(stderr, "Nonce size (%d) is smaller than 12 bytes!\n", nonce_size);
      exit(1);
  }

  int encrypt_result = crypto_aead_chacha20poly1305_ietf_encrypt(
        /*signed msg buf=*/ciphertext,
        /*signed msg sz=*/&ciphertext_sz,
        /*msg buf=*/msg,
        /*msg sz=*/msg_sz,
        /*additional data=*/additional_data,
        /*additional data sz=*/additional_data_sz, NULL, nonce, privk);

  return 0;
}
