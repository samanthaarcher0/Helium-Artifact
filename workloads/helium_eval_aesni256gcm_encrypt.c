#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>

#include "eval_util.h"

#define EXPECTED_ARGC 2
#define MSG_ARG_IDX 1
#define AD_SIZE_ARG_IDX 2

extern int strncmp(const char *str1, const char *str2, size_t n);
extern size_t crypto_aead_aes256gcm_keybytes(void);
extern size_t crypto_aead_aes256gcm_npubbytes(void);
extern size_t crypto_aead_aes256gcm_abytes(void);
extern int sodium_init();
extern void randombytes_buf(void * const buf, const size_t size);
extern int crypto_aead_aes256gcm_is_available(void);
extern int crypto_aead_aes256gcm_keygen(unsigned char *k);
extern int crypto_aead_aes256gcm_encrypt(unsigned char *c,
          unsigned long long *clen_p, const unsigned char *m,
          unsigned long long m_len, const unsigned char *ad,
          unsigned long long ad_len, const unsigned char *nsec,
          const unsigned char *npub, const unsigned char *k);
extern int crypto_aead_aes256gcm_decrypt(unsigned char *m,
          unsigned long long *mlen_p, unsigned char *nsec,
          const unsigned char *c, unsigned long long clen,
          const unsigned char *ad, unsigned long long adlen,
          const unsigned char *npub, const unsigned char *k);

int
main(int argc, char** argv)
{
  if (argc < EXPECTED_ARGC) {
    printf("Usage: %s <message> <size_of_associated_data>\n", argv[0]);
    exit(-1);
  }

  unsigned char* msg = (unsigned char*)argv[MSG_ARG_IDX];
  unsigned long long msg_sz = strlen(argv[MSG_ARG_IDX]);
  unsigned long long additional_data_sz = 0; // strtol(argv[AD_SIZE_ARG_IDX], (char**) NULL, 10);

  // Make sure AES is available
  // assert(crypto_aead_aes256gcm_is_available() && "AES not available on this CPU");

  /// allocate space for additional data
  unsigned char* additional_data = NULL; // malloc(additional_data_sz);
  // assert(additional_data && "Couldn't allocate msg bytes in eval_aesni256gcm_decrypt.c");

  // allocate space for decrypted message
  unsigned char* decrypted_msg = malloc(msg_sz);
  assert(decrypted_msg &&
    "Couldn't allocate decrypted_msg bytes in eval_aesni256gcm_encrypt.c");

  // allocate space for ciphertext
  unsigned long long ciphertext_sz = msg_sz + crypto_aead_aes256gcm_abytes();
  unsigned char* ciphertext = malloc(ciphertext_sz);
  assert(msg && "Couldn't allocate ciphertext bytes in eval_aesni256gcm_encrypt.c");

  // allocate space for key
  int key_size = crypto_aead_aes256gcm_keybytes();
  unsigned char* key = malloc(key_size);
  assert(key && "Couldn't allocate key bytes in eval_aesni256gcm_encrypt.c");

  // allocate space for noncei
  int nonce_size = crypto_aead_aes256gcm_npubbytes();
  unsigned char* nonce = malloc(nonce_size);
  assert(nonce && "Couldn't allocate key bytes in eval_aesni256gcm_encrypt.c");

  printf("key_size: %d\n", key_size);
  printf("nonce_size: %d\n", nonce_size);
  // generate key
  // generate nonce
  crypto_aead_aes256gcm_keygen(key);
  //randombytes_buf(nonce, sizeof nonce);

  unsigned char fixed_nonce[12] = {0x74, 0x02, 0xaf, 0x8e, 0x90, 0xe4,0xe5, 0xb9, 0xab, 0xb3, 0x66, 0xf7};
  if (nonce_size >= 12) {
      memcpy(nonce, fixed_nonce, 12);
  } else {
      fprintf(stderr, "Nonce size (%d) is smaller than 12 bytes!\n", nonce_size);
      exit(1);
  }


  // encrypt message
  int encrypt_result = crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_sz,
        msg, msg_sz, additional_data, additional_data_sz, NULL, nonce, key);

  return 0;
}
