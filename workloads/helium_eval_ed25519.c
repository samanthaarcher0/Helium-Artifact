#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h> 
#include <string.h>

#include "eval_util.h"

#define EXPECTED_ARGC 2
#define MSG_ARG_IDX 1

extern int sodium_init(void);
extern size_t crypto_sign_secretkeybytes(void);
extern size_t crypto_sign_publickeybytes(void);
extern size_t crypto_sign_bytes(void);
extern int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
extern int crypto_sign(unsigned char *sm, unsigned long long *smlen_p,
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char *sk);
extern int crypto_sign_open(unsigned char *m, unsigned long long *mlen_p,
			    const unsigned char *sm, unsigned long long smlen,
			    const unsigned char *pk);

int
main(int argc, char** argv)
{
  if (argc < EXPECTED_ARGC) {
    printf("Usage: %s <message>\n", argv[0]);
    exit(-1);
  }

  unsigned char* msg = (unsigned char*)argv[MSG_ARG_IDX];
  unsigned long long msg_sz = strlen(argv[MSG_ARG_IDX]);

  // allocate space for opened message
  unsigned char* opened_msg = malloc(msg_sz);
  assert(opened_msg && "Couldn't allocate opened_msg bytes in eval_ed25519.c");

  // allocate space for signed message buffer
  unsigned long long signed_msg_sz = msg_sz + crypto_sign_bytes();
  unsigned char* signed_msg = malloc(signed_msg_sz);
  assert(msg && "Couldn't allocate signed msg bytes in eval_ed25519.c");
    
  // allocate space for secret and private keys
  int privk_size = crypto_sign_secretkeybytes();
  int pubk_size = crypto_sign_publickeybytes();
  unsigned char* privk = malloc(privk_size);
  unsigned char* pubk = malloc(pubk_size);
  printf("privk_size: %d\n", privk_size);
  printf("pubk_size: %d\n", pubk_size);

  // generate private key
  // generate public key
  int _eval_unused = crypto_sign_keypair(/*public=*/ pubk, /*secret=*/ privk);

  // sign the message
  int sign_result = crypto_sign(/*signed msg buf=*/ signed_msg,
				/*signed msg sz=*/ &signed_msg_sz,
				/*msg buf=*/ msg,
				/*msg sz=*/ msg_sz,
				/*secret key=*/ privk);

  return 0;
}
