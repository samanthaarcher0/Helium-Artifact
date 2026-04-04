#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h> 
#include <string.h>

#include "eval_util.h"

#define EXPECTED_ARGC 3
#define PASSWD_ARG_IDX 1
#define OUT_SIZE_ARG_IDX 2

extern int sodium_init(void);
extern void randombytes_buf(void * const buf, const size_t size);
extern size_t crypto_pwhash_saltbytes(void);
extern size_t crypto_pwhash_passwd_min(void);
extern size_t crypto_pwhash_passwd_max(void);
extern size_t crypto_pwhash_bytes_min(void);
extern size_t crypto_pwhash_bytes_max(void);
extern unsigned long long crypto_pwhash_opslimit_interactive(void);
extern unsigned long long crypto_pwhash_memlimit_interactive(void);
extern int crypto_pwhash_alg_argon2id13(void);
extern int crypto_pwhash(unsigned char * const out, unsigned long long outlen,
                         const char * const passwd, unsigned long long passwdlen,
                         const unsigned char * const salt,
                         unsigned long long opslimit, size_t memlimit, int alg);

int
main(int argc, char** argv)
{
  if (argc < EXPECTED_ARGC) {
    printf("Usage: %s <password> <size_of_output>\n", argv[0]);
    exit(-1);
  }

  // passwd_sz must be between PASSWD_MIN and PASSWD_MAX (inclusive)
  unsigned char* passwd = (unsigned char*)argv[PASSWD_ARG_IDX];
  unsigned long long passwd_sz = strlen(argv[PASSWD_ARG_IDX]);
  assert(passwd_sz >= crypto_pwhash_passwd_min() &&
    "Password size is less than min in eval_argon2id.c");
  assert(passwd_sz <= crypto_pwhash_passwd_max() &&
    "Password size is greater than max in eval_argon2id.c");

  // out_sz must be between BYTES_MIN and BYTES_MAX (inclusive)
  unsigned long long out_sz = strtol(argv[OUT_SIZE_ARG_IDX], (char**) NULL, 10);
  assert(out_sz >= crypto_pwhash_bytes_min() &&
    "Output size is less than min in eval_argon2id.c");
  assert(out_sz <= crypto_pwhash_bytes_max() &&
    "Output size is greater than max in eval_argon2id.c");

  // allocate space for output
  unsigned char* out = malloc(out_sz);
  assert(out && "Couldn't allocate output bytes in eval_argon2id.c");

  // allocate space for salt
  int salt_size = crypto_pwhash_saltbytes();
  unsigned char* salt = malloc(salt_size);
  assert(salt && "Couldn't allocate salt bytes in eval_argon2id.c");

  // set ops limit
  unsigned long long opslimit = crypto_pwhash_opslimit_interactive();

  // set mem limit
  unsigned long long memlimit = crypto_pwhash_memlimit_interactive();

  // set hashing algorithm (argon2id)
  int alg = crypto_pwhash_alg_argon2id13();

  // generate salt
  //randombytes_buf(salt, sizeof salt);
  unsigned char fixed_salt[16] = {0xaf, 0x6e, 0x02, 0x33, 0xe5, 0x2b, 0xeb, 0x3f, 0x8b, 0x13, 0x42, 0x24, 0x2d, 0x23, 0x16, 0xf3};
  if (salt_size >= 16) {
      memcpy(salt, fixed_salt, 16);
  } else {
      fprintf(stderr, "Salt size (%d) is smaller than 16 bytes!\n", salt_size);
      exit(1);
  }

  // generate output
  int pwhash_result = crypto_pwhash(out, out_sz, (const char*)passwd, passwd_sz,
          salt, opslimit, memlimit, alg);

  return 0;
}
