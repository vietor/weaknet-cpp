#pragma once

#include <sodium.h>
#include <string.h>

#include <memory>
#include <string>
#include <vector>

#include "debug.h"
#include "network.h"

enum {
  CRYPTO_ERROR = -1,
  CRYPTO_OK,
  CRYPTO_NEED_NORE,
};

#define SODIUM_BLOCK_SIZE 64

#define CIPHER_MAX_KEY_SIZE 64
#define CIPHER_MAX_IV_SIZE 32
#define CIPHER_MAX_TAG_SIZE 32

struct CipherKey {
  unsigned int key_size;
  unsigned int iv_size;
  unsigned int tag_size;
  unsigned char key[CIPHER_MAX_KEY_SIZE];
};
enum CryptoCipher { CHACHA20 = 0, CHACHA20_IETF, CHACHA20_IETF_POLY1305, XCHACHA20_IETF_POLY1305 };

class Crypto
{
 protected:
  Crypto();
  virtual ~Crypto() = 0;

 public:
  virtual void Release();

  virtual int Encrypt(evbuffer *buf, evbuffer *&out) = 0;
  virtual int Decrypt(evbuffer *buf, evbuffer *&out) = 0;

  static void HKEY_MD5(const char *password, unsigned char *key, unsigned int key_size);
  static void HKDF_SHA1(const unsigned char *salt, int salt_len, const unsigned char *ikm, int ikm_len, const unsigned char *info, int info_len,
                        unsigned char *okm, int okm_len);
};

class CryptoCreator
{
 public:
  Crypto *NewCrypto();

  static bool Init(std::string &error);
  static CryptoCreator *NewInstance(const char *algorithm, const char *password);

 private:
  CryptoCreator();
  ~CryptoCreator();

  unsigned int cipher_;
  CipherKey cipher_key_;
};
