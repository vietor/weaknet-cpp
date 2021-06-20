#pragma once

#include <string.h>

#include <memory>
#include <string>
#include <vector>

#include "debug.h"
#include "network.h"

#define CIPHER_MAX_IV_SIZE 16
#define CIPHER_MAX_KEY_SIZE 32

enum {
  CRYPTO_ERROR = -1,
  CRYPTO_OK,
  CRYPTO_NEED_NORE,
};

struct CipherKey {
  unsigned int key_size;
  unsigned int iv_size;
  unsigned char key[CIPHER_MAX_KEY_SIZE];
};

class StreamCrypto
{
 protected:
  StreamCrypto();
  virtual ~StreamCrypto() = 0;

 public:
  virtual void Release();

  virtual int Encrypt(evbuffer *buf, evbuffer *&out) = 0;
  virtual int Decrypt(evbuffer *buf, evbuffer *&out) = 0;
};

class StreamBasicCrypto : StreamCrypto
{
  friend class StreamCipher;

  struct CipherNodeKey {
    unsigned int key_size;
    unsigned int iv_size;
    unsigned char key[CIPHER_MAX_KEY_SIZE];
    unsigned char encode_iv[CIPHER_MAX_IV_SIZE];
    unsigned char decode_iv[CIPHER_MAX_IV_SIZE];
  };

 protected:
  StreamBasicCrypto(unsigned int cipher, CipherKey *cipher_key);
  ~StreamBasicCrypto();

 public:
  int Encrypt(evbuffer *buf, evbuffer *&out);
  int Decrypt(evbuffer *buf, evbuffer *&out);

 private:
  static unsigned char *GetHelperBuffer(size_t size);

  bool en_iv_ = false;
  size_t en_bytes_ = 0;
  bool de_iv_ = false;
  size_t de_bytes_ = 0;
  unsigned int cipher_ = 0;
  CipherNodeKey cipher_node_key_;
  static std::vector<unsigned char> help_buffer_;
};

class StreamCipher
{
 public:
  StreamCrypto *NewCrypto();

  static bool Init(std::string &error);
  static StreamCipher *NewInstance(const char *algorithm, const char *password);

 private:
  StreamCipher();
  ~StreamCipher();

  unsigned int cipher_;
  CipherKey cipher_key_;
};
