#pragma once

#include <sodium.h>

#include <vector>

#include "network.h"

#define CIPHER_MAX_IV_SIZE 16
#define CIPHER_MAX_KEY_SIZE 32

struct CipherKey {
  unsigned int key_size;
  unsigned int iv_size;
  unsigned char key[CIPHER_MAX_KEY_SIZE];
  unsigned char iv[CIPHER_MAX_IV_SIZE];
};

struct CipherNodeKey {
  unsigned int key_size;
  unsigned int iv_size;
  unsigned char key[CIPHER_MAX_KEY_SIZE];
  unsigned char encode_iv[CIPHER_MAX_IV_SIZE];
  unsigned char decode_iv[CIPHER_MAX_IV_SIZE];
};

class StreamCrypto
{
  friend class StreamCipher;

 public:
  void Release();

  evbuffer *Encrypt(evbuffer *buf);
  evbuffer *Decrypt(evbuffer *buf);

 private:
  StreamCrypto(unsigned int cipher, CipherKey *cipher_key);
  ~StreamCrypto();

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

  static StreamCipher *NewInstance(const char *algorithm, const char *password);

 private:
  StreamCipher();
  ~StreamCipher();

  unsigned int cipher_;
  CipherKey cipher_key_;
};
