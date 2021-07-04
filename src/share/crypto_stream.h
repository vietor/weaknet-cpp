#pragma once

#include "crypto.h"

class StreamCrypto : Crypto
{
  friend class CryptoCreator;

  struct CipherStreamKey {
    unsigned int key_size;
    unsigned int iv_size;
    unsigned char key[CIPHER_MAX_KEY_SIZE];
    unsigned char encode_iv[CIPHER_MAX_IV_SIZE];
    unsigned char decode_iv[CIPHER_MAX_IV_SIZE];
  };

 protected:
  StreamCrypto(unsigned int cipher, CipherKey *cipher_key);
  ~StreamCrypto();

 public:
  int Encrypt(evbuffer *buf, evbuffer *&out);
  int Decrypt(evbuffer *buf, evbuffer *&out);

 private:
  static unsigned char *GetHelperBuffer(size_t size);

  bool en_init_ = false;
  bool de_init_ = false;
  size_t en_bytes_ = 0;
  size_t de_bytes_ = 0;
  unsigned int cipher_ = 0;
  CipherStreamKey cipher_stream_key_;
  static std::vector<unsigned char> help_buffer_;
};
