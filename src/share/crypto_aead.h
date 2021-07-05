#pragma once

#include "crypto.h"

class AeadCrypto : Crypto {
  friend class CryptoCreator;

  struct CipherAeadKey {
    unsigned int key_size;
    unsigned int iv_size;
    unsigned int tag_size;
    unsigned char key[CIPHER_MAX_KEY_SIZE];
    unsigned char encode_iv[CIPHER_MAX_IV_SIZE];
    unsigned char decode_iv[CIPHER_MAX_IV_SIZE];
    unsigned char encode_salt[CIPHER_MAX_KEY_SIZE];
    unsigned char decode_salt[CIPHER_MAX_KEY_SIZE];
    unsigned char encode_subkey[CIPHER_MAX_KEY_SIZE];
    unsigned char decode_subkey[CIPHER_MAX_KEY_SIZE];
  };

 protected:
  AeadCrypto(unsigned int cipher, CipherKey *cipher_key);
  ~AeadCrypto();

 public:
  int Encrypt(evbuffer *buf, evbuffer *&out);
  int Decrypt(evbuffer *buf, evbuffer *&out);

 private:
  bool en_init_ = false;
  bool de_init_ = false;
  unsigned int cipher_ = 0;
  CipherAeadKey cipher_aead_key_;
  evbuffer *decode_cached_ = nullptr;
};
