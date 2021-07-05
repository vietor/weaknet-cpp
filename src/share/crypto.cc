#include "crypto.h"

#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "crypto_aead.h"
#include "crypto_stream.h"

struct CryptoCreatorInfo {
  const char *name;
  unsigned int cipher;
  unsigned int key_size;
  unsigned int iv_size;
  unsigned int tag_size;
};

CryptoCreatorInfo supported_ciphers[] = {{"chacha20", CHACHA20, 32, 8, 0},
                                         {"chacha20-ietf", CHACHA20_IETF, 32, 12, 0},
                                         {"chacha20-ietf-poly1305", CHACHA20_IETF_POLY1305, 32, 12, 16},
                                         {"xchacha20-ietf-poly1305", XCHACHA20_IETF_POLY1305, 32, 24, 16}};

Crypto::Crypto() {}
Crypto::~Crypto() {}

void Crypto::Release() { delete this; }

void Crypto::HKEY_MD5(const char *password, unsigned char *key, unsigned int key_size)
{
  MD5_CTX md;
  unsigned int i, j, addmd;
  size_t password_len = strlen(password);
  unsigned char md_buf[MD5_DIGEST_LENGTH];

  for (j = 0, addmd = 0; j < key_size; addmd++) {
    MD5_Init(&md);
    if (addmd) {
      MD5_Update(&md, md_buf, MD5_DIGEST_LENGTH);
    }
    MD5_Update(&md, password, password_len);
    MD5_Final(md_buf, &md);

    for (i = 0; i < MD5_DIGEST_LENGTH; i++, j++) {
      if (j >= key_size) break;
      key[j] = md_buf[i];
    }
  }
}

void Crypto::HKDF_SHA1(const unsigned char *salt, int salt_len, const unsigned char *ikm, int ikm_len, const unsigned char *info, int info_len,
                       unsigned char *okm, int okm_len)
{
  unsigned int len;
  unsigned char prk[SHA_DIGEST_LENGTH], md[SHA_DIGEST_LENGTH];

  HMAC_CTX *ctx = HMAC_CTX_new();

  HMAC_Init_ex(ctx, salt, salt_len, EVP_sha1(), NULL);
  HMAC_Update(ctx, ikm, ikm_len);
  HMAC_Final(ctx, prk, &len);

  int N = okm_len / SHA_DIGEST_LENGTH;
  if ((okm_len % SHA_DIGEST_LENGTH) != 0) {
    N++;
  }

  for (int i = 1, where = 0; i <= N; i++) {
    unsigned char c = i;

    HMAC_CTX_reset(ctx);
    HMAC_Init_ex(ctx, prk, SHA_DIGEST_LENGTH, EVP_sha1(), NULL);
    if (i > 1) {
      HMAC_Update(ctx, md, SHA_DIGEST_LENGTH);
    }
    HMAC_Update(ctx, info, info_len);
    HMAC_Update(ctx, &c, 1);
    HMAC_Final(ctx, md, &len);

    memcpy(okm + where, md, (i != N) ? SHA_DIGEST_LENGTH : (okm_len - where));
    where += SHA_DIGEST_LENGTH;
  }

  HMAC_CTX_free(ctx);
}

CryptoCreator::CryptoCreator() {}

CryptoCreator::~CryptoCreator() {}

Crypto *CryptoCreator::NewCrypto()
{
  if (cipher_key_.tag_size > 0)
    return new AeadCrypto(cipher_, &cipher_key_);
  else
    return new StreamCrypto(cipher_, &cipher_key_);
};

bool CryptoCreator::Init(std::string &error)
{
  if (sodium_init()) {
    error = "incredible: sodium_init error";
    return false;
  }
  return true;
}

CryptoCreator *CryptoCreator::NewInstance(const char *algorithm, const char *password)
{
  CryptoCreatorInfo *info = nullptr;
  for (size_t i = 0; i < sizeof(supported_ciphers) / sizeof(supported_ciphers[0]); ++i) {
    if (strcmp(algorithm, supported_ciphers[i].name) == 0) {
      info = &supported_ciphers[i];
      break;
    }
  }

  if (!info) return nullptr;

  CryptoCreator *out = new CryptoCreator();
  out->cipher_ = info->cipher;
  memset(&out->cipher_key_, 0, sizeof(out->cipher_key_));
  out->cipher_key_.key_size = info->key_size;
  out->cipher_key_.iv_size = info->iv_size;
  out->cipher_key_.tag_size = info->tag_size;
  Crypto::HKEY_MD5(password, out->cipher_key_.key, info->key_size);
  return out;
}
