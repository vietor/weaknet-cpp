#include "stream.h"

#include <openssl/md5.h>
#include <sodium/utils.h>

#define SODIUM_BLOCK_SIZE 64

enum StreamCipherMode { CHACHA20 = 0, CHACHA20_IETF };

struct StreamCipherInfo {
  const char *name;
  unsigned int cipher;
  unsigned int key_size;
  unsigned int iv_size;
};

StreamCipherInfo supported_ciphers[] = {{"chacha20", CHACHA20, crypto_stream_chacha20_KEYBYTES, crypto_stream_chacha20_NONCEBYTES},
                                        {"chacha20-ietf", CHACHA20_IETF, crypto_stream_chacha20_ietf_KEYBYTES, crypto_stream_chacha20_ietf_NONCEBYTES}};

static void DeriveCipherKey(CipherKey *out, const char *password, unsigned int key_size, unsigned int iv_size)
{
  MD5_CTX md;
  unsigned int i, j, addmd;
  size_t password_len = strlen(password);
  unsigned char md_buf[MD5_DIGEST_LENGTH];

  memset(out, 0, sizeof(*out));
  out->key_size = key_size;
  out->iv_size = iv_size;
  for (j = 0, addmd = 0; j < key_size; addmd++) {
    MD5_Init(&md);
    if (addmd) {
      MD5_Update(&md, md_buf, MD5_DIGEST_LENGTH);
    }
    MD5_Update(&md, password, password_len);
    MD5_Final(md_buf, &md);

    for (i = 0; i < MD5_DIGEST_LENGTH; i++, j++) {
      if (j >= key_size) break;
      out->key[j] = md_buf[i];
    }
  }
}

StreamCrypto::StreamCrypto() {}
StreamCrypto::~StreamCrypto() {}

void StreamCrypto::Release() { delete this; }

std::vector<unsigned char> StreamBasicCrypto::help_buffer_;

StreamBasicCrypto::StreamBasicCrypto(unsigned int cipher, CipherKey *cipher_key) : cipher_(cipher)
{
  memset(&cipher_node_key_, 0, sizeof(cipher_node_key_));
  cipher_node_key_.key_size = cipher_key->key_size;
  cipher_node_key_.iv_size = cipher_key->iv_size;
  memcpy(cipher_node_key_.key, cipher_key->key, CIPHER_MAX_KEY_SIZE);
  randombytes_buf(cipher_node_key_.encode_iv, cipher_key->iv_size);
}

StreamBasicCrypto::~StreamBasicCrypto() {}

unsigned char *StreamBasicCrypto::GetHelperBuffer(size_t size)
{
  if (size >= help_buffer_.size()) {
    help_buffer_.resize(size * 1.5);
  }
  return help_buffer_.data();
}

int StreamBasicCrypto::Encrypt(evbuffer *buf, evbuffer *&out)
{
  size_t counter = en_bytes_ / SODIUM_BLOCK_SIZE;
  size_t padding = en_bytes_ % SODIUM_BLOCK_SIZE;
  size_t data_len = evbuffer_get_length(buf);
  size_t code_pos = 0, drain_len = padding;

  if (!en_iv_) {
    if (padding > cipher_node_key_.iv_size) {
      drain_len = padding - cipher_node_key_.iv_size;
    } else {
      drain_len = 0;
      code_pos = cipher_node_key_.iv_size - padding;
    }
  }

  size_t code_len = padding + data_len;
  unsigned char *code = evbuffer_pullup(buf, data_len);
  if (padding) {
    unsigned char *cache = GetHelperBuffer(code_len);
    memset(cache, 0, padding);
    memcpy(cache + padding, code, data_len);
    code = cache;
  }

  struct evbuffer_iovec v;
  out = evbuffer_new();
  evbuffer_reserve_space(out, code_pos + code_len, &v, 1);
  if (cipher_ == CHACHA20) {
    crypto_stream_chacha20_xor_ic((unsigned char *)v.iov_base + code_pos, code, code_len, cipher_node_key_.encode_iv, counter, cipher_node_key_.key);
  } else {
    crypto_stream_chacha20_ietf_xor_ic((unsigned char *)v.iov_base + code_pos, code, code_len, cipher_node_key_.encode_iv, counter, cipher_node_key_.key);
  }
  if (!en_iv_) {
    en_iv_ = true;
    memcpy((unsigned char *)v.iov_base + drain_len, cipher_node_key_.encode_iv, cipher_node_key_.iv_size);
  }
  en_bytes_ += data_len;

  v.iov_len = code_pos + code_len;
  evbuffer_commit_space(out, &v, 1);
  if (drain_len > 0) {
    evbuffer_drain(out, drain_len);
  }
  return CRYPTO_OK;
}

int StreamBasicCrypto::Decrypt(evbuffer *buf, evbuffer *&out)
{
  size_t counter = de_bytes_ / SODIUM_BLOCK_SIZE;
  size_t padding = de_bytes_ % SODIUM_BLOCK_SIZE;
  size_t data_len = evbuffer_get_length(buf);

  unsigned char *code = evbuffer_pullup(buf, data_len);
  if (!de_iv_) {
    if (data_len < cipher_node_key_.iv_size) {
      return CRYPTO_ERROR;
    }

    de_iv_ = true;
    memcpy(cipher_node_key_.decode_iv, code, cipher_node_key_.iv_size);
    code += cipher_node_key_.iv_size;
    data_len -= cipher_node_key_.iv_size;
  }

  size_t code_len = padding + data_len;
  if (padding) {
    unsigned char *cache = GetHelperBuffer(code_len);
    memset(cache, 0, padding);
    memcpy(cache + padding, code, data_len);
    code = cache;
  }

  struct evbuffer_iovec v;
  out = evbuffer_new();
  evbuffer_reserve_space(out, code_len, &v, 1);
  if (cipher_ == CHACHA20) {
    crypto_stream_chacha20_xor_ic((unsigned char *)v.iov_base, code, code_len, cipher_node_key_.decode_iv, counter, cipher_node_key_.key);
  } else {
    crypto_stream_chacha20_ietf_xor_ic((unsigned char *)v.iov_base, code, code_len, cipher_node_key_.decode_iv, counter, cipher_node_key_.key);
  }
  de_bytes_ += data_len;

  v.iov_len = code_len;
  evbuffer_commit_space(out, &v, 1);
  if (padding > 0) {
    evbuffer_drain(out, padding);
  }
  return CRYPTO_OK;
}

StreamCipher::StreamCipher() {}

StreamCipher::~StreamCipher() {}

StreamCrypto *StreamCipher::NewCrypto() { return new StreamBasicCrypto(cipher_, &cipher_key_); };

StreamCipher *StreamCipher::NewInstance(const char *algorithm, const char *password)
{
  StreamCipherInfo *info = nullptr;
  for (size_t i = 0; i < sizeof(supported_ciphers) / sizeof(supported_ciphers[0]); ++i) {
    if (strcmp(algorithm, supported_ciphers[i].name) == 0) {
      info = &supported_ciphers[i];
      break;
    }
  }

  if (!info) return nullptr;

  StreamCipher *out = new StreamCipher();
  out->cipher_ = info->cipher;
  DeriveCipherKey(&out->cipher_key_, password, info->key_size, info->iv_size);
  return out;
}
