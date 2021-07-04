#include "crypto_stream.h"

static inline int crypto_stream_xor_ic(unsigned int cipher, unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n,
                                       uint64_t ic, const unsigned char *k)
{
  if (cipher == CHACHA20) {
    return crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k);
  } else if (cipher == CHACHA20_IETF) {
    return crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, ic, k);
  } else {
    return -1;
  }
}

std::vector<unsigned char> StreamCrypto::help_buffer_;

StreamCrypto::StreamCrypto(unsigned int cipher, CipherKey *cipher_key) : cipher_(cipher)
{
  memset(&cipher_stream_key_, 0, sizeof(cipher_stream_key_));
  cipher_stream_key_.key_size = cipher_key->key_size;
  cipher_stream_key_.iv_size = cipher_key->iv_size;
  memcpy(cipher_stream_key_.key, cipher_key->key, cipher_key->key_size);
  randombytes_buf(cipher_stream_key_.encode_iv, cipher_key->iv_size);
}

StreamCrypto::~StreamCrypto() {}

unsigned char *StreamCrypto::GetHelperBuffer(size_t size)
{
  if (size >= help_buffer_.size()) {
    help_buffer_.resize(size * 1.5);
  }
  return help_buffer_.data();
}

int StreamCrypto::Encrypt(evbuffer *buf, evbuffer *&out)
{
  size_t counter = en_bytes_ / SODIUM_BLOCK_SIZE;
  size_t padding = en_bytes_ % SODIUM_BLOCK_SIZE;
  size_t data_len = evbuffer_get_length(buf);
  size_t code_pos = 0, drain_len = padding;

  if (!en_init_) {
    if (padding > cipher_stream_key_.iv_size) {
      drain_len = padding - cipher_stream_key_.iv_size;
    } else {
      drain_len = 0;
      code_pos = cipher_stream_key_.iv_size - padding;
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

  evbuffer_iovec v;
  out = evbuffer_new();
  evbuffer_reserve_space(out, code_pos + code_len, &v, 1);

  crypto_stream_xor_ic(cipher_, (unsigned char *)v.iov_base + code_pos, code, code_len, cipher_stream_key_.encode_iv, counter, cipher_stream_key_.key);
  en_bytes_ += data_len;

  if (!en_init_) {
    en_init_ = true;
    memcpy((unsigned char *)v.iov_base + drain_len, cipher_stream_key_.encode_iv, cipher_stream_key_.iv_size);
  }

  v.iov_len = code_pos + code_len;
  evbuffer_commit_space(out, &v, 1);
  if (drain_len > 0) {
    evbuffer_drain(out, drain_len);
  }

  evbuffer_free(buf);
  return CRYPTO_OK;
}

int StreamCrypto::Decrypt(evbuffer *buf, evbuffer *&out)
{
  size_t counter = de_bytes_ / SODIUM_BLOCK_SIZE;
  size_t padding = de_bytes_ % SODIUM_BLOCK_SIZE;
  size_t data_len = evbuffer_get_length(buf);

  unsigned char *code = evbuffer_pullup(buf, data_len);
  if (!de_init_) {
    if (data_len < cipher_stream_key_.iv_size) {
      evbuffer_free(buf);
      return CRYPTO_ERROR;
    }

    de_init_ = true;
    memcpy(cipher_stream_key_.decode_iv, code, cipher_stream_key_.iv_size);
    code += cipher_stream_key_.iv_size;
    data_len -= cipher_stream_key_.iv_size;
  }

  size_t code_len = padding + data_len;
  if (padding) {
    unsigned char *cache = GetHelperBuffer(code_len);
    memset(cache, 0, padding);
    memcpy(cache + padding, code, data_len);
    code = cache;
  }

  evbuffer_iovec v;
  out = evbuffer_new();
  evbuffer_reserve_space(out, code_len, &v, 1);

  crypto_stream_xor_ic(cipher_, (unsigned char *)v.iov_base, code, code_len, cipher_stream_key_.decode_iv, counter, cipher_stream_key_.key);
  de_bytes_ += data_len;

  v.iov_len = code_len;
  evbuffer_commit_space(out, &v, 1);
  if (padding > 0) {
    evbuffer_drain(out, padding);
  }

  evbuffer_free(buf);
  return CRYPTO_OK;
}
