#include "crypto_aead.h"

#define CHUNK_SIZE_LEN 2
#define CHUNK_SIZE_MASK 0x3FFF
#define CHUNK_SIZE_SPLIT (CHUNK_SIZE_MASK / 2 * 2)

const unsigned char SUBKEY_INFO[] = "ss-subkey";

static inline int crypto_aead_encrypt(unsigned int cipher, unsigned char *c, unsigned long long *clen_p, const unsigned char *m, unsigned long long mlen,
                                      const unsigned char *npub, const unsigned char *k)
{
  if (cipher == CHACHA20_IETF_POLY1305) {
    return crypto_aead_chacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, NULL, 0, NULL, npub, k);
  } else {
    return -1;
  }
}

static inline int crypto_aead_decrypt(unsigned int cipher, unsigned char *m, unsigned long long *mlen_p, const unsigned char *c, unsigned long long clen,
                                      const unsigned char *npub, const unsigned char *k)
{
  if (cipher == CHACHA20_IETF_POLY1305) {
    return crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen_p, NULL, c, clen, NULL, 0, npub, k);
  } else {
    return -1;
  }
}

AeadCrypto::AeadCrypto(unsigned int cipher, CipherKey *cipher_key) : cipher_(cipher)
{
  memset(&cipher_aead_key_, 0, sizeof(cipher_aead_key_));
  cipher_aead_key_.key_size = cipher_key->key_size;
  cipher_aead_key_.iv_size = cipher_key->iv_size;
  cipher_aead_key_.tag_size = cipher_key->tag_size;
  memcpy(cipher_aead_key_.key, cipher_key->key, cipher_key->key_size);
  randombytes_buf(cipher_aead_key_.encode_salt, cipher_key->key_size);
  Crypto::HKDF_SHA1(cipher_aead_key_.encode_salt, cipher_key->key_size, cipher_aead_key_.key, cipher_key->key_size, SUBKEY_INFO, sizeof(SUBKEY_INFO),
                    cipher_aead_key_.encode_subkey, cipher_key->key_size);
}

AeadCrypto::~AeadCrypto()
{
  if (decode_cached_) {
    evbuffer_free(decode_cached_);
  }
}

int AeadCrypto::Encrypt(evbuffer *buf, evbuffer *&out)
{
  size_t source_pos = 0, source_len = evbuffer_get_length(buf);
  unsigned char *source_ptr = evbuffer_pullup(buf, source_len);

  size_t chunk_count = source_len / CHUNK_SIZE_SPLIT, last_chunk_len = source_len % CHUNK_SIZE_SPLIT;
  size_t target_pos = 0, target_len = (2 * cipher_aead_key_.tag_size + CHUNK_SIZE_LEN + CHUNK_SIZE_SPLIT) * chunk_count;
  if (last_chunk_len > 0) {
    chunk_count += 1;
    target_len += 2 * cipher_aead_key_.tag_size + CHUNK_SIZE_LEN + last_chunk_len;
  }
  if (!en_init_) {
    target_len += cipher_aead_key_.key_size;
  }

  evbuffer_iovec v;
  out = evbuffer_new();
  evbuffer_reserve_space(out, target_len, &v, 1);

  if (!en_init_) {
    en_init_ = true;
    memcpy((unsigned char *)v.iov_base + target_pos, cipher_aead_key_.encode_salt, cipher_aead_key_.key_size);
    target_pos += cipher_aead_key_.key_size;
  }

  unsigned short len;
  unsigned long long encrypt_len;
  size_t chunk_index, chunk_len;

  for (chunk_index = 1; chunk_index <= chunk_count; ++chunk_index) {
    chunk_len = chunk_index < chunk_count ? CHUNK_SIZE_SPLIT : last_chunk_len;

    len = htons(chunk_len);
    encrypt_len = CHUNK_SIZE_LEN + cipher_aead_key_.tag_size;
    crypto_aead_encrypt(cipher_, (unsigned char *)v.iov_base + target_pos, &encrypt_len, (unsigned char *)&len, CHUNK_SIZE_LEN, cipher_aead_key_.encode_iv,
                        cipher_aead_key_.encode_subkey);
    target_pos += encrypt_len;
    sodium_increment(cipher_aead_key_.encode_iv, cipher_aead_key_.iv_size);

    encrypt_len = chunk_len + cipher_aead_key_.tag_size;
    crypto_aead_encrypt(cipher_, (unsigned char *)v.iov_base + target_pos, &encrypt_len, source_ptr + source_pos, chunk_len, cipher_aead_key_.encode_iv,
                        cipher_aead_key_.encode_subkey);
    target_pos += encrypt_len;
    sodium_increment(cipher_aead_key_.encode_iv, cipher_aead_key_.iv_size);

    source_pos += chunk_len;
  }

  v.iov_len = target_len;
  evbuffer_commit_space(out, &v, 1);

  evbuffer_free(buf);
  return CRYPTO_OK;
}

int AeadCrypto::Decrypt(evbuffer *buf, evbuffer *&out)
{
  if (decode_cached_) {
    evbuffer_add_buffer(decode_cached_, buf);
    evbuffer_free(buf);
    buf = decode_cached_;
    decode_cached_ = nullptr;
  }

  size_t source_pos = 0, source_len = evbuffer_get_length(buf);
  unsigned char *source_ptr = evbuffer_pullup(buf, source_len);

  if (!de_init_) {
    if (source_len < cipher_aead_key_.key_size) {
      evbuffer_free(buf);
      out = nullptr;
      return CRYPTO_ERROR;
    }

    de_init_ = true;
    memcpy(cipher_aead_key_.decode_salt, source_ptr + source_pos, cipher_aead_key_.key_size);
    Crypto::HKDF_SHA1(cipher_aead_key_.decode_salt, cipher_aead_key_.key_size, cipher_aead_key_.key, cipher_aead_key_.key_size, SUBKEY_INFO,
                      sizeof(SUBKEY_INFO), cipher_aead_key_.decode_subkey, cipher_aead_key_.key_size);

    source_pos += cipher_aead_key_.key_size;
  }

  evbuffer_iovec v;
  out = evbuffer_new();

  unsigned short len;
  unsigned long long decrypt_len;
  size_t drain_len = source_pos;
  int err = 0, last = CRYPTO_NEED_NORE;

  while (1) {
    if (source_len - source_pos < CHUNK_SIZE_LEN + cipher_aead_key_.tag_size) {
      last = CRYPTO_NEED_NORE;
      break;
    }

    decrypt_len = CHUNK_SIZE_LEN;
    err = crypto_aead_decrypt(cipher_, (unsigned char *)&len, &decrypt_len, source_ptr + source_pos, CHUNK_SIZE_LEN + cipher_aead_key_.tag_size,
                              cipher_aead_key_.decode_iv, cipher_aead_key_.decode_subkey);
    if (err) {
      last = CRYPTO_ERROR;
      break;
    }

    len = ntohs(len);
    source_pos += CHUNK_SIZE_LEN + cipher_aead_key_.tag_size;
    if (source_len - source_pos < len + cipher_aead_key_.tag_size) {
      last = CRYPTO_NEED_NORE;
      break;
    }
    sodium_increment(cipher_aead_key_.decode_iv, cipher_aead_key_.iv_size);

    evbuffer_reserve_space(out, len, &v, 1);

    decrypt_len = len;
    err = crypto_aead_decrypt(cipher_, (unsigned char *)v.iov_base, &decrypt_len, source_ptr + source_pos, len + cipher_aead_key_.tag_size,
                              cipher_aead_key_.decode_iv, cipher_aead_key_.decode_subkey);

    v.iov_len = len;
    evbuffer_commit_space(out, &v, 1);

    if (err) {
      last = CRYPTO_ERROR;
      break;
    }

    source_pos += len + cipher_aead_key_.tag_size;
    sodium_increment(cipher_aead_key_.decode_iv, cipher_aead_key_.iv_size);

    drain_len = source_pos;
    if (drain_len == source_len) {
      last = CRYPTO_OK;
      break;
    }
  }

  if (last != CRYPTO_NEED_NORE) {
    evbuffer_free(buf);
    if (last == CRYPTO_ERROR) {
      evbuffer_free(out);
      out = nullptr;
    }
  } else {
    if (drain_len > 0) {
      evbuffer_drain(buf, drain_len);
      decode_cached_ = buf;
    }

    if (evbuffer_get_length(out) > 0) {
      last = CRYPTO_OK;
    }
  }

  return last;
}
