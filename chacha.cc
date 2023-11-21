#include "chacha.h"

#include <array>    // array
#include <climits>  // CHAR_BIT
#include <cstddef>  // size_t
#include <cstdint>  // uint32_t, uint8_t
#include <cstring>  // strlen, memcpy, memcmp
#include <string>   // string
#include <vector>   // vector

// The ChaCha20 Encryption Algorithm
// https://datatracker.ietf.org/doc/html/rfc8439

std::uint32_t ChaCha::u8tou32l(const std::uint8_t* n) {
  uint32_t res = 0;
  res |= (std::uint32_t)n[0];
  res |= (std::uint32_t)n[1] << 8;
  res |= (std::uint32_t)n[2] << 16;
  res |= (std::uint32_t)n[3] << 24;
  return res;
}

ChaCha::ChaCha(const std::array<std::uint8_t, kKeySize>& key,
               const std::array<std::uint8_t, kNonceSize>& nonce,
               std::uint32_t counter) {
  std::memcpy(key_, key.data(), sizeof(key_));
  std::memcpy(nonce_, nonce.data(), sizeof(nonce_));
  counter_ = counter;
  Init();
}

// https://en.wikipedia.org/wiki/Circular_shift
std::uint32_t ChaCha::rotl32(std::uint32_t value, std::size_t count) {
  std::size_t mask = CHAR_BIT * sizeof(value) - 1;
  count &= mask;
  return (value << count) | (value >> (-count & mask));
}

// see rotl32
std::uint32_t ChaCha::rotr32(std::uint32_t value, std::size_t count) {
  std::size_t mask = CHAR_BIT * sizeof(value) - 1;
  count &= mask;
  return (value >> count) | (value << (-count & mask));
}

// a += b; d ^= a; d <<<= 16;
// c += d; b ^= c; b <<<= 12;
// a += b; d ^= a; d <<<= 8;
// c += d; b ^= c; b <<<= 7;
// Where "+" denotes integer addition modulo 2^32, "^" denotes a bitwise
// Exclusive OR (XOR), and "<<< n" denotes an n-bit left roll (towards the high
// bits).
void ChaCha::QuarterRound(std::uint32_t* input, std::size_t a, std::size_t b,
                          std::size_t c, std::size_t d) {
  input[a] += input[b];
  input[d] = rotl32(input[d] ^ input[a], 16);
  input[c] += input[d];
  input[b] = rotl32(input[b] ^ input[c], 12);
  input[a] += input[b];
  input[d] = rotl32(input[d] ^ input[a], 8);
  input[c] += input[d];
  input[b] = rotl32(input[b] ^ input[c], 7);
}

// cccccccc  cccccccc  cccccccc  cccccccc
// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
// bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
//
// c=constant k=key b=blockcount n=nonce
void ChaCha::Init() {
  // The first four words (0-3) are constants: 0x61707865, 0x3320646e,
  // 0x79622d32, 0x6b206574.
  init_state_[0] = 0x61707865U;
  init_state_[1] = 0x3320646eU;
  init_state_[2] = 0x79622d32U;
  init_state_[3] = 0x6b206574U;

  // The next eight words (4-11) are taken from the 256-bit key by reading the
  // bytes in little-endian order, in 4-byte chunks.
  for (std::size_t i = 0; i < 8; ++i) {
    init_state_[i + 4] = u8tou32l(key_ + sizeof(std::uint32_t) * i);
  }

  // Word 12 is a block counter.  Since each block is 64-byte, a 32-bit word is
  // enough for 256 gigabytes of data.
  init_state_[kStateCounterIdx] = counter_;

  // Words 13-15 are a nonce, which MUST not be repeated for the same key. The
  // 13th word is the first 32 bits of the input nonce taken as a little-endian
  // integer, while the 15th word is the last 32 bits.
  init_state_[13] = u8tou32l(nonce_);
  init_state_[14] = u8tou32l(nonce_ + 4);
  init_state_[15] = u8tou32l(nonce_ + 8);
}

void ChaCha::Block() {
  std::memcpy(state_, init_state_, sizeof(init_state_));

  // ChaCha20 runs 20 rounds, alternating between "column rounds" and "diagonal
  // rounds". Each round consists of four quarter-rounds, and they are run as
  // follows.
  for (std::size_t i = 0; i < kIteration; ++i) {
    // column rounds
    QuarterRound(state_, 0, 4, 8, 12);
    QuarterRound(state_, 1, 5, 9, 13);
    QuarterRound(state_, 2, 6, 10, 14);
    QuarterRound(state_, 3, 7, 11, 15);
    // diagonal rounds
    QuarterRound(state_, 0, 5, 10, 15);
    QuarterRound(state_, 1, 6, 11, 12);
    QuarterRound(state_, 2, 7, 8, 13);
    QuarterRound(state_, 3, 4, 9, 14);
  }

  for (std::size_t i = 0; i < kStateSize; ++i) {
    state_[i] += init_state_[i];
  }

  ++init_state_[kStateCounterIdx];

  // serialize?
}

std::vector<std::uint8_t> ChaCha::Encrypt(const char* plaintext) {
  return Encrypt(plaintext, std::strlen(plaintext));
}

#define CHACHA_XOR(x, y, z)                \
  for (std::size_t i = 0; i < size; ++i) { \
    if (pos_ >= 64) {                      \
      Block();                             \
      pos_ = 0;                            \
    }                                      \
    x.push_back(y[i] ^ z[pos_]);           \
    ++pos_;                                \
  }

std::vector<std::uint8_t> ChaCha::Encrypt(const char* plaintext,
                                          std::size_t size) {
  std::vector<std::uint8_t> ciphertext;
  auto key_stream = reinterpret_cast<std::uint8_t*>(state_);
  ciphertext.reserve(size);
  CHACHA_XOR(ciphertext, plaintext, key_stream);
  return ciphertext;
}

std::vector<std::uint8_t> ChaCha::Encrypt(const std::string& plaintext) {
  return Encrypt(plaintext.data(), plaintext.size());
}

std::string ChaCha::Decrypt(const std::uint8_t* ciphertext, std::size_t size) {
  std::string plaintext;
  auto key_stream = reinterpret_cast<std::uint8_t*>(state_);
  plaintext.reserve(size);
  CHACHA_XOR(plaintext, ciphertext, key_stream);
  return plaintext;
}

#if (CHACHA_TEST > 0)
#include <cassert>  // assert
#include <cstdio>   // printf

void TestChaChaQuarterRound() {
  std::uint32_t vector[4] = {0x11111111U, 0x01020304U, 0x9b8d6f43U,
                             0x01234567U};
  ChaCha::QuarterRound(vector, 0, 1, 2, 3);
  assert(vector[0] == 0xea2a92f4U);
  assert(vector[1] == 0xcb1cf8ceU);
  assert(vector[2] == 0x4581472eU);
  assert(vector[3] == 0x5881c4bbU);
  printf("%s: OK\n", __func__);
}

void TestChaChaQuarterRoundOnChaChaState() {
  std::uint32_t vector[16]{
      0x879531e0U, 0xc5ecf37dU, 0x516461b1U, 0xc9a62f8a,
      0x44c20ef3U, 0x3390af7fU, 0xd9fc690bU, 0x2a5f714cU,
      0x53372767U, 0xb00a5631U, 0x974c541aU, 0x359e9963U,
      0x5c971061U, 0x3d631689U, 0x2098d9d6U, 0x91dbd320U,
  };
  ChaCha::QuarterRound(vector, 2, 7, 8, 13);
  assert(vector[0] == 0x879531e0U);
  assert(vector[1] == 0xc5ecf37dU);
  assert(vector[2] == 0xbdb886dcU);
  assert(vector[3] == 0xc9a62f8aU);
  assert(vector[4] == 0x44c20ef3U);
  assert(vector[5] == 0x3390af7fU);
  assert(vector[6] == 0xd9fc690bU);
  assert(vector[7] == 0xcfacafd2U);
  assert(vector[8] == 0xe46bea80U);
  assert(vector[9] == 0xb00a5631U);
  assert(vector[10] == 0x974c541aU);
  assert(vector[11] == 0x359e9963U);
  assert(vector[12] == 0x5c971061U);
  assert(vector[13] == 0xccc07c79U);
  assert(vector[14] == 0x2098d9d6U);
  assert(vector[15] == 0x91dbd320U);
  printf("%s: OK\n", __func__);
}

void TestChaChaBlock() {
  std::array<std::uint8_t, ChaCha::kKeySize> key = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  std::array<std::uint8_t, ChaCha::kNonceSize> nonce = {
      0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
  };
  std::uint32_t counter = 1;
  ChaCha chacha(key, nonce, counter);

  assert(chacha.init_state_[0] == 0x61707865U);
  assert(chacha.init_state_[1] == 0x3320646eU);
  assert(chacha.init_state_[2] == 0x79622d32U);
  assert(chacha.init_state_[3] == 0x6b206574U);
  assert(chacha.init_state_[4] == 0x03020100U);
  assert(chacha.init_state_[5] == 0x07060504U);
  assert(chacha.init_state_[6] == 0x0b0a0908U);
  assert(chacha.init_state_[7] == 0x0f0e0d0cU);
  assert(chacha.init_state_[8] == 0x13121110U);
  assert(chacha.init_state_[9] == 0x17161514U);
  assert(chacha.init_state_[10] == 0x1b1a1918U);
  assert(chacha.init_state_[11] == 0x1f1e1d1cU);
  assert(chacha.init_state_[12] == 0x00000001U);
  assert(chacha.init_state_[13] == 0x09000000U);
  assert(chacha.init_state_[14] == 0x4a000000U);
  assert(chacha.init_state_[15] == 0x00000000U);

  chacha.Block();

  assert(chacha.state_[0] == 0xe4e7f110U);
  assert(chacha.state_[1] == 0x15593bd1U);
  assert(chacha.state_[2] == 0x1fdd0f50U);
  assert(chacha.state_[3] == 0xc47120a3U);
  assert(chacha.state_[4] == 0xc7f4d1c7U);
  assert(chacha.state_[5] == 0x0368c033U);
  assert(chacha.state_[6] == 0x9aaa2204U);
  assert(chacha.state_[7] == 0x4e6cd4c3U);
  assert(chacha.state_[8] == 0x466482d2U);
  assert(chacha.state_[9] == 0x09aa9f07U);
  assert(chacha.state_[10] == 0x05d7c214U);
  assert(chacha.state_[11] == 0xa2028bd9U);
  assert(chacha.state_[12] == 0xd19c12b5U);
  assert(chacha.state_[13] == 0xb94e16deU);
  assert(chacha.state_[14] == 0xe883d0cbU);
  assert(chacha.state_[15] == 0x4e3c50a2U);

  std::uint8_t serialized_block[] = {
      0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd,
      0x1f, 0xa3, 0x20, 0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0,
      0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e, 0xd2,
      0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05,
      0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e,
      0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
  };

  assert(sizeof(chacha.state_) == sizeof(serialized_block));
  assert(std::memcmp(chacha.state_, serialized_block,
                     sizeof(serialized_block)) == 0);
  printf("%s: OK\n", __func__);
}

void TestChaChaEncrypt() {
  std::array<std::uint8_t, ChaCha::kKeySize> key = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  std::array<std::uint8_t, ChaCha::kNonceSize> nonce = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
  };
  std::uint32_t counter = 1;
  ChaCha chacha(key, nonce, counter);

  std::string plaintext =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one "
      "tip for the future, sunscreen would be it.";
  auto ciphertext = chacha.Encrypt(plaintext);
  std::uint8_t data[] = {
      0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28,
      0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
      0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5,
      0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
      0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
      0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
      0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
      0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
      0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed,
      0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d,
  };
  assert(sizeof(data) == ciphertext.size());
  assert(std::memcmp(data, ciphertext.data(), sizeof(data)) == 0);
  printf("%s: OK\n", __func__);
}

void TestChaChaDecrypt() {
  std::array<std::uint8_t, ChaCha::kKeySize> key = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  std::array<std::uint8_t, ChaCha::kNonceSize> nonce = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
  };
  std::uint32_t counter = 1;
  ChaCha chacha(key, nonce, counter);

  std::uint8_t ciphertext[] = {
      0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28,
      0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
      0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5,
      0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
      0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
      0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
      0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
      0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
      0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed,
      0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d,
  };
  std::string plaintext =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one "
      "tip for the future, sunscreen would be it.";
  auto data = chacha.Decrypt(ciphertext, sizeof(ciphertext));
  assert(data == plaintext);
  printf("%s: OK\n", __func__);
}
#endif
