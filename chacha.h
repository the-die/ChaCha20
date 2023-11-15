#ifndef CHACHA_H_
#define CHACHA_H_

#include <cstddef>  // size_t
#include <cstdint>  // uint32_t, uint8_t
#include <string>   // string
#include <vector>   // vector

// The ChaCha20 Encryption Algorithm
// https://datatracker.ietf.org/doc/html/rfc8439
class ChaCha {
  friend void TestChaChaQuarterRound();
  friend void TestChaChaQuarterRoundOnChaChaState();
  friend void TestChaChaBlock();
  friend void TestChaChaEncrypt();
  friend void TestChaChaDecrypt();

 public:
  ChaCha(const std::uint8_t* key, const std::uint8_t* nonce,
         std::uint32_t counter);

  std::vector<std::uint8_t> Encrypt(const char* plaintext);

  std::vector<std::uint8_t> Encrypt(const char* plaintext, std::size_t size);

  std::vector<std::uint8_t> Encrypt(const std::string& plaintext);

  std::string Decrypt(const std::uint8_t* cipher, std::size_t size);

 private:
  static constexpr std::size_t kKeySize = 32;
  static constexpr std::size_t kNonceSize = 16;
  static constexpr std::size_t kStateSize = 16;
  static constexpr std::size_t kStateCounterIdx = 12;
  static constexpr std::size_t kIteration = 10;

  static std::uint32_t u8tou32l(const std::uint8_t* n);

  static std::uint32_t rotl32(std::uint32_t value, std::size_t count);

  static std::uint32_t rotr32(std::uint32_t value, std::size_t count);

  static void QuarterRound(std::uint32_t* input, std::size_t a, std::size_t b,
                           std::size_t c, std::size_t d);

  void Init();

  void Block();

  // A 256-bit key, treated as a concatenation of eight 32-bit little-endian
  // integers.
  std::uint8_t key_[kKeySize];

  // A 96-bit nonce, treated as a concatenation of three 32-bit little-endian
  // integers.
  std::uint8_t nonce_[kNonceSize];

  // A 32-bit block count parameter, treated as a 32-bit little-endian integer.
  std::uint32_t counter_;

  std::uint32_t init_state_[kStateSize];
  std::uint32_t state_[kStateSize];

  std::size_t pos_ = -1;
};

void TestChaChaQuarterRound();
void TestChaChaQuarterRoundOnChaChaState();
void TestChaChaBlock();
void TestChaChaEncrypt();
void TestChaChaDecrypt();

#endif  // CHACHA_H_
