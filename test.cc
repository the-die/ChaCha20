#include "chacha.h"

int main() {
  TestChaChaQuarterRound();
  TestChaChaQuarterRoundOnChaChaState();
  TestChaChaBlock();
  TestChaChaEncrypt();
  TestChaChaDecrypt();
  return 0;
}