#include <chrono>    // chrono::*
#include <iostream>  // cout

#include "chacha.h"

namespace {
auto gettime() { return std::chrono::steady_clock::now(); }

template <typename T>
auto duration(const T& start, const T& end) {
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start)
      .count();
}
}  // namespace

int main() {
  auto t1 = gettime();
  TestChaChaQuarterRound();
  TestChaChaQuarterRoundOnChaChaState();
  TestChaChaBlock();
  TestChaChaEncrypt();
  TestChaChaDecrypt();
  auto v1 = duration(t1, gettime());
  std::cout << "time: " << v1 << "us\n";
  return 0;
}
