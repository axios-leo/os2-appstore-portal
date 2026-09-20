// =============================================================================
// os2/platform/hash.hpp — 密码学摘要原语（SHA-256 / HMAC-SHA256，FIPS 180-4）
// 自包含零依赖实现，供安全管理器（验签/审计链）与应用商店（制品摘要）等共用。
// M1.1 自 security-mgr impl 下沉（跨模块只允许经 platform 共享工具，边界铁律）。
// =============================================================================
#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace os2::hash {

inline std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

inline std::array<std::uint8_t, 32> sha256(const std::string& data) {
  static constexpr std::uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  std::array<std::uint32_t, 8> h = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  std::string msg = data;
  const std::uint64_t bitlen = static_cast<std::uint64_t>(data.size()) * 8;
  msg.push_back(static_cast<char>(0x80));
  while (msg.size() % 64 != 56) msg.push_back('\0');
  for (int i = 7; i >= 0; --i) msg.push_back(static_cast<char>((bitlen >> (i * 8)) & 0xff));

  for (std::size_t off = 0; off < msg.size(); off += 64) {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
      const auto* p = reinterpret_cast<const std::uint8_t*>(msg.data() + off + i * 4);
      w[i] = (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) |
             (std::uint32_t(p[2]) << 8) | p[3];
    }
    for (int i = 16; i < 64; ++i) {
      const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    auto [a, b, c, d, e, f, g, hh] = h;
    for (int i = 0; i < 64; ++i) {
      const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const std::uint32_t ch = (e & f) ^ (~e & g);
      const std::uint32_t t1 = hh + S1 + ch + K[i] + w[i];
      const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const std::uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t t2 = S0 + mj;
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  std::array<std::uint8_t, 32> out{};
  for (int i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<std::uint8_t>(h[i] >> 24);
    out[i * 4 + 1] = static_cast<std::uint8_t>(h[i] >> 16);
    out[i * 4 + 2] = static_cast<std::uint8_t>(h[i] >> 8);
    out[i * 4 + 3] = static_cast<std::uint8_t>(h[i]);
  }
  return out;
}

inline std::string hex(const std::array<std::uint8_t, 32>& d) {
  static const char* t = "0123456789abcdef";
  std::string s;
  s.reserve(64);
  for (auto b : d) { s.push_back(t[b >> 4]); s.push_back(t[b & 0xf]); }
  return s;
}

inline std::string sha256_hex(const std::string& data) { return hex(sha256(data)); }

inline std::string hmac_sha256_hex(const std::string& key, const std::string& msg) {
  std::string k = key.size() > 64 ? std::string(reinterpret_cast<const char*>(sha256(key).data()), 32)
                                  : key;
  k.resize(64, '\0');
  std::string ipad = k, opad = k;
  for (auto& c : ipad) c = static_cast<char>(c ^ 0x36);
  for (auto& c : opad) c = static_cast<char>(c ^ 0x5c);
  auto inner = sha256(ipad + msg);
  return sha256_hex(opad + std::string(reinterpret_cast<const char*>(inner.data()), 32));
}

}  // namespace os2::hash
