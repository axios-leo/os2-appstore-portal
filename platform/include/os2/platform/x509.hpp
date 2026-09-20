// =============================================================================
// os2/platform/x509.hpp — X.509 一期真逻辑 + 可插拔验签后端（选项 B，方案 ①）
// 依据：docs/security/X509_INSERVICE_PLAN.md（负责人 2026-07-17 核准）。
// 一期边界（如实）：本文件的"真"=PEM/DER 装载、最小 ASN.1 解析（CN/有效期/算法
// OID 提取）、有效期窗判定——纯 C++ 零依赖可证；RSA/ECDSA 数学本体不在此，
// 一律出 IVerifyBackend：宿主 openssl 进程委托（appstore 收编）/测试向量（单测）/
// mbedTLS（1.5期真件，OS2_WITH_MBEDTLS 切换点，壳子引用即编译错——FastDDS 同款）。
// 接口口径较方案草案微调：verify 走纯数据面（PEM/hex 内容而非文件路径）——
// 后端各自落地 I/O，接口可测性优先（已记方案更新记录）。
// =============================================================================
#pragma once

#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>  // environ（C linkage 声明）

#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace os2::x509 {

struct CertInfo {                  // 最小解析产物（一期真逻辑）
  std::string subject_cn, issuer_cn;
  std::uint64_t not_before_s{0}, not_after_s{0};  // epoch 秒（UTC）
  std::string pubkey_algo;         // rsa / ecdsa / unknown（OID 映射）
  bool parsed{false};
};

namespace detail {

inline std::vector<std::uint8_t> b64_decode(const std::string& in) {
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;  // 空白/换行/=/其他：跳过或终止由调用侧语义决定
  };
  std::vector<std::uint8_t> out;
  int buf = 0, bits = 0;
  for (char c : in) {
    if (c == '=') break;
    const int v = val(c);
    if (v < 0) continue;  // 容忍 PEM 折行空白
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((buf >> bits) & 0xff));
    }
  }
  return out;
}

struct Cur {                       // DER 游标（越界即 ok=false，解析整体判失败）
  const std::uint8_t* p{nullptr};
  std::size_t n{0}, off{0};
  bool ok{true};
  std::uint8_t peek_tag() const { return off < n ? p[off] : 0; }
  // 读 TLV 头：返回内容区起点与长度；长形长度 ≤4 字节（证书足够）
  bool tlv(std::uint8_t& tag, std::size_t& len, std::size_t& content) {
    if (!ok || off + 2 > n) return ok = false;
    tag = p[off++];
    std::size_t l = p[off++];
    if (l & 0x80) {
      const std::size_t cnt = l & 0x7f;
      if (cnt == 0 || cnt > 4 || off + cnt > n) return ok = false;
      l = 0;
      for (std::size_t i = 0; i < cnt; ++i) l = (l << 8) | p[off++];
    }
    if (off + l > n) return ok = false;
    content = off;
    len = l;
    return true;
  }
  Cur enter(std::size_t content, std::size_t len) const {  // 下钻子结构
    Cur c;
    c.p = p;
    c.n = content + len;
    c.off = content;
    c.ok = ok;
    return c;
  }
  void skip() {                    // 跳过一个 TLV
    std::uint8_t t;
    std::size_t l, c;
    if (tlv(t, l, c)) off = c + l;
  }
};

// Hinnant days_from_civil：公历 → 1970 起天数（无时区库依赖）
inline std::int64_t days_from_civil(int y, unsigned m, unsigned d) {
  y -= m <= 2;
  const int era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return static_cast<std::int64_t>(era) * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

// UTCTime(YYMMDDHHMMSSZ) / GeneralizedTime(YYYYMMDDHHMMSSZ) → epoch 秒；0=解析失败
inline std::uint64_t asn1_time(std::uint8_t tag, const std::uint8_t* s, std::size_t len) {
  auto dig = [&](std::size_t i) { return s[i] >= '0' && s[i] <= '9' ? s[i] - '0' : -1; };
  auto num2 = [&](std::size_t i) {
    const int a = dig(i), b = dig(i + 1);
    return a < 0 || b < 0 ? -1 : a * 10 + b;
  };
  int year = 0;
  std::size_t o = 0;
  if (tag == 0x17 && len >= 13) {          // UTCTime：YY<50 → 20YY，否则 19YY（RFC5280）
    const int yy = num2(0);
    if (yy < 0) return 0;
    year = yy < 50 ? 2000 + yy : 1900 + yy;
    o = 2;
  } else if (tag == 0x18 && len >= 15) {   // GeneralizedTime：四位年
    const int hi = num2(0), lo = num2(2);
    if (hi < 0 || lo < 0) return 0;
    year = hi * 100 + lo;
    o = 4;
  } else {
    return 0;
  }
  const int mo = num2(o), dd = num2(o + 2), hh = num2(o + 4), mi = num2(o + 6), ss = num2(o + 8);
  if (mo < 1 || mo > 12 || dd < 1 || dd > 31 || hh < 0 || mi < 0 || ss < 0) return 0;
  const std::int64_t days = days_from_civil(year, static_cast<unsigned>(mo),
                                            static_cast<unsigned>(dd));
  if (days < 0) return 0;
  return static_cast<std::uint64_t>(days) * 86400 + hh * 3600 + mi * 60 + ss;
}

// Name(RDNSequence) 内取 CN（OID 2.5.4.3 = 55 04 03）
inline std::string name_cn(Cur name) {
  while (name.ok && name.off < name.n) {
    std::uint8_t t;
    std::size_t l, c;
    if (!name.tlv(t, l, c)) break;
    if (t == 0x31) {                       // SET
      Cur set = name.enter(c, l);
      std::uint8_t t2;
      std::size_t l2, c2;
      if (set.tlv(t2, l2, c2) && t2 == 0x30) {   // AttributeTypeAndValue SEQUENCE
        Cur atv = set.enter(c2, l2);
        std::uint8_t t3;
        std::size_t l3, c3;
        if (atv.tlv(t3, l3, c3) && t3 == 0x06 && l3 == 3 &&
            atv.p[c3] == 0x55 && atv.p[c3 + 1] == 0x04 && atv.p[c3 + 2] == 0x03) {
          atv.off = c3 + l3;
          std::uint8_t t4;
          std::size_t l4, c4;
          if (atv.tlv(t4, l4, c4))               // UTF8/Printable/T61/IA5 一律按字节取
            return std::string(reinterpret_cast<const char*>(atv.p + c4), l4);
        }
      }
    }
    name.off = c + l;
  }
  return {};
}

}  // namespace detail

// PEM 证书 → CertInfo。解析失败一律 parsed=false（无部分可信结果）。
inline CertInfo parse_pem_info(const std::string& pem) {
  CertInfo info;
  const std::string b = "-----BEGIN CERTIFICATE-----", e = "-----END CERTIFICATE-----";
  const auto bp = pem.find(b), ep = pem.find(e);
  if (bp == std::string::npos || ep == std::string::npos || ep <= bp) return info;
  const auto der = detail::b64_decode(pem.substr(bp + b.size(), ep - bp - b.size()));
  if (der.empty()) return info;
  detail::Cur root;
  root.p = der.data();
  root.n = der.size();
  std::uint8_t t;
  std::size_t l, c;
  if (!root.tlv(t, l, c) || t != 0x30) return info;   // Certificate SEQUENCE
  detail::Cur cert = root.enter(c, l);
  if (!cert.tlv(t, l, c) || t != 0x30) return info;   // TBSCertificate SEQUENCE
  detail::Cur tbs = cert.enter(c, l);
  if (tbs.peek_tag() == 0xa0) tbs.skip();             // [0] version（可选）
  tbs.skip();                                         // serialNumber
  tbs.skip();                                         // signature AlgorithmIdentifier
  if (!tbs.tlv(t, l, c) || t != 0x30) return info;    // issuer Name
  info.issuer_cn = detail::name_cn(tbs.enter(c, l));
  tbs.off = c + l;
  if (!tbs.tlv(t, l, c) || t != 0x30) return info;    // validity SEQUENCE
  {
    detail::Cur v = tbs.enter(c, l);
    std::uint8_t tt;
    std::size_t ll, cc;
    if (!v.tlv(tt, ll, cc)) return info;
    info.not_before_s = detail::asn1_time(tt, v.p + cc, ll);
    v.off = cc + ll;
    if (!v.tlv(tt, ll, cc)) return info;
    info.not_after_s = detail::asn1_time(tt, v.p + cc, ll);
  }
  tbs.off = c + l;
  if (!tbs.tlv(t, l, c) || t != 0x30) return info;    // subject Name
  info.subject_cn = detail::name_cn(tbs.enter(c, l));
  tbs.off = c + l;
  if (!tbs.tlv(t, l, c) || t != 0x30) return info;    // subjectPublicKeyInfo
  {
    detail::Cur spki = tbs.enter(c, l);
    std::uint8_t tt;
    std::size_t ll, cc;
    if (spki.tlv(tt, ll, cc) && tt == 0x30) {         // AlgorithmIdentifier
      detail::Cur alg = spki.enter(cc, ll);
      if (alg.tlv(tt, ll, cc) && tt == 0x06) {
        static const std::uint8_t kRsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
        static const std::uint8_t kEc[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
        auto eq = [&](const std::uint8_t* oid, std::size_t n) {
          if (ll != n) return false;
          for (std::size_t i = 0; i < n; ++i)
            if (alg.p[cc + i] != oid[i]) return false;
          return true;
        };
        info.pubkey_algo = eq(kRsa, sizeof(kRsa)) ? "rsa"
                           : eq(kEc, sizeof(kEc)) ? "ecdsa"
                                                  : "unknown";
      }
    }
  }
  if (info.not_before_s == 0 || info.not_after_s == 0) return info;  // 有效期必须解析成功
  info.parsed = true;
  return info;
}

inline bool valid_at(const CertInfo& c, std::uint64_t epoch_s) {
  return c.parsed && epoch_s >= c.not_before_s && epoch_s <= c.not_after_s;
}

// ---- 可插拔验签后端（RSA/ECDSA 数学本体的唯一出口）---------------------------
class IVerifyBackend {
 public:
  virtual ~IVerifyBackend() = default;
  // sig_hex 是否为 signer_cert_pem 对 digest_hex 的合法签名、且 signer 由 ca_cert_pem
  // 签发。纯数据面：PEM/hex 内容直传，I/O 由各后端自理。
  virtual bool verify(const std::string& digest_hex, const std::string& sig_hex,
                      const std::string& signer_cert_pem, const std::string& ca_cert_pem,
                      std::string& reason) = 0;
};

// 测试向量后端（仅 SIL 单测/测试 profile；交付基线禁用——baseline 规则拦截）：
// 预置 (digest_hex → sig_hex) 白名单，命中即过。零密码学、确定性。
class TestVectorBackend : public IVerifyBackend {
 public:
  explicit TestVectorBackend(std::map<std::string, std::string> vectors)
      : vectors_(std::move(vectors)) {}
  bool verify(const std::string& digest_hex, const std::string& sig_hex,
              const std::string&, const std::string&, std::string& reason) override {
    auto it = vectors_.find(digest_hex);
    if (it != vectors_.end() && it->second == sig_hex) return true;
    reason = "testvec: no matching vector for digest " + digest_hex;
    return false;
  }

 private:
  std::map<std::string, std::string> vectors_;
};

// ---- 宿主 openssl 进程委托（一期真件后端；F-06 去 shell 化同源口径）------------
// 共用核心：sh <script> <digest_hex> <sig_path> <cert_path> <ca_path>，argv 直传
// （无 shell 解析）、子进程 stdout/err → /dev/null。制品验签（appstore 文件面）与
// 命令门（数据面适配 SpawnScriptBackend）共用本核心=同一后端族，1.5期 mbedTLS
// 落地一次两处受益。返回：0=通过；-1=spawn 失败；>0=脚本退出码（2=链 3=签名）。
inline int spawn_verify_script(const std::string& script, const std::string& digest_hex,
                               const std::string& sig_path, const std::string& cert_path,
                               const std::string& ca_path) {
  std::vector<std::string> args{"sh", script, digest_hex, sig_path, cert_path, ca_path};
  std::vector<char*> argv;
  for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
  argv.push_back(nullptr);
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
  posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
  pid_t pid = 0;
  const int rc = posix_spawnp(&pid, "sh", &fa, nullptr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&fa);
  if (rc != 0) return -1;
  int status = 0;
  if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) return -1;
  return WEXITSTATUS(status);
}

// 数据面适配后端：签名 hex/证书 PEM 落临时文件（0600、独占创建、用毕即删）后走
// spawn 核心。命令门（security-mgr）经此复用 tools/verify_artifact.sh 全套链校验。
class SpawnScriptBackend : public IVerifyBackend {
 public:
  explicit SpawnScriptBackend(std::string script, std::string workdir = "/tmp")
      : script_(std::move(script)), workdir_(std::move(workdir)) {}

  bool verify(const std::string& digest_hex, const std::string& sig_hex,
              const std::string& signer_cert_pem, const std::string& ca_cert_pem,
              std::string& reason) override {
    std::vector<std::uint8_t> sig;
    if (!hex_decode(sig_hex, sig)) { reason = "x509: bad signature hex"; return false; }
    const std::string base = workdir_ + "/os2x5-" + std::to_string(::getpid()) + "-" +
                             std::to_string(seq_++);
    const std::string sigf = base + ".sig", certf = base + ".crt", caf = base + ".ca";
    if (!write_private(sigf, sig.data(), sig.size()) ||
        !write_private(certf, signer_cert_pem.data(), signer_cert_pem.size()) ||
        !write_private(caf, ca_cert_pem.data(), ca_cert_pem.size())) {
      cleanup(sigf, certf, caf);
      reason = "x509: cannot materialize verify material";
      return false;
    }
    const int rc = spawn_verify_script(script_, digest_hex, sigf, certf, caf);
    cleanup(sigf, certf, caf);
    if (rc == 0) return true;
    reason = rc == -1 ? "x509: verify spawn failed"
             : rc == 2 ? "x509: certificate chain/validity failed"
                       : "x509: signature verify failed";
    return false;
  }

 private:
  static bool hex_decode(const std::string& hex, std::vector<std::uint8_t>& out) {
    auto nib = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    if (hex.empty() || hex.size() % 2) return false;
    out.clear();
    for (std::size_t i = 0; i < hex.size(); i += 2) {
      const int h = nib(hex[i]), l = nib(hex[i + 1]);
      if (h < 0 || l < 0) return false;
      out.push_back(static_cast<std::uint8_t>((h << 4) | l));
    }
    return true;
  }
  static bool write_private(const std::string& path, const void* data, std::size_t n) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return false;
    const bool ok = ::write(fd, data, n) == static_cast<ssize_t>(n);
    ::close(fd);
    return ok;
  }
  static void cleanup(const std::string& a, const std::string& b, const std::string& c) {
    ::unlink(a.c_str());
    ::unlink(b.c_str());
    ::unlink(c.c_str());
  }
  std::string script_, workdir_;
  unsigned long seq_{0};
};

// mbedTLS 进程内后端 = 1.5期真件（量产一致替换件，切换点 OS2_WITH_MBEDTLS）。
// 一期壳子如实标注：开启开关即编译错——防"以为有真件"（FastDDS 同款口径）。
#ifdef OS2_WITH_MBEDTLS
static_assert(false, "mbedTLS 后端未落地（1.5期交付）：去除 OS2_WITH_MBEDTLS 或实现 MbedTlsBackend");
#endif

}  // namespace os2::x509
