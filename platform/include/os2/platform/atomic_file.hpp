// =============================================================================
// os2/platform/atomic_file.hpp — 原子文件替换写（write-temp → fsync → rename）
// R2-④/F-07（量产差距重审采纳项）：状态落盘统一走本原语——truncation 直写在
// 写到一半崩溃/断电时留下半文件或空文件，恰好毁掉持久化要保护的状态。
// 语义：任一时刻中断，读方看到的要么旧全量要么新全量，绝无半文件。
// 依据：同目录临时文件 + POSIX rename(2) 同文件系统原子替换；rename 前 fsync
// 数据，rename 后 best-effort fsync 目录项（崩溃后 rename 本身不丢）。
// 供 registry 目录持久化使用；F-07 后续状态类别（耐久等级随 R0 定）共用。
// =============================================================================
#pragma once

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <string>

namespace os2::fsio {

// 整文件原子替换。失败返回 false 且尽力清理临时文件，目标文件保持原状。
inline bool atomic_write(const std::string& path, const std::string& content) {
  const std::string tmp = path + ".tmp";  // 同目录=同文件系统，rename 才原子
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return false;
  const char* p = content.data();
  std::size_t left = content.size();
  while (left > 0) {
    const ssize_t n = ::write(fd, p, left);
    if (n < 0) { ::close(fd); ::unlink(tmp.c_str()); return false; }
    p += n;
    left -= static_cast<std::size_t>(n);
  }
  if (::fsync(fd) != 0 || ::close(fd) != 0) {  // 数据未到盘就不 rename
    ::unlink(tmp.c_str());
    return false;
  }
  if (std::rename(tmp.c_str(), path.c_str()) != 0) {
    ::unlink(tmp.c_str());
    return false;
  }
  const auto slash = path.rfind('/');  // 目录项落盘 best-effort（失败不回退：数据已原子就位）
  const std::string dir = slash == std::string::npos ? "." : path.substr(0, slash);
  const int dfd = ::open(dir.c_str(), O_RDONLY);
  if (dfd >= 0) { ::fsync(dfd); ::close(dfd); }
  return true;
}

}  // namespace os2::fsio
