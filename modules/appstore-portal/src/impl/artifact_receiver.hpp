// =============================================================================
// impl/artifact_receiver.hpp — 端侧制品接收：流式复核、独占提交、仓库一致性检查
//
// 暂存约定：<incoming>/<artifact_id>-<version>.artifact
// 仓库布局：<repository>/<artifact_id>/<version>/artifact.bin
// 入库先在目标目录创建随机、独占的临时文件，流式复制并计算 SHA-256；校验通过后
// 通过 link(2) 以“不覆盖”语义提交。崩溃残留和孤儿制品可在启动时显式启用 GC。
// =============================================================================
#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "impl/grayscale_store.hpp"
#include "os2/platform/hash.hpp"

namespace os2::store::impl {

namespace artifact_fs {

inline std::string normalize_hex(std::string value) {
  for (char& ch : value) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  return value;
}

inline bool safe_component(const std::string& value, std::size_t max_size) {
  if (value.empty() || value.size() > max_size || value == "." || value == "..") return false;
  for (char ch : value) {
    const auto c = static_cast<unsigned char>(ch);
    if (!std::isalnum(c) && ch != '.' && ch != '_' && ch != '-') return false;
  }
  return true;
}

inline bool write_all(int fd, const char* data, std::size_t size) {
  while (size > 0) {
    const ssize_t written = ::write(fd, data, size);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return false;
    data += written;
    size -= static_cast<std::size_t>(written);
  }
  return true;
}

inline void fsync_directory(const std::filesystem::path& directory) {
  const int fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd >= 0) {
    (void)::fsync(fd);
    (void)::close(fd);
  }
}

inline int open_regular_readonly(const std::filesystem::path& path, const std::string& not_found,
                                 std::string& reason) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    reason = errno == ENOENT ? not_found : "cannot open artifact file";
    return -1;
  }
  struct stat status {};
  if (::fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)) {
    (void)::close(fd);
    reason = "artifact path must be a regular file";
    return -1;
  }
  return fd;
}

inline bool stream_digest_fd(int fd, std::uint64_t max_bytes, std::string& digest,
                             std::string& reason, int copy_fd = -1) {
  os2::hash::Sha256Stream sha;
  std::array<char, 64 * 1024> buffer{};
  std::uint64_t total = 0;
  for (;;) {
    const ssize_t count = ::read(fd, buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) {
      reason = "cannot read complete artifact file";
      return false;
    }
    if (count == 0) break;
    const auto bytes = static_cast<std::uint64_t>(count);
    if (bytes > max_bytes - total) {
      reason = "artifact exceeds store.max_artifact_bytes";
      return false;
    }
    total += bytes;
    sha.update(buffer.data(), static_cast<std::size_t>(count));
    if (copy_fd >= 0 && !write_all(copy_fd, buffer.data(), static_cast<std::size_t>(count))) {
      reason = "cannot write artifact temporary file";
      return false;
    }
  }
  digest = os2::hash::hex(sha.finalize());
  return true;
}

inline bool digest_regular_file(const std::filesystem::path& path, std::uint64_t max_bytes,
                                std::string& digest, std::string& reason) {
  const int fd = open_regular_readonly(path, "artifact repository file not found", reason);
  if (fd < 0) return false;
  const bool ok = stream_digest_fd(fd, max_bytes, digest, reason);
  if (::close(fd) != 0 && ok) {
    reason = "cannot close artifact file";
    return false;
  }
  return ok;
}

}  // namespace artifact_fs

class FilesystemArtifactVerifier final : public IArtifactVerifier {
 public:
  FilesystemArtifactVerifier(std::unique_ptr<IArtifactVerifier> inner, std::string incoming_dir,
                             std::string repository_dir, std::uint64_t max_artifact_bytes)
      : inner_(std::move(inner)),
        incoming_dir_(std::move(incoming_dir)),
        repository_dir_(std::move(repository_dir)),
        max_artifact_bytes_(max_artifact_bytes) {}

  bool verify(const Artifact& artifact, std::string& reason) override {
    if (!inner_ || !inner_->verify(artifact, reason)) return false;
    if (incoming_dir_.empty() || repository_dir_.empty()) {
      reason = "artifact receiver directories are not configured";
      return false;
    }
    if (!artifact_fs::safe_component(artifact.artifact_id, 128)) {
      reason = "artifact_id has illegal char (allowed: alnum . _ -)";
      return false;
    }
    if (!artifact_fs::safe_component(artifact.version, 64)) {
      reason = "version has illegal char (allowed: alnum . _ -)";
      return false;
    }

    const std::filesystem::path source =
        std::filesystem::path(incoming_dir_) /
        (artifact.artifact_id + "-" + artifact.version + ".artifact");
    const std::filesystem::path destination = std::filesystem::path(repository_dir_) /
                                              artifact.artifact_id / artifact.version /
                                              "artifact.bin";
    std::error_code ec;
    std::filesystem::create_directories(destination.parent_path(), ec);
    if (ec) {
      reason = "cannot create artifact repository directory";
      return false;
    }

    const int source_fd = artifact_fs::open_regular_readonly(
        source, "artifact staging file not found", reason);
    if (source_fd < 0) return false;

    std::string pattern = (destination.parent_path() / ".artifact.bin.tmp.XXXXXX").string();
    std::vector<char> temp_name(pattern.begin(), pattern.end());
    temp_name.push_back('\0');
    const int temp_fd = ::mkstemp(temp_name.data());
    if (temp_fd < 0) {
      (void)::close(source_fd);
      reason = "cannot create exclusive artifact temporary file";
      return false;
    }
    const std::filesystem::path temporary{temp_name.data()};
    (void)::fcntl(temp_fd, F_SETFD, FD_CLOEXEC);
    (void)::fchmod(temp_fd, 0644);

    std::string actual_digest;
    bool copied = artifact_fs::stream_digest_fd(source_fd, max_artifact_bytes_, actual_digest,
                                                 reason, temp_fd);
    if (::close(source_fd) != 0 && copied) {
      reason = "cannot close artifact staging file";
      copied = false;
    }
    if (copied && artifact_fs::normalize_hex(actual_digest) !=
                      artifact_fs::normalize_hex(artifact.sha256)) {
      reason = "artifact content sha256 mismatch";
      copied = false;
    }
    if (copied && ::fsync(temp_fd) != 0) {
      reason = "cannot sync artifact temporary file";
      copied = false;
    }
    if (::close(temp_fd) != 0 && copied) {
      reason = "cannot close artifact temporary file";
      copied = false;
    }
    if (!copied) {
      (void)::unlink(temporary.c_str());
      return false;
    }

    // link(2) 在目标存在时返回 EEXIST，绝不会替换既有版本。
    if (::link(temporary.c_str(), destination.c_str()) == 0) {
      artifact_fs::fsync_directory(destination.parent_path());
      (void)::unlink(temporary.c_str());
      artifact_fs::fsync_directory(destination.parent_path());
      return true;
    }

    const int commit_error = errno;
    (void)::unlink(temporary.c_str());
    if (commit_error != EEXIST) {
      reason = "cannot commit artifact into repository";
      return false;
    }

    std::string existing_digest;
    if (!artifact_fs::digest_regular_file(destination, max_artifact_bytes_, existing_digest,
                                          reason))
      return false;
    if (artifact_fs::normalize_hex(existing_digest) !=
        artifact_fs::normalize_hex(artifact.sha256)) {
      reason = "artifact version already exists with different content";
      return false;
    }
    return true;  // 同一内容重试：目标不改写，按幂等成功处理。
  }

 private:
  std::unique_ptr<IArtifactVerifier> inner_;
  std::string incoming_dir_;
  std::string repository_dir_;
  std::uint64_t max_artifact_bytes_;
};

class ReceivingStore final : public GrayscaleStore {
 public:
  using GrayscaleStore::GrayscaleStore;

 protected:
  std::unique_ptr<IArtifactVerifier> make_verifier() override {
    return std::make_unique<FilesystemArtifactVerifier>(
        GrayscaleStore::make_verifier(), config().get("store.incoming_dir"),
        config().get("store.repository_dir"),
        config().get_u64("store.max_artifact_bytes", 256ULL * 1024ULL * 1024ULL));
  }

  bool on_state_restored() override {
    const std::filesystem::path repository = config().get("store.repository_dir");
    const auto indexed = registered_artifacts();
    if (repository.empty()) {
      if (indexed.empty()) return true;
      log().warn("store_repository_inconsistent", "store.repository_dir is empty");
      return false;
    }
    const auto max_bytes =
        config().get_u64("store.max_artifact_bytes", 256ULL * 1024ULL * 1024ULL);
    for (const auto& artifact : indexed) {
      if (!artifact_fs::safe_component(artifact.artifact_id, 128) ||
          !artifact_fs::safe_component(artifact.version, 64)) {
        log().warn("store_repository_inconsistent", "unsafe artifact key in restored index");
        return false;
      }
      const auto path = repository / artifact.artifact_id / artifact.version / "artifact.bin";
      std::string digest;
      std::string reason;
      if (!artifact_fs::digest_regular_file(path, max_bytes, digest, reason) ||
          artifact_fs::normalize_hex(digest) != artifact_fs::normalize_hex(artifact.sha256)) {
        log().warn("store_repository_inconsistent",
                   artifact.artifact_id + "@" + artifact.version + ": " +
                       (reason.empty() ? "artifact digest mismatch" : reason));
        return false;
      }
    }

    std::error_code ec;
    if (!std::filesystem::exists(repository, ec)) return indexed.empty();
    if (ec || !std::filesystem::is_directory(repository, ec)) {
      log().warn("store_repository_inconsistent", "repository is not a readable directory");
      return false;
    }
    const bool gc = config().get("store.gc_orphans_on_start", "false") == "true";
    std::filesystem::recursive_directory_iterator it(
        repository, std::filesystem::directory_options::skip_permission_denied, ec);
    const std::filesystem::recursive_directory_iterator end;
    while (!ec && it != end) {
      const auto path = it->path();
      const std::string filename = path.filename().string();
      bool orphan = false;
      bool temporary = filename.rfind(".artifact.bin.tmp.", 0) == 0;
      if (filename == "artifact.bin") {
        const auto relative = path.lexically_relative(repository);
        std::vector<std::string> parts;
        for (const auto& part : relative) parts.push_back(part.string());
        if (parts.size() == 3)
          orphan = !find(parts[0], parts[1]).has_value();
      }
      if ((orphan || temporary) && gc) {
        std::error_code remove_ec;
        std::filesystem::remove(path, remove_ec);
        if (remove_ec) {
          log().warn("store_gc_failed", path.string());
          return false;
        }
        log().info(temporary ? "store_temp_collected" : "store_orphan_collected",
                   path.string());
      } else if (orphan || temporary) {
        log().warn(temporary ? "store_temp_detected" : "store_orphan_detected",
                   path.string());
      }
      it.increment(ec);
    }
    if (ec) {
      log().warn("store_repository_inconsistent", "cannot scan complete repository");
      return false;
    }
    return true;
  }
};

}  // namespace os2::store::impl
