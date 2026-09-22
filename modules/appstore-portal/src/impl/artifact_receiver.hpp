// =============================================================================
// impl/artifact_receiver.hpp — 端侧制品接收：流式复核、独占提交、仓库一致性检查
//
// 兼容暂存约定：<incoming>/<artifact_id>-<version>.artifact
// 跨节点传输：prepare → chunk（顺序、hex）→ commit；可选 abort 主动清理。
// 仓库布局：<repository>/<artifact_id>/<version>/artifact.bin
// 入库先在目标目录创建随机、独占的临时文件，流式复制并计算 SHA-256；校验通过后
// 通过 link(2) 以“不覆盖”语义提交。崩溃残留和孤儿制品可在启动时显式启用 GC。
// =============================================================================
#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <map>
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

inline bool decode_hex(const std::string& encoded, std::string& decoded) {
  if (encoded.size() % 2 != 0) return false;
  auto nibble = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
  };
  decoded.clear();
  decoded.reserve(encoded.size() / 2);
  for (std::size_t i = 0; i < encoded.size(); i += 2) {
    const int hi = nibble(encoded[i]);
    const int lo = nibble(encoded[i + 1]);
    if (hi < 0 || lo < 0) return false;
    decoded.push_back(static_cast<char>((hi << 4) | lo));
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

  // IBus 的服务派发是单线程模型。跨节点 commit 在同一调用栈中设置一次性来源，
  // 让既有发布链直接读取上传会话文件，避免创建可能在掉电后遗留的兼容暂存链接。
  void use_source_once(std::filesystem::path source) { next_source_ = std::move(source); }

  bool verify(const Artifact& artifact, std::string& reason) override {
    const std::filesystem::path source_override = std::move(next_source_);
    next_source_.clear();
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
        source_override.empty()
            ? std::filesystem::path(incoming_dir_) /
                  (artifact.artifact_id + "-" + artifact.version + ".artifact")
            : source_override;
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
  std::filesystem::path next_source_;
};

class ReceivingStore final : public GrayscaleStore {
 public:
  using GrayscaleStore::GrayscaleStore;

 protected:
  bool on_init() override {
    if (!cleanup_stale_uploads() || !GrayscaleStore::on_init()) return false;
    mgmt().serve(topics::ArtifactUploadPrepare,
                 [this](const Msg& m) { return handle_upload_prepare(m); });
    mgmt().serve(topics::ArtifactUploadChunk,
                 [this](const Msg& m) { return handle_upload_chunk(m); });
    mgmt().serve(topics::ArtifactUploadCommit,
                 [this](const Msg& m) { return handle_upload_commit(m); });
    mgmt().serve(topics::ArtifactUploadAbort,
                 [this](const Msg& m) { return handle_upload_abort(m); });
    return true;
  }

  void on_stop() override {
    clear_uploads();
    GrayscaleStore::on_stop();
  }

  std::unique_ptr<IArtifactVerifier> make_verifier() override {
    auto verifier = std::make_unique<FilesystemArtifactVerifier>(
        GrayscaleStore::make_verifier(), config().get("store.incoming_dir"),
        config().get("store.repository_dir"),
        config().get_u64("store.max_artifact_bytes", 256ULL * 1024ULL * 1024ULL));
    filesystem_verifier_ = verifier.get();
    return verifier;
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

 private:
  struct UploadSession {
    std::string artifact_id;
    std::string version;
    std::string sha256;
    std::string sbom_ref;
    std::filesystem::path temporary;
    int fd{-1};
    std::uint64_t total_bytes{0};
    std::uint64_t received_bytes{0};
    std::uint64_t last_activity_ms{0};
    os2::hash::Sha256Stream digest;

    ~UploadSession() {
      if (fd >= 0) (void)::close(fd);
    }
  };

  std::filesystem::path upload_directory() const {
    return std::filesystem::path(config().get("store.incoming_dir")) / ".uploads";
  }

  std::uint64_t chunk_bytes() const {
    const auto configured = config().get_u64("store.upload_chunk_bytes", 64ULL * 1024ULL);
    return std::max<std::uint64_t>(1, std::min<std::uint64_t>(configured, 1024ULL * 1024ULL));
  }

  bool cleanup_stale_uploads() {
    const auto incoming = config().get("store.incoming_dir");
    if (incoming.empty()) {
      log().warn("store_upload_init_failed", "store.incoming_dir is empty");
      return false;
    }
    const auto directory = upload_directory();
    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    if (ec) {
      log().warn("store_upload_init_failed", "cannot create upload directory");
      return false;
    }
    std::filesystem::directory_iterator it(directory, ec), end;
    while (!ec && it != end) {
      const auto path = it->path();
      const auto name = path.filename().string();
      if (name.rfind(".upload.", 0) == 0) {
        std::error_code status_ec;
        const auto status = std::filesystem::symlink_status(path, status_ec);
        if (status_ec || (!std::filesystem::is_regular_file(status) &&
                          !std::filesystem::is_symlink(status))) {
          log().warn("store_upload_cleanup_failed", path.string());
          return false;
        }
        std::error_code remove_ec;
        std::filesystem::remove(path, remove_ec);
        if (remove_ec) {
          log().warn("store_upload_cleanup_failed", path.string());
          return false;
        }
        log().info("store_upload_collected", path.string());
      }
      it.increment(ec);
    }
    if (ec) {
      log().warn("store_upload_cleanup_failed", "cannot scan upload directory");
      return false;
    }
    artifact_fs::fsync_directory(directory);
    return true;
  }

  void discard_upload(const std::string& upload_id) {
    auto it = uploads_.find(upload_id);
    if (it == uploads_.end()) return;
    const auto path = it->second->temporary;
    uploads_.erase(it);  // 先关闭 fd，再删除目录项。
    (void)::unlink(path.c_str());
    artifact_fs::fsync_directory(upload_directory());
  }

  void clear_uploads() {
    while (!uploads_.empty()) discard_upload(uploads_.begin()->first);
  }

  void expire_uploads() {
    const auto now = now_ms();
    const auto ttl = config().get_u64("store.upload_session_ttl_ms", 15ULL * 60ULL * 1000ULL);
    std::vector<std::string> expired;
    for (const auto& entry : uploads_)
      if (ttl == 0 || now - entry.second->last_activity_ms > ttl) expired.push_back(entry.first);
    for (const auto& id : expired) discard_upload(id);
  }

  static Msg upload_rejected(const char* type, const std::string& reason,
                             std::uint64_t next_offset = 0) {
    Msg reply{type, {{"accepted", "false"}, {"reason", reason}}};
    if (std::string(type) == "ArtifactUploadChunkReply")
      reply.kv["next_offset"] = std::to_string(next_offset);
    return reply;
  }

  Msg handle_upload_prepare(const Msg& m) {
    expire_uploads();
    const auto total = m.get_u64_checked("total_bytes");
    if (!total) return upload_rejected("ArtifactUploadPrepareReply", "total_bytes is required and must be numeric");
    const auto max_bytes =
        config().get_u64("store.max_artifact_bytes", 256ULL * 1024ULL * 1024ULL);
    if (*total > max_bytes)
      return upload_rejected("ArtifactUploadPrepareReply", "artifact exceeds store.max_artifact_bytes");
    if (uploads_.size() >= config().get_u64("store.max_upload_sessions", 32))
      return upload_rejected("ArtifactUploadPrepareReply", "too many active upload sessions");

    Artifact artifact{m.get("artifact_id"), m.get("version"), m.get("sha256"),
                      m.get("sbom_ref"), "published", 0};
    Sha256FormatVerifier format;
    std::string reason;
    if (!format.verify(artifact, reason) ||
        !artifact_fs::safe_component(artifact.version, 64))
      return upload_rejected("ArtifactUploadPrepareReply",
                             reason.empty() ? "version has illegal char (allowed: alnum . _ -)" : reason);

    std::string pattern = (upload_directory() / ".upload.XXXXXX").string();
    std::vector<char> name(pattern.begin(), pattern.end());
    name.push_back('\0');
    const int fd = ::mkstemp(name.data());
    if (fd < 0)
      return upload_rejected("ArtifactUploadPrepareReply", "cannot create upload temporary file");
    (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
    (void)::fchmod(fd, 0600);

    std::string upload_id;
    do upload_id = gen_id("upload"); while (uploads_.count(upload_id) != 0);
    auto session = std::make_unique<UploadSession>();
    session->artifact_id = std::move(artifact.artifact_id);
    session->version = std::move(artifact.version);
    session->sha256 = artifact_fs::normalize_hex(std::move(artifact.sha256));
    session->sbom_ref = std::move(artifact.sbom_ref);
    session->temporary = name.data();
    session->fd = fd;
    session->total_bytes = *total;
    session->last_activity_ms = now_ms();
    uploads_.emplace(upload_id, std::move(session));
    artifact_fs::fsync_directory(upload_directory());
    return Msg{"ArtifactUploadPrepareReply",
               {{"accepted", "true"}, {"upload_id", upload_id},
                {"chunk_bytes", std::to_string(chunk_bytes())}}};
  }

  Msg handle_upload_chunk(const Msg& m) {
    expire_uploads();
    const auto id = m.get("upload_id");
    auto it = uploads_.find(id);
    if (it == uploads_.end())
      return upload_rejected("ArtifactUploadChunkReply", "unknown or expired upload_id");
    auto& session = *it->second;
    const auto offset = m.get_u64_checked("offset");
    if (!offset)
      return upload_rejected("ArtifactUploadChunkReply", "offset is required and must be numeric",
                             session.received_bytes);
    if (*offset != session.received_bytes)
      return upload_rejected("ArtifactUploadChunkReply", "unexpected chunk offset",
                             session.received_bytes);
    const auto& encoded = m.get("data_hex");
    if (encoded.size() > chunk_bytes() * 2)
      return upload_rejected("ArtifactUploadChunkReply", "chunk exceeds store.upload_chunk_bytes",
                             session.received_bytes);
    std::string bytes;
    if (!artifact_fs::decode_hex(encoded, bytes))
      return upload_rejected("ArtifactUploadChunkReply", "data_hex is not valid even-length hex",
                             session.received_bytes);
    if (bytes.empty() && session.received_bytes < session.total_bytes)
      return upload_rejected("ArtifactUploadChunkReply", "empty chunk does not advance upload",
                             session.received_bytes);
    if (bytes.size() > session.total_bytes - session.received_bytes)
      return upload_rejected("ArtifactUploadChunkReply", "chunk exceeds declared total_bytes",
                             session.received_bytes);
    if (!artifact_fs::write_all(session.fd, bytes.data(), bytes.size())) {
      discard_upload(id);
      return upload_rejected("ArtifactUploadChunkReply", "cannot write upload temporary file");
    }
    session.digest.update(bytes);
    session.received_bytes += bytes.size();
    session.last_activity_ms = now_ms();
    return Msg{"ArtifactUploadChunkReply",
               {{"accepted", "true"},
                {"next_offset", std::to_string(session.received_bytes)}}};
  }

  Msg handle_upload_commit(const Msg& m) {
    expire_uploads();
    const auto id = m.get("upload_id");
    auto it = uploads_.find(id);
    if (it == uploads_.end())
      return upload_rejected("ArtifactUploadCommitReply", "unknown or expired upload_id");
    auto session = std::move(it->second);
    uploads_.erase(it);
    auto cleanup = [&]() {
      if (session->fd >= 0) {
        (void)::close(session->fd);
        session->fd = -1;
      }
      (void)::unlink(session->temporary.c_str());
      artifact_fs::fsync_directory(upload_directory());
    };
    if (session->received_bytes != session->total_bytes) {
      cleanup();
      return upload_rejected("ArtifactUploadCommitReply", "upload is incomplete");
    }
    const std::string actual = os2::hash::hex(session->digest.finalize());
    if (actual != session->sha256) {
      cleanup();
      return upload_rejected("ArtifactUploadCommitReply", "uploaded artifact sha256 mismatch");
    }
    if (::fsync(session->fd) != 0 || ::close(session->fd) != 0) {
      session->fd = -1;
      cleanup();
      return upload_rejected("ArtifactUploadCommitReply", "cannot sync upload temporary file");
    }
    session->fd = -1;

    if (!filesystem_verifier_) {
      cleanup();
      return upload_rejected("ArtifactUploadCommitReply", "artifact verifier is unavailable");
    }
    filesystem_verifier_->use_source_once(session->temporary);
    const Msg published = publish_artifact(
        Msg{"ArtifactPublish", {{"artifact_id", session->artifact_id},
                                 {"version", session->version},
                                 {"sha256", session->sha256},
                                 {"sbom_ref", session->sbom_ref}}});
    cleanup();
    if (published.get("accepted") != "true")
      return upload_rejected("ArtifactUploadCommitReply", published.get("reason", "artifact publish rejected"));
    return Msg{"ArtifactUploadCommitReply", {{"accepted", "true"}}};
  }

  Msg handle_upload_abort(const Msg& m) {
    expire_uploads();
    const auto id = m.get("upload_id");
    if (uploads_.count(id) == 0)
      return upload_rejected("ArtifactUploadAbortReply", "unknown or expired upload_id");
    discard_upload(id);
    return Msg{"ArtifactUploadAbortReply", {{"accepted", "true"}}};
  }

  std::map<std::string, std::unique_ptr<UploadSession>> uploads_;
  FilesystemArtifactVerifier* filesystem_verifier_{nullptr};
};

}  // namespace os2::store::impl
