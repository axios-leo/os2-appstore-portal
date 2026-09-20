// =============================================================================
// impl/artifact_receiver.hpp — 端侧制品接收：暂存文件复核、原子入库、幂等保护
//
// 当前 ArtifactPublish 契约没有传输文件字段。本实现采用受控暂存目录约定：
//   <store.incoming_dir>/<artifact_id>-<version>.artifact
// 发布请求到达后，先走既有格式/签名校验，再读取真实文件复算 SHA-256；一致时原子
// 写入：
//   <store.repository_dir>/<artifact_id>/<version>/artifact.bin
// 同一 id+version 已存在相同内容视为幂等成功，不同内容从严拒绝。
// =============================================================================
#pragma once

#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include "impl/grayscale_store.hpp"
#include "os2/platform/atomic_file.hpp"
#include "os2/platform/hash.hpp"

namespace os2::store::impl {

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
    if (!safe_component(artifact.version)) {
      reason = "version has illegal char (allowed: alnum . _ -)";
      return false;
    }

    const std::filesystem::path source =
        std::filesystem::path(incoming_dir_) /
        (artifact.artifact_id + "-" + artifact.version + ".artifact");
    const std::filesystem::path destination = std::filesystem::path(repository_dir_) /
                                              artifact.artifact_id / artifact.version /
                                              "artifact.bin";

    std::string content;
    if (!read_regular_file(source, content, reason)) return false;
    if (normalize_hex(os2::hash::sha256_hex(content)) != normalize_hex(artifact.sha256)) {
      reason = "artifact content sha256 mismatch";
      return false;
    }

    std::error_code ec;
    const auto existing_status = std::filesystem::symlink_status(destination, ec);
    if (!ec && std::filesystem::exists(existing_status)) {
      std::string existing;
      if (!read_regular_file(destination, existing, reason)) return false;
      if (normalize_hex(os2::hash::sha256_hex(existing)) != normalize_hex(artifact.sha256)) {
        reason = "artifact version already exists with different content";
        return false;
      }
      return true;  // 同一制品重试：幂等接收，不重复改写仓库文件。
    }

    ec.clear();
    std::filesystem::create_directories(destination.parent_path(), ec);
    if (ec) {
      reason = "cannot create artifact repository directory";
      return false;
    }
    if (!os2::fsio::atomic_write(destination.string(), content)) {
      reason = "cannot persist artifact into repository";
      return false;
    }
    return true;
  }

 private:
  static bool safe_component(const std::string& value) {
    if (value.empty() || value.size() > 64 || value == "." || value == "..") return false;
    for (char ch : value) {
      const auto c = static_cast<unsigned char>(ch);
      if (!std::isalnum(c) && ch != '.' && ch != '_' && ch != '-') return false;
    }
    return true;
  }

  static std::string normalize_hex(std::string value) {
    for (char& ch : value) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return value;
  }

  bool read_regular_file(const std::filesystem::path& path, std::string& content,
                         std::string& reason) const {
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec || !std::filesystem::exists(status)) {
      reason = "artifact staging file not found";
      return false;
    }
    if (std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status)) {
      reason = "artifact staging path must be a regular file";
      return false;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
      reason = "cannot open artifact staging file";
      return false;
    }
    content.clear();
    std::array<char, 64 * 1024> buffer{};
    while (input) {
      input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
      const auto count = input.gcount();
      if (count <= 0) break;
      if (content.size() + static_cast<std::size_t>(count) > max_artifact_bytes_) {
        reason = "artifact exceeds store.max_artifact_bytes";
        return false;
      }
      content.append(buffer.data(), static_cast<std::size_t>(count));
    }
    if (!input.eof()) {
      reason = "cannot read complete artifact staging file";
      return false;
    }
    return true;
  }

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
};

}  // namespace os2::store::impl
