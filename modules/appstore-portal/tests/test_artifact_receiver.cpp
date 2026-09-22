#include <atomic>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <string>
#include <thread>

#include "impl/artifact_receiver.hpp"
#include "os2/platform/testing.hpp"

using namespace os2;
using namespace os2::store::impl;

namespace {

struct Fixture {
  std::filesystem::path root;
  std::filesystem::path incoming;
  std::filesystem::path repository;

  Fixture() {
    root = std::filesystem::path("/tmp") / gen_id("os2-artifact-receiver");
    incoming = root / "incoming";
    repository = root / "repository";
    std::filesystem::create_directories(incoming);
  }
  ~Fixture() { std::filesystem::remove_all(root); }

  Config config(std::uint64_t max_bytes = 1024 * 1024) const {
    return Config{{{"store.incoming_dir", incoming.string()},
                   {"store.repository_dir", repository.string()},
                   {"store.max_artifact_bytes", std::to_string(max_bytes)}}};
  }

  void stage(const std::string& id, const std::string& version, const std::string& content) const {
    std::ofstream out(incoming / (id + "-" + version + ".artifact"), std::ios::binary);
    out << content;
  }
};

ReceivingStore make_store(ServiceContext& ctx) {
  ctx.buses.mgmt->serve(topics::PolicyCheck,
                        [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
  return ReceivingStore{
      ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Compute, "core-01", ""},
      ctx};
}

Msg publish(ServiceContext& ctx, const std::string& id, const std::string& version,
            const std::string& digest) {
  auto reply = ctx.buses.mgmt->request(
      topics::ArtifactPublish,
      Msg{"ArtifactPublish", {{"artifact_id", id},
                               {"version", version},
                               {"sha256", digest},
                               {"sbom_ref", "sbom://demo"}}},
      100);
  OS2_ASSERT(reply.has_value());
  return *reply;
}

}  // namespace

OS2_TEST(receives_real_file_verifies_digest_and_persists_atomically) {
  Fixture f;
  const std::string content = "real artifact bytes v1";
  f.stage("os2.pkg.demo", "1.0.0", content);
  ServiceContext ctx{BusPair::make_inproc(), f.config()};
  auto store = make_store(ctx);
  OS2_ASSERT(store.init() && store.start());

  const Msg reply = publish(ctx, "os2.pkg.demo", "1.0.0", ArtifactSealer::seal(content));
  OS2_ASSERT_EQ(reply.get("accepted"), std::string("true"));
  OS2_ASSERT(store.find("os2.pkg.demo").has_value());

  const auto stored = f.repository / "os2.pkg.demo" / "1.0.0" / "artifact.bin";
  std::ifstream input(stored, std::ios::binary);
  const std::string copied{std::istreambuf_iterator<char>(input),
                           std::istreambuf_iterator<char>()};
  OS2_ASSERT_EQ(copied, content);
}

OS2_TEST(rejects_tampered_file_without_registering_or_persisting) {
  Fixture f;
  f.stage("os2.pkg.demo", "1.0.0", "tampered bytes");
  ServiceContext ctx{BusPair::make_inproc(), f.config()};
  auto store = make_store(ctx);
  OS2_ASSERT(store.init() && store.start());

  const Msg reply =
      publish(ctx, "os2.pkg.demo", "1.0.0", ArtifactSealer::seal("expected bytes"));
  OS2_ASSERT_EQ(reply.get("accepted"), std::string("false"));
  OS2_ASSERT(reply.get("reason").find("sha256 mismatch") != std::string::npos);
  OS2_ASSERT(!store.find("os2.pkg.demo").has_value());
  OS2_ASSERT(!std::filesystem::exists(f.repository / "os2.pkg.demo" / "1.0.0" /
                                      "artifact.bin"));
}

OS2_TEST(rejects_missing_oversized_and_unsafe_version_inputs) {
  Fixture f;
  ServiceContext ctx{BusPair::make_inproc(), f.config(4)};
  auto store = make_store(ctx);
  OS2_ASSERT(store.init() && store.start());

  Msg missing = publish(ctx, "os2.pkg.missing", "1.0", ArtifactSealer::seal("x"));
  OS2_ASSERT_EQ(missing.get("accepted"), std::string("false"));
  OS2_ASSERT(missing.get("reason").find("not found") != std::string::npos);

  f.stage("os2.pkg.big", "1.0", "12345");
  Msg large = publish(ctx, "os2.pkg.big", "1.0", ArtifactSealer::seal("12345"));
  OS2_ASSERT_EQ(large.get("accepted"), std::string("false"));
  OS2_ASSERT(large.get("reason").find("max_artifact_bytes") != std::string::npos);

  Msg unsafe = publish(ctx, "os2.pkg.bad", "../1", ArtifactSealer::seal("x"));
  OS2_ASSERT_EQ(unsafe.get("accepted"), std::string("false"));
  OS2_ASSERT(unsafe.get("reason").find("version has illegal char") != std::string::npos);
}

OS2_TEST(retry_is_idempotent_and_existing_version_cannot_be_replaced) {
  Fixture f;
  const std::string original = "immutable artifact";
  f.stage("os2.pkg.demo", "2.0", original);
  ServiceContext ctx{BusPair::make_inproc(), f.config()};
  auto store = make_store(ctx);
  OS2_ASSERT(store.init() && store.start());

  const std::string digest = ArtifactSealer::seal(original);
  OS2_ASSERT_EQ(publish(ctx, "os2.pkg.demo", "2.0", digest).get("accepted"),
                std::string("true"));
  OS2_ASSERT_EQ(publish(ctx, "os2.pkg.demo", "2.0", digest).get("accepted"),
                std::string("true"));

  f.stage("os2.pkg.demo", "2.0", "replacement bytes");
  const Msg replaced =
      publish(ctx, "os2.pkg.demo", "2.0", ArtifactSealer::seal("replacement bytes"));
  OS2_ASSERT_EQ(replaced.get("accepted"), std::string("false"));
  OS2_ASSERT(replaced.get("reason").find("already exists") != std::string::npos);
}

OS2_TEST(concurrent_publish_uses_exclusive_no_overwrite_commit) {
  Fixture f;
  const auto incoming_a = f.root / "incoming-a";
  const auto incoming_b = f.root / "incoming-b";
  std::filesystem::create_directories(incoming_a);
  std::filesystem::create_directories(incoming_b);
  const std::string content_a(256 * 1024, 'a');
  const std::string content_b(256 * 1024, 'b');
  {
    std::ofstream out(incoming_a / "os2.pkg.race-1.0.artifact", std::ios::binary);
    out << content_a;
  }
  {
    std::ofstream out(incoming_b / "os2.pkg.race-1.0.artifact", std::ios::binary);
    out << content_b;
  }
  store::Artifact artifact_a{"os2.pkg.race", "1.0", ArtifactSealer::seal(content_a), "", "published", 0};
  store::Artifact artifact_b{"os2.pkg.race", "1.0", ArtifactSealer::seal(content_b), "", "published", 0};
  std::atomic<int> ready{0};
  std::atomic<bool> go{false};
  bool accepted_a = false;
  bool accepted_b = false;
  std::string reason_a;
  std::string reason_b;
  auto receive = [&](const std::filesystem::path& incoming, const store::Artifact& artifact,
                     bool& accepted, std::string& reason) {
    FilesystemArtifactVerifier verifier{std::make_unique<Sha256FormatVerifier>(),
                                        incoming.string(), f.repository.string(), 1024 * 1024};
    ++ready;
    while (!go.load()) std::this_thread::yield();
    accepted = verifier.verify(artifact, reason);
  };
  std::thread first(receive, incoming_a, std::cref(artifact_a),
                    std::ref(accepted_a), std::ref(reason_a));
  std::thread second(receive, incoming_b, std::cref(artifact_b),
                     std::ref(accepted_b), std::ref(reason_b));
  while (ready.load() != 2) std::this_thread::yield();
  go = true;
  first.join();
  second.join();

  OS2_ASSERT(accepted_a != accepted_b);
  const auto stored = f.repository / "os2.pkg.race" / "1.0" / "artifact.bin";
  std::ifstream input(stored, std::ios::binary);
  const std::string copied{std::istreambuf_iterator<char>(input),
                           std::istreambuf_iterator<char>()};
  OS2_ASSERT(copied == content_a || copied == content_b);
  OS2_ASSERT_EQ(ArtifactSealer::seal(copied),
                accepted_a ? artifact_a.sha256 : artifact_b.sha256);
  for (const auto& entry : std::filesystem::directory_iterator(stored.parent_path()))
    OS2_ASSERT(entry.path().filename().string().rfind(".artifact.bin.tmp.", 0) != 0);
}

OS2_TEST(startup_fails_closed_when_indexed_file_is_missing) {
  Fixture f;
  Config cfg = f.config();
  const auto state = f.root / "state.tsv";
  cfg.set("store.persist_path", state.string());
  const std::string content = "durable artifact";
  f.stage("os2.pkg.missing-after-restart", "1.0", content);
  {
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    auto store = make_store(ctx);
    OS2_ASSERT(store.init() && store.start());
    OS2_ASSERT_EQ(publish(ctx, "os2.pkg.missing-after-restart", "1.0",
                          ArtifactSealer::seal(content)).get("accepted"),
                  std::string("true"));
    store.stop();
  }
  std::filesystem::remove(f.repository / "os2.pkg.missing-after-restart" / "1.0" /
                          "artifact.bin");
  ServiceContext restarted_ctx{BusPair::make_inproc(), cfg};
  auto restarted = make_store(restarted_ctx);
  OS2_ASSERT(!restarted.init());
}

OS2_TEST(startup_fails_closed_when_repository_content_is_corrupted) {
  Fixture f;
  Config cfg = f.config();
  const auto state = f.root / "state.tsv";
  cfg.set("store.persist_path", state.string());
  const std::string content = "verified before restart";
  f.stage("os2.pkg.corrupted", "1.0", content);
  {
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    auto store = make_store(ctx);
    OS2_ASSERT(store.init() && store.start());
    OS2_ASSERT_EQ(publish(ctx, "os2.pkg.corrupted", "1.0", ArtifactSealer::seal(content))
                      .get("accepted"),
                  std::string("true"));
    store.stop();
  }
  {
    std::ofstream out(f.repository / "os2.pkg.corrupted" / "1.0" / "artifact.bin",
                      std::ios::binary | std::ios::trunc);
    out << "modified after indexing";
  }
  ServiceContext restarted_ctx{BusPair::make_inproc(), cfg};
  auto restarted = make_store(restarted_ctx);
  OS2_ASSERT(!restarted.init());
}

OS2_TEST(startup_rejects_corrupted_index) {
  Fixture f;
  Config cfg = f.config();
  const auto state = f.root / "state.tsv";
  cfg.set("store.persist_path", state.string());
  {
    std::ofstream out(state);
    out << "V\t2\nA\tzz\t31\t00\t00\t00\t0\n";
  }
  ServiceContext ctx{BusPair::make_inproc(), cfg};
  auto store = make_store(ctx);
  OS2_ASSERT(!store.init());
}

OS2_TEST(startup_gc_recovers_crash_window_and_removes_temp_files) {
  Fixture f;
  Config cfg = f.config();
  const auto state = f.root / "state.tsv";
  cfg.set("store.persist_path", state.string());
  cfg.set("store.gc_orphans_on_start", "true");
  const std::string content = "blob committed before index checkpoint";
  f.stage("os2.pkg.crash", "1.0", content);
  {
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    auto store = make_store(ctx);
    OS2_ASSERT(store.init() && store.start());
    OS2_ASSERT_EQ(publish(ctx, "os2.pkg.crash", "1.0", ArtifactSealer::seal(content))
                      .get("accepted"),
                  std::string("true"));
    // 故意不 stop()：模拟制品已提交、索引尚未持久化时掉电。
  }
  const auto version_dir = f.repository / "os2.pkg.crash" / "1.0";
  const auto orphan = version_dir / "artifact.bin";
  const auto stale_temp = version_dir / ".artifact.bin.tmp.crash";
  { std::ofstream out(stale_temp); out << "stale"; }
  OS2_ASSERT(std::filesystem::exists(orphan));
  OS2_ASSERT(!std::filesystem::exists(state));

  ServiceContext restarted_ctx{BusPair::make_inproc(), cfg};
  auto restarted = make_store(restarted_ctx);
  OS2_ASSERT(restarted.init() && restarted.start());
  OS2_ASSERT(!std::filesystem::exists(orphan));
  OS2_ASSERT(!std::filesystem::exists(stale_temp));
}

int main() { return os2::testing::run_all(); }
