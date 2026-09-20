#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

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

int main() { return os2::testing::run_all(); }
