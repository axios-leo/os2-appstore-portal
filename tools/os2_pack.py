#!/usr/bin/env python3
"""os2-pack（M2.3，ROADMAP §3 标准体系；M3.2 SBOM 深度依赖图）：制品打包 + SBOM + 清单。

把源目录打包为可分发制品，产出（确定性、字节可复现）：
  <out>/<id>-<ver>.tar.gz         制品包（排序 / mtime=0 / uid=gid=0 / gzip 无时间戳）
  <out>/<id>-<ver>.sbom.json      软件物料清单 os2-sbom/2：逐文件 sha256 + 大小
                                  + **依赖图谱**（C/C++ 源逐文件 #include 实扫：包内
                                  解析为依赖边 deps、包外归外部引用 external；顶层聚合
                                  external_refs 带消费方计数）——图谱从源码事实提取，
                                  非手工登记，同输入字节一致
  <out>/<id>-<ver>.manifest.json  清单（id/version/包 sha256 / sbom 引用+sha256）

签名解耦：包产出后用 `tools/sign_release.sh <pkg> <sign_dir>` 对包 sha256 签名（X.509）；
商店（appstore SignatureArtifactVerifier）/部署门（verify_release.sh）验签。清单字段
（artifact_id/version/sha256/sbom_ref）对齐 ArtifactPublish，可直接发布入库。

用法：
  os2_pack.py <src_dir> --id <artifact_id> --version <v> [-o out=build/pack]
  os2_pack.py --verify <manifest.json>   # 校验包/SBOM 与清单 sha256 一致
  os2_pack.py --graph <sbom.json>        # 依赖图谱渲染：邻接表+根/叶统计+环检测
  os2_pack.py --check <sbom.json> <advisories.json>
                                         # 漏洞/通报溯源：本地通报单匹配（sha256 精确/
                                         # 路径 glob/外部引用），命中列文件与消费方，
                                         # 命中即退出码 1（可作部署前门禁）
  os2_pack.py --selftest                 # 打包+校验+确定性+篡改拒+图谱边/环/通报溯源 自检
"""
import fnmatch
import gzip
import hashlib
import io
import json
import pathlib
import posixpath
import sys
import tarfile
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


SRC_SUFFIXES = {".hpp", ".h", ".hh", ".ipp", ".cpp", ".cc", ".c", ".cxx"}


def scan_includes(text):
    """C/C++ 源的 #include 目标列表（<> 与 "" 两式；忽略行内其余内容）。"""
    out = []
    for line in text.splitlines():
        s = line.lstrip()
        if not s.startswith("#"):
            continue
        s = s[1:].lstrip()
        if not s.startswith("include"):
            continue
        s = s[len("include"):].lstrip()
        if len(s) >= 2 and s[0] in "<\"":
            close = ">" if s[0] == "<" else "\""
            end = s.find(close, 1)
            if end > 1:
                out.append(s[1:end])
    return out


def build_dep_graph(src, files):
    """依赖图谱（os2-sbom/2）：逐文件 #include 实扫——目标在包内（按含入文件目录/
    包根两式解析、normpath 归一且不得越出包根）= 依赖边；否则 = 外部引用。
    返回 {path: (deps 排序去重, external 排序去重)}；全量确定性。"""
    inpkg = set(files)
    graph = {}
    for rel in files:
        p = src / rel
        if p.suffix.lower() not in SRC_SUFFIXES:
            continue
        deps, ext = set(), set()
        for inc in scan_includes(p.read_text(encoding="utf-8", errors="ignore")):
            hit = None
            for base in (posixpath.dirname(rel), ""):
                cand = posixpath.normpath(posixpath.join(base, inc))
                if not cand.startswith("..") and cand in inpkg:
                    hit = cand
                    break
            if hit and hit != rel:
                deps.add(hit)
            elif not hit:
                ext.add(inc)
        if deps or ext:
            graph[rel] = (sorted(deps), sorted(ext))
    return graph


def build_sbom(src, artifact_id, version):
    """逐文件 sha256 + 大小 + 依赖图谱（排序，确定性）——从源码事实提取的物料清单。"""
    files = [p.relative_to(src).as_posix() for p in sorted(src.rglob("*")) if p.is_file()]
    graph = build_dep_graph(src, files)
    comps, edge_n, ext_consumers = [], 0, {}
    for rel in files:
        p = src / rel
        c = {"path": rel, "sha256": sha256_file(p), "bytes": p.stat().st_size}
        deps, ext = graph.get(rel, ([], []))
        if deps:
            c["deps"] = deps
            edge_n += len(deps)
        if ext:
            c["external"] = ext
            for e in ext:
                ext_consumers[e] = ext_consumers.get(e, 0) + 1
        comps.append(c)
    return {"artifact_id": artifact_id, "version": version, "sbom_schema": "os2-sbom/2",
            "component_count": len(comps), "dependency_edges": edge_n,
            "external_refs": [{"ref": r, "consumers": n}
                              for r, n in sorted(ext_consumers.items())],
            "components": comps}


def pack_bytes(src, artifact_id):
    """确定性 tar.gz 字节：排序、mtime=0、uid=gid=0、gzip 无文件名/时间戳。"""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for p in sorted(src.rglob("*")):
            if not p.is_file():
                continue
            ti = tarfile.TarInfo(name=f"{artifact_id}/{p.relative_to(src).as_posix()}")
            data = p.read_bytes()
            ti.size = len(data)
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.mode = 0o644
            tar.addfile(ti, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def do_pack(src_dir, artifact_id, version, outdir):
    src = pathlib.Path(src_dir)
    if not src.is_dir():
        raise SystemExit(f"ERR  源目录不存在：{src}")
    out = pathlib.Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    base = f"{artifact_id}-{version}"

    pkg = pack_bytes(src, artifact_id)
    pkg_path = out / f"{base}.tar.gz"
    pkg_path.write_bytes(pkg)

    sbom = build_sbom(src, artifact_id, version)
    sbom_bytes = (json.dumps(sbom, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    sbom_path = out / f"{base}.sbom.json"
    sbom_path.write_bytes(sbom_bytes)

    manifest = {"artifact_id": artifact_id, "version": version,
                "package": pkg_path.name, "sha256": sha256_bytes(pkg),
                "sbom_ref": sbom_path.name, "sbom_sha256": sha256_bytes(sbom_bytes),
                "component_count": sbom["component_count"]}
    man_bytes = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    man_path = out / f"{base}.manifest.json"
    man_path.write_bytes(man_bytes)
    return man_path, pkg_path, sbom_path, manifest


def do_verify(manifest_path):
    man_path = pathlib.Path(manifest_path)
    m = json.loads(man_path.read_text(encoding="utf-8"))
    d = man_path.parent
    problems = []
    pkg = d / m["package"]
    if not pkg.exists():
        problems.append(f"包缺失 {pkg.name}")
    elif sha256_file(pkg) != m["sha256"]:
        problems.append(f"包 sha256 不符（{pkg.name} 被篡改？）")
    sbom = d / m["sbom_ref"]
    if not sbom.exists():
        problems.append(f"SBOM 缺失 {sbom.name}")
    elif sha256_file(sbom) != m["sbom_sha256"]:
        problems.append(f"SBOM sha256 不符（{sbom.name} 被篡改？）")
    if problems:
        raise SystemExit("os2-pack verify: FAIL —— " + "；".join(problems))
    print(f"os2-pack verify: OK  {m['artifact_id']}@{m['version']} "
          f"sha256={m['sha256'][:12]}… components={m.get('component_count')}")


def find_cycles(adj):
    """依赖环检测（DFS 三色）：返回环列表（每环为路径元组，起点=环内字典序最小），排序去重。"""
    WHITE, GRAY, BLACK = 0, 1, 2
    color, stack, cycles = {}, [], set()

    def dfs(u):
        color[u] = GRAY
        stack.append(u)
        for v in adj.get(u, []):
            if color.get(v, WHITE) == WHITE:
                dfs(v)
            elif color.get(v) == GRAY:
                cyc = stack[stack.index(v):]
                k = cyc.index(min(cyc))
                cycles.add(tuple(cyc[k:] + cyc[:k]))
        stack.pop()
        color[u] = BLACK

    for u in sorted(adj):
        if color.get(u, WHITE) == WHITE:
            dfs(u)
    return sorted(cycles)


def do_graph(sbom_path):
    """依赖图谱渲染：邻接表 + 根/叶/外部引用统计 + 环检测（信息面，环不判负）。"""
    s = json.loads(pathlib.Path(sbom_path).read_text(encoding="utf-8"))
    if s.get("sbom_schema") != "os2-sbom/2":
        raise SystemExit("ERR  非 os2-sbom/2（旧版 SBOM 无图谱；用新版 os2-pack 重打）")
    comps = s["components"]
    adj = {c["path"]: c.get("deps", []) for c in comps}
    dep_targets = {d for ds in adj.values() for d in ds}
    roots = [p for p, ds in adj.items() if ds and p not in dep_targets]
    print(f"os2-pack graph: {s['artifact_id']}@{s['version']}  文件 {s['component_count']} · "
          f"依赖边 {s['dependency_edges']} · 外部引用 {len(s.get('external_refs', []))}")
    for c in comps:
        deps, ext = c.get("deps", []), c.get("external", [])
        if not deps and not ext:
            continue
        print(c["path"] + ("  [根]" if c["path"] in roots else ""))
        for d in deps:
            print(f"  ├─ 依赖 → {d}")
        for e in ext:
            print(f"  └─ 外部 → {e}")
    for r in s.get("external_refs", []):
        print(f"外部引用 {r['ref']} · 消费方 {r['consumers']}")
    cycles = find_cycles(adj)
    for cyc in cycles:
        print("环: " + " → ".join(cyc) + " → " + cyc[0])
    print(f"图谱统计：根 {len(roots)} · 环 {len(cycles)}")
    return 0


def do_check(sbom_path, adv_path):
    """漏洞/通报溯源：通报单（本地 JSON）匹配 SBOM——sha256 精确 / path glob /
    外部引用精确三式；命中列出文件与（外部引用的）消费方；命中即退出码 1。
    通报单格式：{"advisories":[{"id","severity","note","match":{"sha256"|"path_glob"|"external"}}]}"""
    s = json.loads(pathlib.Path(sbom_path).read_text(encoding="utf-8"))
    advs = json.loads(pathlib.Path(adv_path).read_text(encoding="utf-8")).get("advisories", [])
    comps = s["components"]
    hits = 0
    for a in advs:
        m = a.get("match", {})
        matched = []
        if "sha256" in m:
            matched = [c["path"] for c in comps if c["sha256"] == m["sha256"]]
        elif "path_glob" in m:
            matched = [c["path"] for c in comps if fnmatch.fnmatchcase(c["path"], m["path_glob"])]
        elif "external" in m:
            matched = [c["path"] for c in comps if m["external"] in c.get("external", [])]
        if matched:
            hits += 1
            print(f"命中 {a.get('id', '?')}（{a.get('severity', '?')}）：{a.get('note', '')}")
            for p in matched:
                print(f"  受影响：{p}"
                      + ("（消费外部引用 " + m["external"] + "）" if "external" in m else ""))
    print(f"os2-pack check: {s['artifact_id']}@{s['version']} 通报 {len(advs)} 条 · 命中 {hits} 条"
          + ("（溯源见上）" if hits else "（无命中）"))
    return 1 if hits else 0


def selftest():
    with tempfile.TemporaryDirectory() as td:
        tdp = pathlib.Path(td)
        src = tdp / "svc"
        (src / "sub").mkdir(parents=True)
        (src / "a.txt").write_text("alpha\n", encoding="utf-8")
        (src / "sub" / "b.txt").write_text("beta\n", encoding="utf-8")
        # 依赖图谱 fixture：c.cpp→a.hpp→sub/b.hpp（含 "、<> 两式与外部引用）
        (src / "a.hpp").write_text('#include "sub/b.hpp"\n#include <os2/platform/api.hpp>\n',
                                   encoding="utf-8")
        (src / "sub" / "b.hpp").write_text("// leaf\n", encoding="utf-8")
        (src / "c.cpp").write_text('#include "a.hpp"\n#include <vector>\n', encoding="utf-8")
        out = tdp / "out"

        man, pkg, sbom, meta = do_pack(str(src), "os2.pkg.demo", "1.0", str(out))
        assert meta["component_count"] == 5, meta
        do_verify(str(man))

        # 图谱：边与外部引用来自 #include 实扫
        s = json.loads(sbom.read_text(encoding="utf-8"))
        comp = {c["path"]: c for c in s["components"]}
        assert s["sbom_schema"] == "os2-sbom/2" and s["dependency_edges"] == 2, s
        assert comp["c.cpp"]["deps"] == ["a.hpp"], comp["c.cpp"]
        assert comp["a.hpp"]["deps"] == ["sub/b.hpp"], comp["a.hpp"]
        assert {"ref": "os2/platform/api.hpp", "consumers": 1} in s["external_refs"], s
        assert do_graph(str(sbom)) == 0
        print("OK   图谱边/外部引用（#include 实扫 c.cpp→a.hpp→sub/b.hpp）")

        # 环检测：d1↔d2 互含
        cyc_src = tdp / "cyc"
        cyc_src.mkdir()
        (cyc_src / "d1.hpp").write_text('#include "d2.hpp"\n', encoding="utf-8")
        (cyc_src / "d2.hpp").write_text('#include "d1.hpp"\n', encoding="utf-8")
        s2 = build_sbom(cyc_src, "os2.pkg.cyc", "1.0")
        cycles = find_cycles({c["path"]: c.get("deps", []) for c in s2["components"]})
        assert cycles == [("d1.hpp", "d2.hpp")], cycles
        print("OK   依赖环检测（d1↔d2）")

        # 通报溯源：sha256 精确 / 外部引用（含消费方）命中=1，无命中=0
        adv = tdp / "adv.json"
        adv.write_text(json.dumps({"advisories": [
            {"id": "OS2-ADV-T1", "severity": "high", "note": "示例：按内容摘要溯源",
             "match": {"sha256": comp["sub/b.hpp"]["sha256"]}},
            {"id": "OS2-ADV-T2", "severity": "medium", "note": "示例：按外部引用溯源",
             "match": {"external": "os2/platform/api.hpp"}},
        ]}), encoding="utf-8")
        assert do_check(str(sbom), str(adv)) == 1
        adv.write_text(json.dumps({"advisories": [
            {"id": "OS2-ADV-T3", "severity": "low", "match": {"path_glob": "*.nomatch"}}]}),
            encoding="utf-8")
        assert do_check(str(sbom), str(adv)) == 0
        print("OK   通报溯源（sha256/外部引用命中退出码 1；无命中 0）")

        # 确定性：包与 SBOM 再产一次须逐字节一致
        pkg2 = pack_bytes(src, "os2.pkg.demo")
        assert pkg2 == pkg.read_bytes(), "非确定性：两次打包字节不一致"
        sbom2 = (json.dumps(build_sbom(src, "os2.pkg.demo", "1.0"), ensure_ascii=False,
                            sort_keys=True, indent=2) + "\n").encode()
        assert sbom2 == sbom.read_bytes(), "非确定性：两次 SBOM 字节不一致"

        # 篡改包 → verify 应拒
        pkg.write_bytes(pkg.read_bytes() + b"tampered")
        try:
            do_verify(str(man))
        except SystemExit:
            print("os2-pack selftest: PASS（打包/SBOM/清单/图谱/环/通报溯源/确定性/篡改拒 全过）")
            return 0
        raise SystemExit("os2-pack selftest: FAIL —— 篡改包未被拒")


def main(argv):
    if "--selftest" in argv:
        return selftest()
    if "--verify" in argv:
        i = argv.index("--verify")
        do_verify(argv[i + 1])
        return 0
    if "--graph" in argv:
        return do_graph(argv[argv.index("--graph") + 1])
    if "--check" in argv:
        i = argv.index("--check")
        return do_check(argv[i + 1], argv[i + 2])
    if not argv or argv[0].startswith("-"):
        raise SystemExit(__doc__)
    src = argv[0]
    opt = {"--id": None, "--version": None, "-o": str(REPO / "build/pack")}
    i = 1
    while i < len(argv):
        if argv[i] in opt:
            opt[argv[i]] = argv[i + 1]
            i += 2
        else:
            raise SystemExit(f"未知参数 {argv[i]}\n{__doc__}")
    if not opt["--id"] or not opt["--version"]:
        raise SystemExit("ERR  需 --id 与 --version")
    man, pkg, sbom, meta = do_pack(src, opt["--id"], opt["--version"], opt["-o"])
    print(f"os2-pack: {meta['artifact_id']}@{meta['version']}  "
          f"sha256={meta['sha256'][:12]}… components={meta['component_count']}")
    print(f"  package : {pkg}")
    print(f"  sbom    : {sbom}")
    print(f"  manifest: {man}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
