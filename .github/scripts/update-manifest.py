#!/usr/bin/env python3
"""Add (or replace) a version entry in the Jellyfin plugin repository manifest.

The manifest is the JSON file Jellyfin downloads when the repository URL is added under
Dashboard -> Plugins -> Repositories. Plugin-level fields come from meta.json; the
version entry comes from the command line.
"""

import argparse
import json
import pathlib
import sys


def version_key(v: str):
    return tuple(int(p) for p in v.split("."))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True, type=pathlib.Path)
    ap.add_argument("--meta", required=True, type=pathlib.Path)
    ap.add_argument("--version", required=True)
    ap.add_argument("--source-url", required=True)
    ap.add_argument("--checksum", required=True, help="MD5 of the zip")
    ap.add_argument("--timestamp", required=True)
    ap.add_argument("--changelog", default="")
    args = ap.parse_args()

    meta = json.loads(args.meta.read_text(encoding="utf-8"))

    manifest = []
    if args.manifest.exists() and args.manifest.read_text(encoding="utf-8").strip():
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))

    plugin = next((p for p in manifest if p.get("guid") == meta["guid"]), None)
    if plugin is None:
        plugin = {"guid": meta["guid"], "versions": []}
        manifest.append(plugin)

    for key in ("name", "description", "overview", "owner", "category"):
        plugin[key] = meta[key]
    if meta.get("imageUrl"):
        plugin["imageUrl"] = meta["imageUrl"]

    entry = {
        "version": args.version,
        "changelog": args.changelog or meta.get("changelog", ""),
        "targetAbi": meta["targetAbi"],
        "sourceUrl": args.source_url,
        "checksum": args.checksum,
        "timestamp": args.timestamp,
    }

    versions = [v for v in plugin.get("versions", []) if v.get("version") != args.version]
    versions.append(entry)
    versions.sort(key=lambda v: version_key(v["version"]), reverse=True)
    plugin["versions"] = versions

    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"{args.manifest}: {meta['name']} {args.version} ({len(versions)} version(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
