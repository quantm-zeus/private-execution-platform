#!/usr/bin/env sh
# Fail if any Rust workspace package has no `license` field.
#
# Usage: sh scripts/release/license-check.sh
#
# `UNLICENSED` (what `license.workspace = true` resolves to here) is
# allowlisted with a warning. Requires cargo and node or python3.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
cd "$REPO_ROOT"

check_node() {
  node -e '
    "use strict";
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", function (chunk) { data += chunk; });
    process.stdin.on("end", function () {
      const meta = JSON.parse(data);
      const packages = (meta.packages || []).slice().sort(function (a, b) {
        if (a.name < b.name) return -1;
        if (a.name > b.name) return 1;
        return 0;
      });
      const missing = [];
      const unlicensed = [];
      for (const pkg of packages) {
        const license = (pkg.license || "").trim();
        process.stdout.write(
          "license-check: " + pkg.name + " -> " + (license || "(missing)") + "\n"
        );
        if (!license) {
          missing.push(pkg.name);
        } else if (license === "UNLICENSED") {
          unlicensed.push(pkg.name);
        }
      }
      if (unlicensed.length > 0) {
        process.stderr.write(
          "license-check: warning: " + unlicensed.length +
          " package(s) use UNLICENSED (allowlisted): " + unlicensed.join(", ") + "\n"
        );
      }
      if (missing.length > 0) {
        process.stderr.write(
          "license-check: error: " + missing.length +
          " package(s) missing a license field: " + missing.join(", ") + "\n"
        );
        process.exit(1);
      }
      process.stdout.write("license-check: ok (" + packages.length + " package(s))\n");
    });
  '
}

check_python() {
  python3 -c '
import json, sys
meta = json.load(sys.stdin)
packages = sorted(meta.get("packages", []), key=lambda pkg: pkg["name"])
missing = []
unlicensed = []
for pkg in packages:
    license = (pkg.get("license") or "").strip()
    print("license-check: " + pkg["name"] + " -> " + (license or "(missing)"))
    if not license:
        missing.append(pkg["name"])
    elif license == "UNLICENSED":
        unlicensed.append(pkg["name"])
if unlicensed:
    sys.stderr.write(
        "license-check: warning: " + str(len(unlicensed)) +
        " package(s) use UNLICENSED (allowlisted): " + ", ".join(unlicensed) + "\n"
    )
if missing:
    sys.stderr.write(
        "license-check: error: " + str(len(missing)) +
        " package(s) missing a license field: " + ", ".join(missing) + "\n"
    )
    sys.exit(1)
print("license-check: ok (" + str(len(packages)) + " package(s))")
'
}

if command -v node >/dev/null 2>&1; then
  cargo metadata --format-version 1 --no-deps | check_node
elif command -v python3 >/dev/null 2>&1; then
  cargo metadata --format-version 1 --no-deps | check_python
else
  printf 'license-check.sh: error: node or python3 is required\n' >&2
  exit 1
fi
