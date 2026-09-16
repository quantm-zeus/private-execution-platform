#!/usr/bin/env sh
# Emit an SPDX-ish JSON SBOM for the Rust workspace.
#
# Usage: sh scripts/release/sbom.sh [OUT_PATH]
#   OUT_PATH defaults to target/release/sbom.json. Use "-" to write to stdout.
#
# Requires: cargo (for `cargo metadata`), git (optional), and node or python3.
# No network access is required. No credentials are read or printed.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
cd "$REPO_ROOT"

OUT="${1:-target/release/sbom.json}"

SOURCE_COMMIT=$(git rev-parse HEAD 2>/dev/null || printf 'unknown')
SBOM_CREATED=$(git show -s --format=%cI HEAD 2>/dev/null || printf '1970-01-01T00:00:00Z')
export SOURCE_COMMIT SBOM_CREATED

sbom_node() {
  node -e '
    "use strict";
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", function (chunk) { data += chunk; });
    process.stdin.on("end", function () {
      const meta = JSON.parse(data);
      const packages = (meta.packages || [])
        .map(function (pkg) {
          const license = pkg.license || "NOASSERTION";
          return {
            SPDXID: "SPDXRef-Package-" + pkg.name,
            name: pkg.name,
            versionInfo: pkg.version,
            licenseDeclared: license,
            licenseConcluded: license,
            downloadLocation: "NOASSERTION",
            filesAnalyzed: false,
            copyrightText: "NOASSERTION"
          };
        })
        .sort(function (a, b) {
          if (a.name < b.name) return -1;
          if (a.name > b.name) return 1;
          return 0;
        });
      const doc = {
        spdxVersion: "SPDX-2.3",
        dataLicense: "CC0-1.0",
        SPDXID: "SPDXRef-DOCUMENT",
        name: "private-execution-platform",
        documentNamespace:
          "https://spdx.org/spdxdocs/private-execution-platform-" + process.env.SOURCE_COMMIT,
        creationInfo: {
          creators: ["Tool: scripts/release/sbom.sh"],
          created: process.env.SBOM_CREATED
        },
        sourceCommit: process.env.SOURCE_COMMIT,
        packages: packages,
        relationships: packages.map(function (pkg) {
          return {
            spdxElementId: "SPDXRef-DOCUMENT",
            relationshipType: "DESCRIBES",
            relatedSpdxElement: pkg.SPDXID
          };
        })
      };
      process.stdout.write(JSON.stringify(doc, null, 2) + "\n");
    });
  '
}

sbom_python() {
  python3 -c '
import json, os, sys
meta = json.load(sys.stdin)
packages = []
for pkg in meta.get("packages", []):
    license = pkg.get("license") or "NOASSERTION"
    packages.append({
        "SPDXID": "SPDXRef-Package-" + pkg["name"],
        "name": pkg["name"],
        "versionInfo": pkg["version"],
        "licenseDeclared": license,
        "licenseConcluded": license,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "copyrightText": "NOASSERTION",
    })
packages.sort(key=lambda entry: entry["name"])
doc = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "private-execution-platform",
    "documentNamespace": "https://spdx.org/spdxdocs/private-execution-platform-" + os.environ["SOURCE_COMMIT"],
    "creationInfo": {
        "creators": ["Tool: scripts/release/sbom.sh"],
        "created": os.environ["SBOM_CREATED"],
    },
    "sourceCommit": os.environ["SOURCE_COMMIT"],
    "packages": packages,
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package["SPDXID"],
        }
        for package in packages
    ],
}
json.dump(doc, sys.stdout, indent=2)
sys.stdout.write("\n")
'
}

generate_sbom() {
  if command -v node >/dev/null 2>&1; then
    cargo metadata --format-version 1 --no-deps | sbom_node
  elif command -v python3 >/dev/null 2>&1; then
    cargo metadata --format-version 1 --no-deps | sbom_python
  else
    printf 'sbom.sh: error: node or python3 is required\n' >&2
    exit 1
  fi
}

if [ "$OUT" = "-" ]; then
  generate_sbom
else
  mkdir -p -- "$(dirname -- "$OUT")"
  generate_sbom > "$OUT"
  printf 'sbom.sh: wrote %s\n' "$OUT" >&2
fi
