import { readFile, stat } from "node:fs/promises";
import {
  artifactKidFromEnv,
  decryptArtifact,
  unlockSecretFromEnv,
  unpackPackage,
  writeUnpacked,
  MIN_ARTIFACT_BYTES,
  MAX_PACKAGE_BYTES,
} from "./workspace-artifact.mjs";

export async function decryptArtifactFile(path, env = process.env) {
  const secret = unlockSecretFromEnv(env);
  const kid = artifactKidFromEnv(env);
  try {
    const st = await stat(path);
    if (!st.isFile()) {
      throw new Error("artifact path is not a file");
    }
    if (st.size < MIN_ARTIFACT_BYTES || st.size > MAX_PACKAGE_BYTES) {
      throw new Error("artifact file size out of bounds");
    }
    const plaintext = await decryptArtifact(await readFile(path), secret, kid);
    return { plaintext, files: unpackPackage(plaintext) };
  } finally {
    secret.fill(0);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [artifactPath, outputDir] = process.argv.slice(2);
  if (!artifactPath || !outputDir) {
    throw new Error("artifact path and output directory required");
  }
  const { files } = await decryptArtifactFile(artifactPath);
  await writeUnpacked(files, outputDir);
}
