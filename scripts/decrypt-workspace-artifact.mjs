import { readFile } from "node:fs/promises";
import { artifactKeyFromEnv, decryptArtifact, unpackPackage, writeUnpacked } from "./workspace-artifact.mjs";

export async function decryptArtifactFile(path, env = process.env) {
  const key = artifactKeyFromEnv(env);
  try {
    const plaintext = decryptArtifact(await readFile(path), key);
    return { plaintext, files: unpackPackage(plaintext) };
  } finally {
    key.fill(0);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [artifactPath, outputDir] = process.argv.slice(2);
  if (!artifactPath || !outputDir) throw new Error("artifact path and output directory required");
  const { files } = await decryptArtifactFile(artifactPath);
  await writeUnpacked(files, outputDir);
}
