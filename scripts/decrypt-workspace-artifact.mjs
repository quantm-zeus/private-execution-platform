import { readFile, stat } from "node:fs/promises";
import {
  artifactKidFromEnv,
  decryptArtifact,
  decryptRootArtifact,
  unlockSecretFromEnv,
  unpackPackage,
  writeUnpacked,
  MIN_ARTIFACT_BYTES,
  MAX_PACKAGE_BYTES,
} from "./workspace-artifact.mjs";

export async function decryptArtifactFile(path, env = process.env) {
  if (env.WORKSPACE_ARTIFACT_KEY_B64) {
    throw new Error(
      "WORKSPACE_ARTIFACT_KEY_B64 is forbidden; artifact decryption requires client-held WORKSPACE_UNLOCK_SECRET_B64 and canonical WORKSPACE_ARTIFACT_KID_B64",
    );
  }
  const secret = unlockSecretFromEnv(env);
  // Root-Key-V2 mode takes no artifact KID: the KID is bound inside the sealed
  // envelope, so it is read from the artifact rather than from the caller.
  const rootKeyV2 = env.WORKSPACE_ROOT_KEY_V2 === "true";
  try {
    const st = await stat(path);
    if (!st.isFile()) {
      throw new Error("artifact path is not a file");
    }
    if (st.size < MIN_ARTIFACT_BYTES || st.size > MAX_PACKAGE_BYTES) {
      throw new Error("artifact file size out of bounds");
    }
    const artifact = await readFile(path);
    const plaintext = rootKeyV2
      ? await decryptRootArtifact(artifact, secret)
      : await decryptArtifact(artifact, secret, artifactKidFromEnv(env));
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
