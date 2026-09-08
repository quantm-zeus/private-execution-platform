import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { decryptArtifactFile } from "./decrypt-workspace-artifact.mjs";
import { packDirectory } from "./workspace-artifact.mjs";

function run(args, env = process.env) {
  const result = spawnSync("pnpm", args, { stdio: "inherit", env });
  if (result.status !== 0) throw new Error(`command failed: pnpm ${args.join(" ")}`);
}
async function filesUnder(root) {
  const out=[];
  async function walk(dir){ for(const name of (await readdir(dir)).sort()){ const p=join(dir,name); const s=await stat(p); if(s.isDirectory()) await walk(p); else if(s.isFile()) out.push(p); } }
  await walk(root); return out;
}
function digest(buf){ return createHash("sha256").update(buf).digest("hex"); }

const publicOut=resolve("web/public/.output");
const workspaceDist=resolve("web/workspace/dist");
const artifactPath=resolve("web/workspace-artifact/blob.bin");
const forbidden=["@evergreen/workspace","web/workspace","swap","wallet","jupiter","raydium","uniswap","limit_order","privy","trading-core","/v1/stream"];
let key;
let temp;
try {
  run(["build:public"]);
  for(const path of await filesUnder(publicOut)){
    if(path.endsWith(".map")) throw new Error("public source map detected");
    if(/\.(?:m?js|html|css|json)$/i.test(path)){
      const text=(await readFile(path,"utf8")).toLowerCase();
      for(const term of forbidden){ if(text.includes(term.toLowerCase())) throw new Error(`public bundle privacy term detected: ${term}`); }
    }
  }
  run(["build:workspace"]);
  const expected=await packDirectory(workspaceDist);
  const expectedHash=digest(expected);
  key=randomBytes(32).toString("base64");
  run(["build:workspace:encrypted"], { ...process.env, WORKSPACE_ARTIFACT_KEY_B64:key });
  try { await stat(workspaceDist); throw new Error("plaintext workspace build remains"); } catch(e){ if(e?.code!=="ENOENT") throw e; }
  const raw=await readFile(artifactPath);
  for(const clear of ["index.html","Workspace","workspace"]){ if(raw.includes(Buffer.from(clear))) throw new Error("artifact leaks plaintext metadata"); }
  const { plaintext }=await decryptArtifactFile(artifactPath,{WORKSPACE_ARTIFACT_KEY_B64:key});
  if(digest(plaintext)!==expectedHash) throw new Error("artifact roundtrip mismatch");
  const tampered=Buffer.from(raw); tampered[tampered.length-1]^=1;
  temp=await mkdtemp(join(tmpdir(),"web-boundary-"));
  const tamperedPath=join(temp,"blob.bin");
  const { writeFile }=await import("node:fs/promises"); await writeFile(tamperedPath,tampered);
  let rejected=false;
  try{ await decryptArtifactFile(tamperedPath,{WORKSPACE_ARTIFACT_KEY_B64:key}); }catch{ rejected=true; }
  if(!rejected) throw new Error("tampered artifact accepted");
  console.log("web boundary verification passed");
} finally {
  key=undefined;
  delete process.env.WORKSPACE_ARTIFACT_KEY_B64;
  if(temp) await rm(temp,{recursive:true,force:true}).catch(()=>{});
  await rm(workspaceDist,{recursive:true,force:true}).catch(()=>{});
}
