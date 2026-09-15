import assert from "node:assert/strict";
import { test } from "node:test";

import {
  buildPayloadDocument,
  rewriteAssetReferencesInHtml,
  selectRewritableAssetNames,
} from "./unlock-runtime.ts";

test("selectRewritableAssetNames keeps only path-like entries", () => {
  const selected = selectRewritableAssetNames([
    "index.html",
    "src",
    "content",
    "style",
    "assets/app-abc.js",
    "assets/app-abc.css",
  ]);
  assert.deepEqual(selected, ["assets/app-abc.css", "assets/app-abc.js"]);
  // Longest-first ordering prevents a short name matching a longer reference.
  assert.deepEqual(selectRewritableAssetNames(["assets/a.js", "assets/a.js.map"]), [
    "assets/a.js.map",
    "assets/a.js",
  ]);
});

test("a single pass never rescans an inserted blob URL", () => {
  const names = ["blob", "assets/app-abc123.js"];
  const urls = new Map([
    ["blob", "blob:https://origin/11111111-1111"],
    ["assets/app-abc123.js", "blob:https://origin/22222222-2222"],
  ]);
  const html =
    '<script src="./assets/app-abc123.js"></script><x data-src="blob"></x>';
  const out = rewriteAssetReferencesInHtml(html, names, urls);
  assert.equal(
    out,
    '<script src="blob:https://origin/22222222-2222"></script>' +
      '<x data-src="blob:https://origin/11111111-1111"></x>',
  );
});

test("handoff token is injected after rewriting and is never corrupted", () => {
  // A package file named `content` would rewrite the `content` attribute name
  // of an already-injected meta element; injection must therefore run last.
  const html =
    '<html><head><meta name="theme-color" content="#000"></head><body></body></html>';
  const assetNames = ["content", "assets/app.js"];
  const urls = new Map([
    ["content", "blob:https://origin/content"],
    ["assets/app.js", "blob:https://origin/app"],
  ]);
  const token = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
  const document = buildPayloadDocument(html, assetNames, urls, token);
  assert.ok(
    document.includes(`<meta name="evergreen-handoff" content="${token}">`),
    "handoff meta must survive intact",
  );
});

test("a path-like asset referenced in the document is substituted exactly once", () => {
  const html = '<script type="module" src="/assets/index-abc.js"></script>';
  const urls = new Map([["assets/index-abc.js", "blob:https://origin/asset"]]);
  const out = buildPayloadDocument(
    html,
    ["assets/index-abc.js"],
    urls,
    "token",
  );
  assert.ok(out.includes('src="blob:https://origin/asset"'));
  assert.ok(!out.includes('src="/assets/index-abc.js"'));
});
