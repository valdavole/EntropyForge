#!/usr/bin/env node
// Reproducible core tests for the EntropyForge 3.3 HTML edition and bridge path.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import { File } from "node:buffer";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}
if (!globalThis.atob) {
  globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
}
if (!globalThis.btoa) {
  globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
}

class FakeClassList {
  constructor() {
    this.values = new Set();
  }
  toggle(name, force) {
    const enabled = force === undefined ? !this.values.has(name) : Boolean(force);
    if (enabled) this.values.add(name);
    else this.values.delete(name);
    return enabled;
  }
  add(name) { this.values.add(name); }
  remove(name) { this.values.delete(name); }
  contains(name) { return this.values.has(name); }
}

class FakeElement {
  constructor(id = "") {
    this.id = id;
    this.value = "";
    this.checked = false;
    this.disabled = false;
    this.files = [];
    this.textContent = "";
    this.className = "";
    this.style = {};
    this.dataset = {};
    this.children = [];
    this.classList = new FakeClassList();
    this.listeners = new Map();
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }
  async dispatch(type, event = { target: this }) {
    for (const listener of this.listeners.get(type) || []) await listener(event);
  }
  setAttribute() {}
  scrollIntoView() {}
  focus() {}
  click() {}
  appendChild() {}
  remove() {}
  select() {}
  closest() { return null; }
}

class FakeTextNode {
  constructor(value, tagName = "H2") {
    this.nodeValue = value;
    this.isConnected = true;
    this.parentElement = { tagName };
  }
}

const elements = new Map();
const element = (id) => {
  if (!elements.has(id)) elements.set(id, new FakeElement(id));
  return elements.get(id);
};

element("engineMode").value = "auto";
element("tokenFormat").value = "Hex";
element("externalFormat").value = "auto";
for (const id of ["pLower", "pUpper", "pDigits", "pSymbols"]) element(id).checked = true;
element("qualityMeter").children = Array.from({ length: 3 }, () => new FakeElement());

const modeCards = ["validated", "system", "hybrid", "external"].map((mode) => {
  const card = new FakeElement();
  card.dataset.mode = mode;
  return card;
});
const staticTextNodes = [new FakeTextNode("Náhodná čísla")];

globalThis.document = {
  body: { style: {}, appendChild() {} },
  getElementById: element,
  querySelectorAll(selector) { return selector === ".mode-card" ? modeCards : []; },
  addEventListener() {},
  createElement() { return new FakeElement(); },
  createTreeWalker() {
    let index = -1;
    return {
      currentNode: null,
      nextNode() {
        index += 1;
        if (index >= staticTextNodes.length) return false;
        this.currentNode = staticTextNodes[index];
        return true;
      },
    };
  },
};
globalThis.NodeFilter = { SHOW_TEXT: 4 };
globalThis.addEventListener = () => {};
Object.defineProperty(globalThis, "navigator", { value: { userAgent: "Node core test" } });
Object.defineProperty(globalThis, "screen", { value: { width: 1920, height: 1080 } });
Object.defineProperty(globalThis, "location", {
  value: { protocol: "http:", hostname: "127.0.0.1" },
});
let lastAlert = "";
globalThis.alert = (message) => { lastAlert = String(message); };
globalThis.isSecureContext = false;
let bridgeRandomFailure = false;
globalThis.fetch = async (url, options = {}) => {
  if (url === "/api/v1/status") {
    return new Response(JSON.stringify({
      profile: "entropyforge.windows-cng.strict.v1",
      ready: true,
      fips_policy_enabled: true,
      evidence_state: "matched-active",
      certificate: "CMVP #4825",
      claim_limit: "The module certificate is not an EntropyForge certificate.",
      issues: [],
      summary: "ready",
    }), { status: 200, headers: { "Content-Type": "application/json" } });
  }
  if (url === "/api/v1/random") {
    if (bridgeRandomFailure) {
      return new Response(JSON.stringify({ error: "simulated strict failure" }), {
        status: 503,
        headers: { "Content-Type": "application/json" },
      });
    }
    const request = JSON.parse(options.body);
    const output = new Uint8Array(request.bytes);
    for (let offset = 0; offset < output.length; offset += 65536) {
      crypto.getRandomValues(output.subarray(offset, Math.min(offset + 65536, output.length)));
    }
    return new Response(JSON.stringify({
      bytes: output.length,
      data_base64: Buffer.from(output).toString("base64"),
      profile: "entropyforge.windows-cng.strict.v1",
    }), { status: 200, headers: { "Content-Type": "application/json" } });
  }
  throw new Error(`Unexpected fetch target: ${url}`);
};

const projectDir = new URL("../", import.meta.url);
const html = await readFile(new URL("EntropyForge.html", projectDir), "utf8");
assert.match(html, /connect-src 'self'/, "CSP must restrict bridge connections to same origin");
assert.doesNotMatch(html, /<script[^>]+src=/i, "Standalone HTML must not load external scripts");
assert.match(html, /\.quality-badge\{[^}]*justify-content:center/, "Quality badge text must be centered");
assert.match(html, /id="languageSelect"/, "Language selector is missing");
assert.match(html, /\["Náhodná čísla","Random numbers"\]/, "English static UI catalog is missing");
const meterMarkup = html.match(/<div id="qualityMeter"[\s\S]*?<\/div>/);
assert.ok(meterMarkup, "Quality meter markup was not found");
assert.equal((meterMarkup[0].match(/<i/g) || []).length, 3, "Quality meter must have three layers");
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, "HTML script block was not found");
eval(scriptMatch[1]);

for (let attempt = 0; attempt < 400 && element("genNumbers").disabled; attempt += 1) {
  await new Promise((resolve) => setTimeout(resolve, 5));
}
assert.equal(element("genNumbers").disabled, false, "Web Crypto boot did not complete");

const core = globalThis.__EntropyForgeCore;
assert.ok(core, "Testable HTML core was not exported");
assert.deepEqual(core.DIVERSITY_LEVELS, { validated: 1, system: 1, hybrid: 2, external: 3 });
assert.equal(core.bridgeReady(), true, "Loopback strict bridge was not detected");
assert.equal(element("validatedModeOption").disabled, false);
assert.equal(element("qualityLevelText").textContent, "VRSTVY: 2/3");
assert.equal(
  element("qualityMeter").children.filter((bar) => bar.classList.contains("on")).length,
  2,
);

element("outNumbers").textContent = "123456789";
element("languageSelect").value = "en";
await element("languageSelect").dispatch("change");
assert.equal(element("qualityLevelText").textContent, "LAYERS: 2/3");
assert.equal(element("qualityBadge").textContent, "DIVERSIFIED");
assert.match(element("entropyStatus").textContent, /^Supplementary timing:/);
assert.equal(element("hardwareState").textContent, "No external source is connected.");
assert.equal(element("outNumbers").textContent, "123456789", "Language switch changed generated output");
assert.equal(staticTextNodes[0].nodeValue, "Random numbers");
element("nMin").value = "1";
element("nMax").value = "100";
element("nCount").value = "0";
await element("genNumbers").dispatch("click");
assert.match(lastAlert, /Count must be between 1 and 100000\./);
element("nCount").value = "1";

element("languageSelect").value = "cs";
await element("languageSelect").dispatch("change");
assert.equal(element("qualityLevelText").textContent, "VRSTVY: 2/3");
assert.equal(element("qualityBadge").textContent, "DIVERZIFIKOVANÝ");
assert.match(element("entropyStatus").textContent, /^Doplňkové časování:/);
assert.equal(staticTextNodes[0].nodeValue, "Náhodná čísla");

element("engineMode").value = "system";
await element("engineMode").dispatch("change");
assert.equal(element("qualityLevelText").textContent, "VRSTVY: 1/3");
assert.equal(element("qualityBadge").textContent, "SYSTÉMOVÝ\nCSPRNG");
assert.equal(
  element("qualityMeter").children.filter((bar) => bar.classList.contains("on")).length,
  1,
);

element("engineMode").value = "hybrid";
await element("engineMode").dispatch("change");
assert.equal(element("qualityLevelText").textContent, "VRSTVY: 2/3");
const smokeReports = [];
const bitCounts = Uint8Array.from({ length: 256 }, (_, value) => {
  let count = 0;
  for (let current = value; current; current >>= 1) count += current & 1;
  return count;
});
function statisticalSmoke(sample, label) {
  const frequencies = new Uint32Array(256);
  const blocks = new Set();
  let ones = 0;
  for (let index = 0; index < sample.length; index += 1) {
    frequencies[sample[index]] += 1;
    ones += bitCounts[sample[index]];
    if (index % 64 === 0) blocks.add(core.bytesToHex(sample.subarray(index, index + 64)));
  }
  const ratio = ones / (sample.length * 8);
  const expected = sample.length / 256;
  let chiSquare = 0;
  for (const frequency of frequencies) chiSquare += (frequency - expected) ** 2 / expected;
  const duplicateBlocks = Math.ceil(sample.length / 64) - blocks.size;
  assert.ok(ratio > 0.48 && ratio < 0.52, `${label} bit ratio outside smoke bounds`);
  assert.ok(chiSquare > 100 && chiSquare < 450, `${label} byte chi-square outside smoke bounds`);
  assert.equal(duplicateBlocks, 0, `${label} repeated a 64-byte block`);
  smokeReports.push(
    `${label}: ${sample.length} B, ones=${(ratio * 100).toFixed(4)} %, chi2=${chiSquare.toFixed(2)}, duplicate64=${duplicateBlocks}`,
  );
}

const expectedExpansion =
  "08eaa0e330e829a365a7c277861b8a9cdae058401243e6f7dcaa6d141ca8500f" +
  "95c6f8578e20c5a391d344b0163b1c9c513acb0aff2aa6118eef60d983c0fe40" +
  "a92e92e755df5169855f1786ba94f0fba6d4d10e727287c1bb1338e6df58abef";
const expanded = await core.expandedStream(Uint8Array.from({ length: 64 }, (_, i) => i), 96, "stream|");
assert.equal(core.bytesToHex(expanded), expectedExpansion, "HMAC expansion KAT mismatch");

const raw = Uint8Array.from({ length: 4096 }, (_, index) => index & 255);
const encoder = new TextEncoder();
const representations = {
  hex: encoder.encode(core.bytesToHex(raw)),
  base64Padded: encoder.encode(Buffer.from(raw).toString("base64url") + "=="),
  base64Unpadded: encoder.encode(Buffer.from(raw).toString("base64url")),
  decimal: encoder.encode(Array.from(raw).join(" ")),
  bits: encoder.encode(Array.from(raw, (value) => value.toString(2).padStart(8, "0")).join("")),
};

for (const [name, encoded] of Object.entries(representations)) {
  const decoded = core.decodeExternalData(encoded, "auto").bytes;
  assert.deepEqual(Buffer.from(decoded), Buffer.from(raw), `${name} did not round-trip`);
}

const tooSmall = Uint8Array.from({ length: 3072 }, (_, index) => index & 255);
const tooSmallBase64 = encoder.encode(Buffer.from(tooSmall).toString("base64url"));
assert.throws(
  () => core.basicExternalTest(core.decodeExternalData(tooSmallBase64, "auto").bytes),
  /alespoň 4096/,
);
assert.throws(() => core.basicExternalTest(new Uint8Array(4096)), /degenerovaný/);

for (const mode of ["validated", "system", "hybrid"]) {
  element("engineMode").value = mode;
  const first = await core.randomBytes(128);
  const second = await core.randomBytes(128);
  assert.equal(first.length, 128);
  assert.notDeepEqual(Buffer.from(first), Buffer.from(second));
  statisticalSmoke(await core.randomBytes(262_144), `HTML ${mode}`);
}

element("engineMode").value = "validated";
bridgeRandomFailure = true;
await assert.rejects(
  () => core.randomBytes(32),
  /simulated strict failure/,
  "Strict bridge failure must not fall back to Web Crypto",
);
assert.equal(core.bridgeReady(), false, "Strict bridge error state must be sticky");
bridgeRandomFailure = false;

element("engineMode").value = "hybrid";
const seen = new Set();
for (let index = 0; index < 5000; index += 1) {
  const value = Number(await core.randBelow(10n));
  assert.ok(value >= 0 && value < 10);
  seen.add(value);
}
assert.equal(seen.size, 10, "randBelow did not cover every value in the smoke sample");

assert.equal(core.MIN_EXTERNAL_BYTES, 4096);
assert.equal(core.MAX_EXTERNAL_SOURCES, 8);
assert.equal(core.MAX_INTEGER_DIGITS, 2000);

element("nMin").value = "-50";
element("nMax").value = "50";
element("nCount").value = "100";
element("nUnique").checked = true;
await element("genNumbers").dispatch("click");
const generatedNumbers = element("outNumbers").textContent.split("\n");
assert.equal(generatedNumbers.length, 100);
assert.equal(new Set(generatedNumbers).size, 100);

element("choiceInput").value = "A\nA\nB";
element("choiceCount").value = "2";
element("choiceUnique").checked = true;
await element("genChoices").dispatch("click");
const generatedChoices = element("outChoices").textContent.split("\n");
assert.equal(generatedChoices.length, 2);
assert.equal(new Set(generatedChoices).size, 2);

element("passLength").value = "24";
element("passCount").value = "10";
await element("genPasswords").dispatch("click");
for (const password of element("outPasswords").textContent.split("\n")) {
  assert.equal(password.length, 24);
  assert.match(password, /[a-z]/);
  assert.match(password, /[A-Z]/);
  assert.match(password, /\d/);
  assert.match(password, /[!#$%&()*+,\-./:;<=>?@\[\]^_{|}~]/);
}

element("tokenFormat").value = "UUID v4";
element("byteCount").value = "neplatná ignorovaná hodnota";
element("tokenCount").value = "10";
await element("tokenFormat").dispatch("change");
await element("genTokens").dispatch("click");
for (const uuid of element("outTokens").textContent.split("\n")) {
  assert.match(uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
}

element("externalFormat").value = "binary";
element("engineMode").value = "auto";
element("hardwareFile").files = [new File([raw], "external.bin")];
await element("hardwareFile").dispatch("change");
assert.equal(element("externalModeOption").disabled, false);
assert.match(element("hardwareState").textContent, /4\s*096 B zdrojových dat/);
assert.equal(element("activeEngine").textContent, "Vícezdrojový režim (1 externí komponenta)");
assert.equal(element("qualityLevelText").textContent, "VRSTVY: 3/3");
statisticalSmoke(await core.randomBytes(262_144), "HTML external");

const bundleSourceBytes = Uint8Array.from({ length: 32 }, (_, index) => index);
const bundleSourceHash = core.bytesToHex(await core.sha256(bundleSourceBytes));
const bundlePayload = {
  collector: "EntropyForge test collector",
  created_utc: "2026-07-29T12:34:56Z",
  schema: "entropyforge.remote-payload.v1",
  sources: [{
    data_base64: Buffer.from(bundleSourceBytes).toString("base64"),
    data_sha256: bundleSourceHash,
    id: "test.public",
    kind: "public_beacon",
    label: "Test public beacon",
    metadata: { round: 123, signature_hex: "ab".repeat(48) },
    validation: ["HTTPS certificate validation", "Fixture proof checked"],
    visibility: "public",
  }],
};
const payloadBytes = encoder.encode(core.stableStringify(bundlePayload));
const bundleOuter = {
  payload_base64: Buffer.from(payloadBytes).toString("base64"),
  payload_sha256: core.bytesToHex(await core.sha256(payloadBytes)),
  schema: "entropyforge.remote-bundle.v1",
};
const bundleBytes = encoder.encode(core.stableStringify(bundleOuter) + "\n");
const parsedBundle = await core.parseRemoteBundle(bundleBytes);
assert.equal(parsedBundle.sourceCount, 1);
assert.equal(parsedBundle.publicCount, 1);
assert.equal(parsedBundle.totalRandomBytes, 32);
assert.equal(
  parsedBundle.fingerprint,
  "24506993cbe7225548312fe1c174b4bfaca81e90c2ba137243cc1f47a4ab0b9a",
  "portable bundle fingerprint differs from Python",
);
const duplicateDataPayload = structuredClone(bundlePayload);
duplicateDataPayload.sources.push({
  ...structuredClone(bundlePayload.sources[0]),
  id: "test.same-data",
  label: "Same data under another identity",
});
const duplicateDataPayloadBytes = encoder.encode(core.stableStringify(duplicateDataPayload));
const duplicateDataOuter = {
  payload_base64: Buffer.from(duplicateDataPayloadBytes).toString("base64"),
  payload_sha256: core.bytesToHex(await core.sha256(duplicateDataPayloadBytes)),
  schema: "entropyforge.remote-bundle.v1",
};
await assert.rejects(
  () => core.parseRemoteBundle(encoder.encode(core.stableStringify(duplicateDataOuter) + "\n")),
  /stejná náhodná data/,
);
const invalidDatePayload = { ...bundlePayload, created_utc: "2026-02-30T12:34:56Z" };
const invalidDatePayloadBytes = encoder.encode(core.stableStringify(invalidDatePayload));
const invalidDateOuter = {
  payload_base64: Buffer.from(invalidDatePayloadBytes).toString("base64"),
  payload_sha256: core.bytesToHex(await core.sha256(invalidDatePayloadBytes)),
  schema: "entropyforge.remote-bundle.v1",
};
await assert.rejects(
  () => core.parseRemoteBundle(encoder.encode(core.stableStringify(invalidDateOuter) + "\n")),
  /created_utc/,
);
const unsafeMetadataPayload = structuredClone(bundlePayload);
unsafeMetadataPayload.sources[0].metadata = { unsafe_integer: 2 ** 53 };
const unsafeMetadataPayloadBytes = encoder.encode(core.stableStringify(unsafeMetadataPayload));
const unsafeMetadataOuter = {
  payload_base64: Buffer.from(unsafeMetadataPayloadBytes).toString("base64"),
  payload_sha256: core.bytesToHex(await core.sha256(unsafeMetadataPayloadBytes)),
  schema: "entropyforge.remote-bundle.v1",
};
await assert.rejects(
  () => core.parseRemoteBundle(encoder.encode(core.stableStringify(unsafeMetadataOuter) + "\n")),
  /přenositelné bezpečné celé číslo/,
);
const wrongChecksumOuter = { ...bundleOuter, payload_sha256: "0".repeat(64) };
await assert.rejects(
  () => core.parseRemoteBundle(encoder.encode(core.stableStringify(wrongChecksumOuter) + "\n")),
  /součet/,
);
const duplicatePayloadText = core.stableStringify(bundlePayload).replace(
  /}$/,
  ',"schema":"entropyforge.remote-payload.v1"}',
);
const duplicatePayloadBytes = encoder.encode(duplicatePayloadText);
const duplicateOuter = {
  payload_base64: Buffer.from(duplicatePayloadBytes).toString("base64"),
  payload_sha256: core.bytesToHex(await core.sha256(duplicatePayloadBytes)),
  schema: "entropyforge.remote-bundle.v1",
};
await assert.rejects(
  () => core.parseRemoteBundle(encoder.encode(core.stableStringify(duplicateOuter) + "\n")),
  /kanonickém JSON tvaru|duplicitní/,
);

element("externalFormat").value = "auto";
element("hardwareFile").files = [new File([bundleBytes], "remote.efb")];
await element("hardwareFile").dispatch("change");
assert.equal(core.externalSourceCount(), 2);
assert.equal(element("qualityBadge").textContent, "2 EXTERNÍ\nZDROJE");
assert.match(element("qualityDesc").textContent, /nejsou tajnou entropií/);

lastAlert = "";
element("hardwareFile").files = [new File([bundleBytes], "remote-copy.efb")];
await element("hardwareFile").dispatch("change");
assert.equal(core.externalSourceCount(), 2, "duplicate bundle must not be stacked");
assert.match(lastAlert, /už byl/);

await element("removeHardware").dispatch("click");
assert.equal(core.externalSourceCount(), 1);
assert.equal(element("externalModeOption").disabled, false);
assert.equal(element("qualityLevelText").textContent, "VRSTVY: 3/3");
await element("removeAllHardware").dispatch("click");
assert.equal(core.externalSourceCount(), 0);
assert.equal(element("externalModeOption").disabled, true);
assert.equal(element("activeEngine").textContent, "Diverzifikovaný software");
assert.equal(element("qualityLevelText").textContent, "VRSTVY: 2/3");
lastAlert = "";
element("hardwareFile").files = [new File([bundleBytes], "remote-after-remove.efb")];
await element("hardwareFile").dispatch("change");
assert.equal(core.externalSourceCount(), 0, "session replay must remain rejected after removal");
assert.match(lastAlert, /už byl/);

for (const report of smokeReports) console.log(report);
console.log("HTML core tests: PASS");
