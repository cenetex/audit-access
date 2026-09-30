import assert from "node:assert/strict";
import { test } from "node:test";

import { b58decode, checkRequest, enrolStatement } from "./check.mjs";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58encode(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (const byte of bytes) {
    if (byte !== 0) break;
    out += "1";
  }
  for (let i = digits.length - 1; i >= 0; i--) out += ALPHABET[digits[i]];
  return out;
}

const DRAFT = "3f1c1c1e-1b7a-4c3e-9a55-0d4f6a1b2c3d";
const ENC = "07203f7d08cb9ff98b92f6e4d50dba339905946ddeee2a681a7b8efb50ffee7a";

async function request(over = {}) {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const wallet = b58encode(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const sign = async (text) => b58encode(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, new TextEncoder().encode(text))));
  const body = { audit: "001", wallet, enc_pub: ENC, draft: DRAFT, signature: await sign(enrolStatement("001", ENC)), ...over };
  return { wallet, sign, body };
}

const run = (wallet, body, name) => checkRequest(name ?? `requests/${wallet}.json`, JSON.stringify(body));

test("a signed request from the wallet it names passes", async () => {
  const { wallet, body } = await request();
  assert.deepEqual(await run(wallet, body), []);
});

test("base58 decoding is exact", () => {
  assert.equal(new TextDecoder().decode(b58decode("2NEpo7TZRRrLZSi2U", 12)), "Hello World!");
  assert.equal(b58decode("2NEpo7TZRRrLZSi2U", 11), null);
  assert.equal(b58decode("0OIl", 3), null);
});

test("a signature by another wallet, or over another key, fails", async () => {
  const a = await request();
  const b = await request();
  assert.match((await run(a.wallet, { ...a.body, signature: b.body.signature }))[0], /does not match/);
  assert.match((await run(a.wallet, { ...a.body, enc_pub: "a".repeat(64) }))[0], /does not match/);
});

test("the file name must be the wallet and the path must be under requests", async () => {
  const a = await request();
  const b = await request();
  assert.match((await run(a.wallet, a.body, `requests/${b.wallet}.json`))[0], /file name must be the wallet/);
  assert.match((await run(a.wallet, a.body, "README.md"))[0], /requests\/<wallet address>\.json/);
  assert.match((await run(a.wallet, a.body, `requests/${a.wallet}.txt`))[0], /requests\/<wallet address>\.json/);
  assert.match((await run(a.wallet, a.body, `requests/../${a.wallet}.json`))[0], /requests\/<wallet address>\.json/);
});

test("malformed content is reported, not thrown", async () => {
  const { wallet, body } = await request();
  assert.match((await checkRequest(`requests/${wallet}.json`, "not json"))[0], /not valid JSON/);
  assert.match((await run(wallet, { ...body, draft: "nope" }))[0], /draft id/);
  assert.match((await run(wallet, { ...body, enc_pub: "xyz" }))[0], /64 hex/);
  assert.match((await run(wallet, { audit: "001" }))[0], /as strings/);
  assert.match((await checkRequest(`requests/${wallet}.json`, JSON.stringify({ ...body, pad: "x".repeat(3000) })))[0], /larger than/);
});
