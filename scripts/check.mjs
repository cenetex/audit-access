// Checks a request file the way the auditor will: shape, name, and the wallet's signature.
// Usage: node check.mjs <file>...     Exits 1 with every problem found.
//
// This check is advisory. It tells a reviewer that a request is well formed and signed by the
// wallet it names. Whether the wallet is on an audit's reviewer list is for the auditor to decide,
// and a request for a wallet that is not on the list is simply left alone.

import { readFileSync } from "node:fs";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const WALLET = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const PATH = /^requests\/([1-9A-HJ-NP-Za-km-z]{32,44})\.json$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BYTES = 2048;

export function b58decode(text, length) {
  if (typeof text !== "string" || !text.length) return null;
  const bytes = [0];
  for (const char of text) {
    const value = ALPHABET.indexOf(char);
    if (value < 0) return null;
    let carry = value;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of text) {
    if (char !== "1") break;
    bytes.push(0);
  }
  const out = Uint8Array.from(bytes.reverse());
  return out.length === length ? out : null;
}

export const enrolStatement = (audit, encPub) => `ratiaudit enrol v1\naudit: ${audit}\nencryption key: ${encPub}`;

// Returns a list of problems; empty means the request is well formed and correctly signed.
export async function checkRequest(path, text) {
  const problems = [];
  const named = PATH.exec(path);
  if (!named) return [`${path}: a request must be requests/<wallet address>.json`];
  if (new TextEncoder().encode(text).length > MAX_BYTES) return [`${path}: larger than ${MAX_BYTES} bytes`];
  let request;
  try {
    request = JSON.parse(text);
  } catch {
    return [`${path}: not valid JSON`];
  }
  const { audit, wallet, enc_pub: encPub, signature, draft } = request ?? {};
  if (![audit, wallet, encPub, signature, draft].every((v) => typeof v === "string")) {
    return [`${path}: needs audit, wallet, enc_pub, signature and draft as strings`];
  }
  if (!WALLET.test(wallet)) problems.push(`${path}: wallet is not a Solana address`);
  if (wallet !== named[1]) problems.push(`${path}: the file name must be the wallet address inside it`);
  if (!/^[0-9a-f]{64}$/.test(encPub)) problems.push(`${path}: enc_pub must be 64 hex characters`);
  if (!UUID.test(draft)) problems.push(`${path}: draft must be the audit's draft id`);
  if (problems.length) return problems;
  const publicKey = b58decode(wallet, 32);
  const sig = b58decode(signature, 64);
  if (!publicKey || !sig) return [`${path}: wallet or signature is not base58 of the right length`];
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, new TextEncoder().encode(enrolStatement(audit, encPub)));
    if (!ok) problems.push(`${path}: the signature does not match the wallet`);
  } catch {
    problems.push(`${path}: the signature could not be checked`);
  }
  return problems;
}

async function main(files) {
  if (!files.length) {
    console.log("no request files in this change");
    return 0;
  }
  let failed = 0;
  for (const file of files) {
    const problems = await checkRequest(file, readFileSync(file, "utf8"));
    for (const problem of problems) console.log(`::error::${problem}`);
    if (problems.length) failed += 1;
    else console.log(`ok  ${file}`);
  }
  return failed ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exit(await main(process.argv.slice(2)));
