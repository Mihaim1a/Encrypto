/*
 * crypto.js - Encryption module for the messaging app (Person 2 - Cryptography)
 *
 * PUBLIC API (the only functions the rest of the team needs):
 *
 *   await encryptMessage(text, password)       -> string (Base64 payload, safe to send/store)
 *   await decryptMessage(payload, password)    -> string (original text)  - throws on failure
 *   await decryptMessageSafe(payload, password)-> string (original text, or an error notice)
 *
 * HOW IT WORKS
 *   encrypt: text -> random rule (Reverse / ROT13 / Base64) -> JSON {rule, text}
 *            -> AES-GCM-256 with a key derived from the password (PBKDF2-SHA256)
 *            -> Base64( salt[16] + iv[12] + ciphertext+tag )
 *   decrypt: the exact reverse.
 *
 *   The rule ID is stored INSIDE the encrypted data, so the receiver always knows
 *   which rule to undo, and an attacker cannot even see which rule was used.
 *
 *   NOTE: Reverse / ROT13 / Base64 are only an obfuscation layer.
 *         The real security comes from AES-GCM (confidentiality + tamper detection).
 *
 * REQUIREMENT: crypto.subtle only works on https:// or http://localhost
 *              (NOT on http://192.168.x.x). Load this file before app.js.
 */
"use strict";

// ============================================================
// Settings
// ============================================================
const SALT_LENGTH = 16;          // bytes, random per message
const IV_LENGTH = 12;            // bytes, standard for AES-GCM, random per message
const TAG_LENGTH = 16;           // bytes, AES-GCM authentication tag (added automatically)
const PBKDF2_ITERATIONS = 100000;

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  console.error(
    "crypto.js: crypto.subtle is not available. " +
    "Open the app via http://localhost or https://, not via a LAN IP address."
  );
}

// ============================================================
// Byte <-> Base64 helpers (UTF-8 safe, work for any length)
// ============================================================
function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]); // each byte becomes one 0-255 char
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ============================================================
// Rule 1: Reverse  ("Salut" -> "tulaS"), its own inverse
// Array.from splits by real characters, so emoji are not broken.
// ============================================================
function reverseText(text) {
  return Array.from(text).reverse().join("");
}

// ============================================================
// Rule 2: ROT13  ("Hello" -> "Uryyb"), its own inverse
// Only A-Z / a-z are shifted; digits, diacritics, emoji stay the same.
// ============================================================
function rot13(text) {
  return text.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;        // 'A' = 65, 'a' = 97
    const pos = ch.charCodeAt(0) - base;      // 0..25
    return String.fromCharCode(((pos + 13) % 26) + base);
  });
}

// ============================================================
// Rule 3: Base64  ("Salut" -> "U2FsdXQ="), UTF-8 safe (works with ă, ș, ț, emoji)
// ============================================================
function base64Encode(text) {
  return bytesToBase64(new TextEncoder().encode(text)); // text -> UTF-8 bytes -> Base64
}

function base64Decode(b64) {
  return new TextDecoder().decode(base64ToBytes(b64));  // Base64 -> bytes -> text
}

// ============================================================
// Rule table - the array index is the rule ID stored in each message.
// DO NOT reorder once messages are being saved (old messages store the ID).
// ============================================================
const RULES = [
  { name: "Reverse", encode: reverseText,  decode: reverseText  }, // ID 0
  { name: "ROT13",   encode: rot13,        decode: rot13        }, // ID 1
  { name: "Base64",  encode: base64Encode, decode: base64Decode }, // ID 2
];

// ============================================================
// Automatic rule switching: a random rule per message, ID sent along.
// ============================================================
function pickRuleId() {
  return Math.floor(Math.random() * RULES.length); // 0, 1 or 2
}

function applyRule(text) {
  const id = pickRuleId();
  return { rule: id, text: RULES[id].encode(text) };
}

function undoRule(packet) {
  const r = RULES[packet.rule];
  if (!r) throw new Error("Unknown rule ID: " + packet.rule);
  return r.decode(packet.text);
}

// ============================================================
// Key derivation: password + salt -> AES-GCM 256-bit key (PBKDF2-SHA256)
// ============================================================
async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,                    // key cannot be exported
    ["encrypt", "decrypt"]
  );
}

// ============================================================
// PUBLIC: encrypt
// ============================================================
async function encryptMessage(text, password) {
  if (typeof text !== "string") throw new TypeError("encryptMessage: text must be a string");
  if (!password) throw new Error("encryptMessage: password is required");

  // 1. Obfuscation layer: random rule, ID stored with the text
  const packet = applyRule(text);
  const plainBytes = new TextEncoder().encode(JSON.stringify(packet));

  // 2. Fresh random salt and IV for EVERY message
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  // 3. Derive key and encrypt
  const key = await deriveKey(password, salt);
  const cipherBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, plainBytes);
  const cipherBytes = new Uint8Array(cipherBuffer);

  // 4. Pack: salt + iv + ciphertext (tag included) -> one Base64 string
  const combined = new Uint8Array(SALT_LENGTH + IV_LENGTH + cipherBytes.length);
  combined.set(salt, 0);
  combined.set(iv, SALT_LENGTH);
  combined.set(cipherBytes, SALT_LENGTH + IV_LENGTH);

  return bytesToBase64(combined);
}

// ============================================================
// PUBLIC: decrypt (throws an Error with a readable message on failure)
// ============================================================
async function decryptMessage(payload, password) {
  if (!password) throw new Error("decryptMessage: password is required");

  // 1. Unpack
  let combined;
  try {
    combined = base64ToBytes(payload);
  } catch (e) {
    throw new Error("Invalid message format");
  }
  if (combined.length < SALT_LENGTH + IV_LENGTH + TAG_LENGTH) {
    throw new Error("Invalid message format");
  }

  const salt = combined.slice(0, SALT_LENGTH);
  const iv = combined.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const cipherBytes = combined.slice(SALT_LENGTH + IV_LENGTH);

  // 2. Derive the same key and decrypt (fails if password is wrong or data was changed)
  const key = await deriveKey(password, salt);
  let plainBuffer;
  try {
    plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, cipherBytes);
  } catch (e) {
    throw new Error("Cannot decrypt: wrong password or the message was modified");
  }

  // 3. Undo the obfuscation rule
  const packet = JSON.parse(new TextDecoder().decode(plainBuffer));
  return undoRule(packet);
}

// ============================================================
// PUBLIC: decrypt that never throws - handy for rendering a chat list
// ============================================================
async function decryptMessageSafe(payload, password) {
  try {
    return await decryptMessage(payload, password);
  } catch (e) {
    return "⚠️ " + e.message;
  }
}

// ============================================================
// Self-tests - run in the browser console:  testRules()  and  await testCrypto()
// ============================================================
const TEST_SAMPLES = [
  "Salut!",
  "Hello World 123",
  "ă î ș ț â Ă Î Ș Ț",
  "😀👍🔐",
  "",
  "a".repeat(10000),
];

function testRules() {
  let ok = true;

  for (const s of TEST_SAMPLES) {
    // each rule individually
    for (const r of RULES) {
      if (r.decode(r.encode(s)) !== s) {
        ok = false;
        console.error("❌", r.name, "failed on:", s.slice(0, 30));
      }
    }
    // automatic switching, many times so every rule gets picked
    for (let i = 0; i < 20; i++) {
      if (undoRule(applyRule(s)) !== s) {
        ok = false;
        console.error("❌ applyRule/undoRule failed on:", s.slice(0, 30));
      }
    }
  }

  // known values
  const known = [
    [reverseText("abc"), "cba"],
    [rot13("Hello"), "Uryyb"],
    [base64Encode("Salut"), "U2FsdXQ="],
    [base64Encode("ă"), "xIM="],
  ];
  for (const [got, expected] of known) {
    if (got !== expected) {
      ok = false;
      console.error("❌ expected", expected, "got", got);
    }
  }

  console.log(ok ? "✅ All rule tests passed" : "❌ Some rule tests failed");
  return ok;
}

async function testCrypto() {
  const password = "test-password";
  let ok = true;

  // 1. Round trip
  for (const s of TEST_SAMPLES) {
    const enc = await encryptMessage(s, password);
    const dec = await decryptMessage(enc, password);
    if (dec !== s) {
      ok = false;
      console.error("❌ round trip failed on:", s.slice(0, 30));
    }
  }

  // 2. Same text twice -> different payloads (random salt + IV)
  const a = await encryptMessage("Salut", password);
  const b = await encryptMessage("Salut", password);
  if (a === b) {
    ok = false;
    console.error("❌ same text produced identical payloads");
  }

  // 3. Wrong password must fail
  try {
    await decryptMessage(a, "wrong-password");
    ok = false;
    console.error("❌ wrong password was accepted");
  } catch (e) { /* expected */ }

  // 4. Tampered message must fail
  const bytes = base64ToBytes(a);
  bytes[bytes.length - 5] ^= 1; // flip one bit in the ciphertext
  try {
    await decryptMessage(bytesToBase64(bytes), password);
    ok = false;
    console.error("❌ tampered message was accepted");
  } catch (e) { /* expected */ }

  // 5. Garbage input must fail cleanly
  const safe = await decryptMessageSafe("not base64 !!!", password);
  if (!safe.startsWith("⚠️")) {
    ok = false;
    console.error("❌ garbage input did not fail cleanly");
  }

  console.log(ok ? "✅ All crypto tests passed" : "❌ Some crypto tests failed");
  return ok;
}
