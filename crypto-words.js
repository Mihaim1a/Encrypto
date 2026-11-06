/*
 * crypto-words.js (version 4) - Strong two-layer encryption with a 4-letter code
 * Person 2 - Cryptography
 *
 * Drop-in alternative to crypto.js: same function names, plus a 4-letter code.
 * Load ONE of the two files on a page, not both (they use the same names).
 *
 * PUBLIC API
 *   await encryptMessage(text, password, code)          -> string (Base64 payload for the server)
 *   await decryptMessage(payload, password, code)       -> string (original text) - throws on failure
 *   await decryptMessageSafe(payload, password, code)   -> string (original text, or a warning notice)
 *   isValidCode(code)                                   -> true / false (for the code input field)
 *   isStrongEnoughPassword(password)                    -> true / false (at least 8 characters)
 *   forgetKeys()                                        -> wipe all cached keys (call on logout)
 *   await describeScheme(code)                          -> which cipher mode each word length gets (demo)
 *   await encryptMessageDetailed(text, password, code)  -> { payload, words } (demo: shows layer 1)
 *
 * SECURITY DESIGN
 *
 *   password + 4-letter code
 *        |  PBKDF2-SHA256, 600,000 rounds, random 16-byte salt
 *        |  (slow on purpose: makes every password guess expensive for an attacker)
 *        v
 *   master key (256-bit) - derived once per session, stays in memory, is never sent
 *        |  HKDF-SHA256 with a NEW random 16-byte salt for every message
 *        +--> word-layer key  (AES-256-CTR key stream)
 *        +--> message key     (AES-256-GCM)
 *
 *   Layer 1 - word layer. Every word becomes:
 *               [3 encrypted characters holding the real length] + [body]
 *             The body is the word's characters plus random filler, padded to a multiple of
 *             8 characters (sometimes one random extra block), so "a" and "hackaton" look
 *             the same size. The body is then encrypted with a secret AES-256-CTR key stream
 *             (one-time-pad style). The word's REAL length picks one of 6 cipher modes
 *             (Stream, Shuffle, Chained, Double...); the 4-letter code decides which length
 *             gets which mode. Shuffle modes also mix the real characters in with the filler.
 *
 *   Layer 2 - AES-256-GCM over the whole message, padded to a multiple of 64 bytes so the
 *             total length is hidden. The header (version + salts + IV) is authenticated too,
 *             so changing a single bit anywhere makes decryption fail.
 *
 *   Every message gets its own keys. A different password OR code -> different keys -> AES-GCM
 *   refuses to decrypt. The server only ever sees:
 *     Base64( version[1] + sessionSalt[16] + messageSalt[16] + iv[12] + ciphertext + tag[16] )
 *
 *   The weakest point is the PASSWORD: use a long one (e.g. 4 random words). The 4-letter code
 *   adds about 19 bits of secret on top, but it is far too short to be the only secret.
 *
 * REQUIREMENT: crypto.subtle only works on https:// or http://localhost
 *              (NOT on http://192.168.x.x).
 */
"use strict";

// ============================================================
// Settings
// ============================================================
const FORMAT_VERSION = 4;
const KDF_SALT_LENGTH = 16;        // bytes, random once per session (for PBKDF2)
const MSG_SALT_LENGTH = 16;        // bytes, random for every message (for HKDF)
const IV_LENGTH = 12;              // bytes, random for every message (for AES-GCM)
const TAG_LENGTH = 16;             // bytes, AES-GCM authentication tag
const HEADER_LENGTH = 1 + KDF_SALT_LENGTH + MSG_SALT_LENGTH + IV_LENGTH; // 45 bytes
const PBKDF2_ITERATIONS = 600000;  // OWASP recommendation for PBKDF2-SHA256
const PAD_BLOCK = 64;              // whole messages are padded to a multiple of 64 bytes
const MIN_PASSWORD_LENGTH = 8;
const WORD_BLOCK = 8;              // word bodies are padded to a multiple of 8 characters
const LENGTH_DIGITS = 3;           // the real word length is stored in 3 encrypted characters

// Characters the word layer encrypts. Anything else (emoji, other scripts) is not substituted,
// only moved around by the shuffle modes.
// Written with \u escapes so a wrong file encoding can't break them.
//   a ă â b c ... ș t ț ... z  /  A Ă Â ... Z  /  ş ţ Ş Ţ (old cedilla forms)  /  0-9  /  symbols
const CHARSET =
  "aăâbcdefghiîjklmnopqrsștțuvwxyz" +
  "AĂÂBCDEFGHIÎJKLMNOPQRSȘTȚUVWXYZ" +
  "şţŞŢ" +
  "0123456789" +
  ".,!?;:'\"()-_@#&%*/+=<>[]{}~$€";
const N = CHARSET.length; // 105
const CHAR_INDEX = new Map(Array.from(CHARSET).map((ch, i) => [ch, i]));
const MAX_WORD_LENGTH = N ** LENGTH_DIGITS - 1; // 1,157,624 characters without a space

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  console.error(
    "crypto-words.js: crypto.subtle is not available. " +
    "Open the app via http://localhost or https://, not via a LAN IP address."
  );
}

// ============================================================
// Small helpers
// ============================================================
const utf8 = new TextEncoder();

function mod(n, m) {
  return ((n % m) + m) % m; // like %, but never negative
}

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
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

function isWord(piece) {
  return piece !== "" && !/^\s+$/.test(piece);
}

// ============================================================
// Input checks
// ============================================================
function isValidCode(code) {
  return /^[A-Za-z]{4}$/.test(String(code == null ? "" : code).trim());
}

function normalizeCode(code) {
  if (!isValidCode(code)) {
    throw new Error("The code must be exactly 4 letters (A-Z)");
  }
  return String(code).trim().toUpperCase(); // "mare" and "MARE" are the same code
}

function isStrongEnoughPassword(password) {
  return typeof password === "string" && password.length >= MIN_PASSWORD_LENGTH;
}

// ============================================================
// Key derivation
// ============================================================
const keyCache = new Map(); // master keys, so PBKDF2 only runs once per password+code+salt
let sessionSalt = null;     // PBKDF2 salt used for the messages THIS browser tab sends

// password + code + salt -> master key (slow: 600,000 PBKDF2 rounds)
async function deriveMasterKey(password, code, kdfSalt) {
  const baseKey = await crypto.subtle.importKey(
    "raw", utf8.encode(code + ":" + password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: kdfSalt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    256
  );
  return crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
}

async function getMasterKey(password, code, kdfSalt) {
  // The cache is keyed by a hash, so the password itself is not stored as a key
  const id =
    bytesToBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(code + ":" + password)))) +
    "|" + bytesToBase64(kdfSalt);

  if (!keyCache.has(id)) {
    if (keyCache.size >= 100) keyCache.clear();
    const pending = deriveMasterKey(password, code, kdfSalt);
    keyCache.set(id, pending);
    pending.catch(() => keyCache.delete(id));
  }
  return keyCache.get(id);
}

// master key + message salt -> two fresh keys for this one message (fast: HKDF)
async function deriveMessageKeys(masterKey, msgSalt) {
  const hkdf = (label) => ({ name: "HKDF", hash: "SHA-256", salt: msgSalt, info: utf8.encode(label) });
  const [aesKey, wordKey] = await Promise.all([
    crypto.subtle.deriveKey(hkdf("hackaton-v4 aes-gcm"), masterKey,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
    crypto.subtle.deriveKey(hkdf("hackaton-v4 word-layer"), masterKey,
      { name: "AES-CTR", length: 256 }, false, ["encrypt"]),
  ]);
  return { aesKey, wordKey };
}

// PUBLIC: wipe all keys from memory (e.g. on logout or password change)
function forgetKeys() {
  keyCache.clear();
  sessionSalt = null;
}

// ============================================================
// Key stream: secret random-looking numbers from AES-256-CTR
// (a zero counter is safe here because the word-layer key is new for every message)
// ============================================================
async function makeKeyStream(wordKey, count) {
  const bytes = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-CTR", counter: new Uint8Array(16), length: 64 },
    wordKey,
    new Uint8Array(Math.max(count, 1) * 4) // encrypting zeros = the raw key stream
  ));
  const view = new DataView(bytes.buffer);
  let pos = 0;
  return {
    // n secret 32-bit numbers. (value % N has a bias below 1 in 40 million: negligible)
    take(n) {
      const out = new Array(n);
      for (let i = 0; i < n; i++) {
        out[i] = view.getUint32(pos);
        pos += 4;
      }
      return out;
    },
  };
}

// ============================================================
// Layer 1 building blocks (each keeps the length of what it is given and never creates spaces)
// ============================================================

// Shift every character by its own secret number
function streamEncrypt(chars, K) {
  return chars.map((ch, i) => {
    const x = CHAR_INDEX.get(ch);
    return x === undefined ? ch : CHARSET[mod(x + (K[i] % N), N)];
  });
}

function streamDecrypt(chars, K) {
  return chars.map((ch, i) => {
    const x = CHAR_INDEX.get(ch);
    return x === undefined ? ch : CHARSET[mod(x - (K[i] % N), N)];
  });
}

// Like stream, but each result also depends on the previous encrypted character (like CBC)
function chainEncrypt(chars, K) {
  let prev = 0;
  return chars.map((ch, i) => {
    const x = CHAR_INDEX.get(ch);
    if (x === undefined) return ch;
    const y = mod(x + (K[i] % N) + prev, N);
    prev = y;
    return CHARSET[y];
  });
}

function chainDecrypt(chars, K) {
  let prev = 0;
  return chars.map((ch, i) => {
    const y = CHAR_INDEX.get(ch);
    if (y === undefined) return ch;
    const x = mod(y - (K[i] % N) - prev, N);
    prev = y;
    return CHARSET[x];
  });
}

// Secret order of positions (Fisher-Yates shuffle driven by the key stream)
function makePermutation(values) {
  const perm = values.map((_, i) => i);
  for (let i = perm.length - 1; i > 0; i--) {
    const j = values[i] % (i + 1);
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }
  return perm;
}

function shuffle(chars, perm) {
  return perm.map((p) => chars[p]);
}

function unshuffle(chars, perm) {
  const out = new Array(chars.length);
  perm.forEach((p, k) => { out[p] = chars[k]; });
  return out;
}

// ============================================================
// The 6 cipher modes. Each word body uses one, chosen by the word's REAL length.
// k.A and k.B are two independent key streams, k.perm a secret order.
// ============================================================
const WORD_MODES = [
  {
    name: "Stream",
    info: "every character shifted by its own secret number",
    encode: (c, k) => streamEncrypt(c, k.A),
    decode: (c, k) => streamDecrypt(c, k.A),
  },
  {
    name: "Shuffle → Stream",
    info: "letters mixed in with the filler in a secret order, then stream-encrypted",
    encode: (c, k) => streamEncrypt(shuffle(c, k.perm), k.A),
    decode: (c, k) => unshuffle(streamDecrypt(c, k.A), k.perm),
  },
  {
    name: "Stream → Shuffle",
    info: "stream-encrypted, then mixed in with the filler in a secret order",
    encode: (c, k) => shuffle(streamEncrypt(c, k.A), k.perm),
    decode: (c, k) => streamDecrypt(unshuffle(c, k.perm), k.A),
  },
  {
    name: "Chained",
    info: "each character also depends on the previous encrypted one",
    encode: (c, k) => chainEncrypt(c, k.A),
    decode: (c, k) => chainDecrypt(c, k.A),
  },
  {
    name: "Double",
    info: "stream, secret order, then stream again with a second key stream",
    encode: (c, k) => streamEncrypt(shuffle(streamEncrypt(c, k.A), k.perm), k.B),
    decode: (c, k) => streamDecrypt(unshuffle(streamDecrypt(c, k.B), k.perm), k.A),
  },
  {
    name: "Shuffle → Chained",
    info: "letters mixed in with the filler in a secret order, then chained",
    encode: (c, k) => chainEncrypt(shuffle(c, k.perm), k.A),
    decode: (c, k) => unshuffle(chainDecrypt(c, k.A), k.perm),
  },
];

// The code decides which word length gets which mode
async function buildScheme(code) {
  const cleanCode = normalizeCode(code);
  const hash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", utf8.encode("word-scheme-v3:" + cleanCode))
  );
  const order = WORD_MODES.map((_, i) => i);
  for (let i = order.length - 1; i > 0; i--) {
    const j = hash[i] % (i + 1);
    [order[i], order[j]] = [order[j], order[i]];
  }
  return { order }; // order[(length - 1) % 6] = mode ID
}

function modeIdForLength(length, scheme) {
  return scheme.order[(length - 1) % WORD_MODES.length];
}

// ============================================================
// Hiding the word length
// ============================================================

// Body size for a word of real length L: round up to a multiple of 8,
// then randomly add one extra block half of the time.
// So a body of 8 = 1-8 letters, a body of 16 = 1-16 letters, and so on.
function paddedBodyLength(L) {
  const blocks = Math.max(1, Math.ceil(L / WORD_BLOCK)) + (randomBytes(1)[0] & 1);
  return blocks * WORD_BLOCK;
}

// Random filler characters (removed again after decryption)
function randomFiller(count) {
  const values = crypto.getRandomValues(new Uint32Array(count));
  return Array.from(values, (v) => CHARSET[v % N]);
}

// How many key-stream numbers one encrypted word of S body characters uses
function keysPerWord(S) {
  return LENGTH_DIGITS + 3 * S;
}

// Takes this word's key-stream numbers, always in the same order on both sides
function takeWordKeys(keyStream, S) {
  return {
    H: keyStream.take(LENGTH_DIGITS),          // for the hidden length
    A: keyStream.take(S),                      // first key stream
    B: keyStream.take(S),                      // second key stream
    perm: makePermutation(keyStream.take(S)),  // secret order
  };
}

// One word -> [3 encrypted length characters] + [encrypted body of S characters]
function encodeWord(chars, S, scheme, keyStream) {
  const L = chars.length;
  if (L > MAX_WORD_LENGTH) throw new Error("A single word is too long to encrypt");
  const k = takeWordKeys(keyStream, S);

  // The real length, written as 3 digits in base 105 and stream-encrypted
  const digits = [Math.floor(L / (N * N)) % N, Math.floor(L / N) % N, L % N];
  const lengthChars = digits.map((d, i) => CHARSET[mod(d + (k.H[i] % N), N)]);

  // Real characters + random filler, then the cipher mode for this length
  const mode = WORD_MODES[modeIdForLength(L, scheme)];
  const body = mode.encode(chars.concat(randomFiller(S - L)), k);

  return { text: lengthChars.concat(body).join(""), mode: mode.name };
}

// [3 encrypted length characters] + [encrypted body] -> the original word
function decodeWord(chars, scheme, keyStream) {
  const S = chars.length - LENGTH_DIGITS;
  const k = takeWordKeys(keyStream, S);

  const digits = chars.slice(0, LENGTH_DIGITS).map((ch, i) => {
    const y = CHAR_INDEX.get(ch);
    if (y === undefined) throw new Error("Invalid message format");
    return mod(y - (k.H[i] % N), N);
  });
  const L = (digits[0] * N + digits[1]) * N + digits[2];
  if (L < 1 || L > S) throw new Error("Invalid message format");

  const mode = WORD_MODES[modeIdForLength(L, scheme)];
  return mode.decode(chars.slice(LENGTH_DIGITS), k).slice(0, L).join(""); // drop the filler
}

// Layer 1 over a whole text. Spaces and line breaks are kept as they are.
async function encodeWords(text, scheme, wordKey, details) {
  const pieces = text.split(/(\s+)/);
  const bodySizes = pieces.map((p) => (isWord(p) ? paddedBodyLength(Array.from(p).length) : 0));
  const total = bodySizes.reduce((sum, S) => sum + (S ? keysPerWord(S) : 0), 0);
  const keyStream = await makeKeyStream(wordKey, total);

  return pieces
    .map((piece, i) => {
      if (!bodySizes[i]) return piece;
      const chars = Array.from(piece); // real characters, emoji-safe
      const enc = encodeWord(chars, bodySizes[i], scheme, keyStream);
      if (details) details.push({ word: piece, length: chars.length, mode: enc.mode, result: enc.text });
      return enc.text;
    })
    .join("");
}

async function decodeWords(text, scheme, wordKey) {
  const pieces = text.split(/(\s+)/);
  let total = 0;
  for (const piece of pieces) {
    if (!isWord(piece)) continue;
    const S = Array.from(piece).length - LENGTH_DIGITS;
    if (S < WORD_BLOCK || S % WORD_BLOCK !== 0) throw new Error("Invalid message format");
    total += keysPerWord(S);
  }
  const keyStream = await makeKeyStream(wordKey, total);

  return pieces
    .map((piece) => (isWord(piece) ? decodeWord(Array.from(piece), scheme, keyStream) : piece))
    .join("");
}

// ============================================================
// Padding of the whole message: [4-byte length][data][zeros up to a multiple of 64 bytes]
// ============================================================
function pad(data) {
  const total = Math.ceil((data.length + 4) / PAD_BLOCK) * PAD_BLOCK;
  const out = new Uint8Array(total);
  new DataView(out.buffer).setUint32(0, data.length);
  out.set(data, 4);
  return out;
}

function unpad(padded) {
  const length = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0);
  if (length > padded.length - 4) throw new Error("Invalid message format");
  return padded.subarray(4, 4 + length);
}

// ============================================================
// PUBLIC: encrypt
// ============================================================
async function encryptMessageDetailed(text, password, code) {
  if (typeof text !== "string") throw new TypeError("encryptMessage: text must be a string");
  if (!isStrongEnoughPassword(password)) {
    throw new Error("The password must be at least " + MIN_PASSWORD_LENGTH + " characters");
  }
  const cleanCode = normalizeCode(code);

  // 1. Keys: master key (once per session) -> fresh keys for this message
  if (!sessionSalt) sessionSalt = randomBytes(KDF_SALT_LENGTH);
  const kdfSalt = sessionSalt;
  const msgSalt = randomBytes(MSG_SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const masterKey = await getMasterKey(password, cleanCode, kdfSalt);
  const { aesKey, wordKey } = await deriveMessageKeys(masterKey, msgSalt);

  // 2. Layer 1: word layer (word lengths hidden)
  const scheme = await buildScheme(cleanCode);
  const words = [];
  const wordText = await encodeWords(text, scheme, wordKey, words);

  // 3. Layer 2: AES-256-GCM over the padded text; the header is authenticated too
  const header = new Uint8Array(HEADER_LENGTH);
  header[0] = FORMAT_VERSION;
  header.set(kdfSalt, 1);
  header.set(msgSalt, 1 + KDF_SALT_LENGTH);
  header.set(iv, 1 + KDF_SALT_LENGTH + MSG_SALT_LENGTH);

  const cipherBytes = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv, additionalData: header },
    aesKey,
    pad(utf8.encode(wordText))
  ));

  // 4. Pack: header + ciphertext (tag included) -> one Base64 string
  const combined = new Uint8Array(HEADER_LENGTH + cipherBytes.length);
  combined.set(header, 0);
  combined.set(cipherBytes, HEADER_LENGTH);

  return { payload: bytesToBase64(combined), words: words };
}

async function encryptMessage(text, password, code) {
  return (await encryptMessageDetailed(text, password, code)).payload;
}

// ============================================================
// PUBLIC: decrypt (throws an Error with a readable message on failure)
// ============================================================
async function decryptMessage(payload, password, code) {
  if (!password) throw new Error("decryptMessage: password is required");
  const cleanCode = normalizeCode(code);

  // 1. Unpack
  let combined;
  try {
    combined = base64ToBytes(String(payload).trim());
  } catch (e) {
    throw new Error("Invalid message format");
  }
  if (combined.length < HEADER_LENGTH + PAD_BLOCK + TAG_LENGTH || combined[0] !== FORMAT_VERSION) {
    throw new Error("Invalid or unsupported message format");
  }
  const header = combined.slice(0, HEADER_LENGTH);
  const kdfSalt = header.slice(1, 1 + KDF_SALT_LENGTH);
  const msgSalt = header.slice(1 + KDF_SALT_LENGTH, 1 + KDF_SALT_LENGTH + MSG_SALT_LENGTH);
  const iv = header.slice(1 + KDF_SALT_LENGTH + MSG_SALT_LENGTH);
  const cipherBytes = combined.slice(HEADER_LENGTH);

  // 2. Same password + same code -> same keys. Anything different -> AES-GCM refuses.
  const masterKey = await getMasterKey(password, cleanCode, kdfSalt);
  const { aesKey, wordKey } = await deriveMessageKeys(masterKey, msgSalt);

  let padded;
  try {
    padded = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv, additionalData: header },
      aesKey,
      cipherBytes
    ));
  } catch (e) {
    throw new Error("Cannot decrypt: wrong password or code, or the message was modified");
  }

  // 3. Undo layer 1 (real lengths come back, filler is removed)
  const wordText = new TextDecoder().decode(unpad(padded));
  const scheme = await buildScheme(cleanCode);
  return decodeWords(wordText, scheme, wordKey);
}

// ============================================================
// PUBLIC: decrypt that never throws - handy for rendering a chat list
// ============================================================
async function decryptMessageSafe(payload, password, code) {
  try {
    return await decryptMessage(payload, password, code);
  } catch (e) {
    return "⚠️ " + e.message;
  }
}

// ============================================================
// PUBLIC (demo): which cipher mode each word length gets for this code
// ============================================================
async function describeScheme(code) {
  const scheme = await buildScheme(code);
  return scheme.order.map((modeId, pos) => ({
    lengths: (pos + 1) + ", " + (pos + 7) + ", " + (pos + 13) + "…",
    mode: WORD_MODES[modeId].name,
    info: WORD_MODES[modeId].info,
  }));
}

// ============================================================
// Self-tests - run in the browser console:
//   await testWordLayer()    and    await testWordCrypto()
// ============================================================
const TEST_SAMPLES = [
  "Salut!",
  "Ne vedem la ora 5, ok?",
  "ă î ș ț â Ă Î Ș Ț ş ţ",
  "Știința și țara mâine 100€",
  "😀👍🔐 emoji test",
  "  two  spaces\nnew line\ttab ",
  "",
  "supercalifragilisticexpialidocious",
  "word ".repeat(2000),
];

function randomCode() {
  let c = "";
  for (let i = 0; i < 4; i++) c += String.fromCharCode(65 + Math.floor(Math.random() * 26));
  return c;
}

async function testWordLayer() {
  let ok = true;
  const fail = (...msg) => { ok = false; console.error("❌", ...msg); };
  const newKey = () => crypto.subtle.generateKey({ name: "AES-CTR", length: 256 }, false, ["encrypt"]);

  if (new Set(CHARSET).size !== CHARSET.length) fail("CHARSET contains duplicate characters");

  const roundTrip = async (s, scheme, wordKey, label) => {
    const enc = await encodeWords(s, scheme, wordKey);
    if (enc.split(/\S+/).join("|") !== s.split(/\S+/).join("|")) fail(label, "changed the spaces in", s.slice(0, 30));
    for (const w of enc.split(/\s+/).filter(Boolean)) {
      const S = Array.from(w).length - LENGTH_DIGITS;
      if (S < WORD_BLOCK || S % WORD_BLOCK !== 0) fail(label, "bad encrypted word size", w.length);
    }
    const back = await decodeWords(enc, scheme, wordKey);
    if (back !== s) fail(label, "round trip failed on", s.slice(0, 30));
    return enc;
  };

  for (let n = 0; n < 10; n++) {
    const code = randomCode();
    const wordKey = await newKey();
    // the scheme for this code
    const scheme = await buildScheme(code);
    for (const s of TEST_SAMPLES) await roundTrip(s, scheme, wordKey, "code " + code);
    // every mode on its own
    for (let m = 0; m < WORD_MODES.length; m++) {
      const forced = { order: WORD_MODES.map(() => m) };
      for (const s of TEST_SAMPLES) await roundTrip(s, forced, wordKey, WORD_MODES[m].name);
    }
  }

  // Word lengths are hidden: every word of 1-8 characters becomes 3 + 8 or 3 + 16 characters
  const scheme = await buildScheme("MARE");
  const key1 = await newKey();
  const sizesSeen = new Set();
  for (const w of ["a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg", "abcdefgh"]) {
    for (let i = 0; i < 20; i++) {
      const size = Array.from(await encodeWords(w, scheme, key1)).length;
      if (size !== 11 && size !== 19) fail("word", w, "became", size, "characters (expected 11 or 19)");
      sizesSeen.add(size);
    }
  }
  if (sizesSeen.size !== 2) fail("random extra block never happened");

  // Repeated letters must NOT give a repeated pattern (it is not a simple shift)
  const aaa = "a".repeat(30);
  const encA = await encodeWords(aaa, scheme, key1);
  if (new Set(encA).size < 10) fail("repeated letters gave a repeated pattern:", encA);

  // Different key -> different result
  const encB = await encodeWords(aaa, scheme, await newKey());
  if (encA === encB) fail("two different keys gave the same result");

  // Upper/lower case code = same scheme
  if (JSON.stringify(await buildScheme("MARE")) !== JSON.stringify(await buildScheme("mare"))) {
    fail("code should not be case-sensitive");
  }

  console.log(ok ? "✅ All word-layer tests passed" : "❌ Some word-layer tests failed");
  return ok;
}

async function testWordCrypto() {
  const password = "test-password";
  const code = "MARE";
  let ok = true;
  const fail = (...msg) => { ok = false; console.error("❌", ...msg); };
  const mustFail = async (fn, msg) => {
    try { await fn(); } catch (e) { return; }
    fail(msg);
  };

  // 1. Round trip
  for (const s of TEST_SAMPLES) {
    const enc = await encryptMessage(s, password, code);
    if ((await decryptMessage(enc, password, code)) !== s) fail("round trip failed on:", s.slice(0, 30));
  }

  // 2. Lower-case code works the same
  const p = await encryptMessage("Salut", password, "mare");
  if ((await decryptMessage(p, password, "MARE")) !== "Salut") fail("lower-case code did not work");

  // 3. Same text twice -> different payloads
  if (p === (await encryptMessage("Salut", password, "mare"))) fail("same text produced identical payloads");

  // 4. Wrong code / wrong password must fail
  await mustFail(() => decryptMessage(p, password, "MARF"), "wrong code was accepted");
  await mustFail(() => decryptMessage(p, "wrong-password", code), "wrong password was accepted");

  // 5. Changing one bit in the ciphertext OR in the header must fail
  const flip = (index) => {
    const b = base64ToBytes(p);
    b[index] ^= 1;
    return bytesToBase64(b);
  };
  await mustFail(() => decryptMessage(flip(base64ToBytes(p).length - 5), password, code), "tampered ciphertext was accepted");
  await mustFail(() => decryptMessage(flip(20), password, code), "tampered message salt was accepted");
  await mustFail(() => decryptMessage(flip(HEADER_LENGTH - 1), password, code), "tampered IV was accepted");

  // 6. Padding hides the length: a 1-letter and an 8-letter word give the same payload size
  const short = await encryptMessage("a", password, code);
  const longer = await encryptMessage("abcdefgh", password, code);
  if (short.length !== longer.length) fail("padding does not hide the length");

  // 7. Invalid codes and short passwords are rejected
  for (const bad of ["", "ABC", "ABCDE", "AB1D", "AB D", "ĂBCD", null]) {
    await mustFail(() => encryptMessage("x", password, bad), "invalid code accepted: " + bad);
  }
  await mustFail(() => encryptMessage("x", "short", code), "a 5-character password was accepted");

  // 8. A receiver with an empty key cache (another browser) can still decrypt
  forgetKeys();
  if ((await decryptMessage(p, password, code)) !== "Salut") fail("decrypt failed after forgetKeys()");

  // 9. Garbage input fails cleanly
  const safe = await decryptMessageSafe("not base64 !!!", password, code);
  if (!safe.startsWith("⚠")) fail("garbage input did not fail cleanly");

  console.log(ok ? "✅ All crypto tests passed" : "❌ Some crypto tests failed");
  return ok;
}
