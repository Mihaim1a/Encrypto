/**
 * Byte and string encoding helpers (UTF-8, base64, Crockford base32, integers).
 * Nothing in this file is secret-dependent; it only moves bytes around.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export function utf8ToBytes(text) {
  if (typeof text !== 'string') throw new TypeError('Expected a string');
  return encoder.encode(text);
}

export function bytesToUtf8(bytes) {
  return decoder.decode(bytes);
}

export function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Compares two byte arrays without an early exit on the first difference. */
export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

/** Decodes base64; if `expectedLength` is given, the result must have exactly that many bytes. */
export function fromBase64(text, expectedLength) {
  if (typeof text !== 'string') throw new TypeError('Expected a base64 string');
  let binary;
  try {
    binary = atob(text);
  } catch {
    throw new TypeError('Invalid base64 data');
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  if (expectedLength !== undefined && out.length !== expectedLength) {
    throw new TypeError(`Expected ${expectedLength} bytes, got ${out.length}`);
  }
  return out;
}

export function fromBase64Url(text) {
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  return fromBase64(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
}

export function u32ToBytes(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

export function readU32(bytes, offset) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);
}

// Crockford base32: no I, L, O or U, so codes are easy to read aloud and type.
const BASE32_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function toBase32(bytes) {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(buffer >>> bits) & 31];
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

/** Decodes Crockford base32, ignoring case, spaces and dashes, and accepting O/I/L as 0/1/1. */
export function fromBase32(text) {
  const clean = text.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  const out = [];
  let buffer = 0;
  let bits = 0;
  for (const char of clean) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value === -1) throw new TypeError(`Invalid character "${char}"`);
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 0xff);
    }
    buffer &= (1 << bits) - 1;
  }
  if (buffer !== 0) throw new TypeError('Invalid trailing characters');
  return new Uint8Array(out);
}

/** "ABCDEFGHIJ" -> "ABCDE-FGHIJ" */
export function groupString(text, size = 5, separator = '-') {
  return text.match(new RegExp(`.{1,${size}}`, 'g')).join(separator);
}
