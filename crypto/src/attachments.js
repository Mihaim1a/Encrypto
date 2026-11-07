/**
 * Attachments (images, files, voice notes) are too large to send through the ratchet.
 * Encrypt them once with a random AES-256 key, upload only the ciphertext, and send the key
 * (with the download URL) inside a normal encrypted message:
 *
 *   const { ciphertext, key } = await encryptAttachment(fileBytes);
 *   const url = await uploadToServer(ciphertext);
 *   await account.encrypt(contact, JSON.stringify({ type: 'image', url, key }));
 */
import { fromBase64, toBase64 } from './encoding.js';
import { aesGcmDecrypt, aesGcmEncrypt, label, randomBytes } from './primitives.js';

export async function encryptAttachment(data) {
  if (!(data instanceof Uint8Array)) throw new TypeError('Attachment data must be a Uint8Array');
  const key = randomBytes(32);
  const ciphertext = await aesGcmEncrypt(key, data, label('attachment'));
  return { ciphertext, key: toBase64(key) };
}

/** Throws DecryptionError if the downloaded file was altered or the key is wrong. */
export async function decryptAttachment(ciphertext, key) {
  if (!(ciphertext instanceof Uint8Array)) throw new TypeError('Attachment ciphertext must be a Uint8Array');
  return aesGcmDecrypt(fromBase64(key, 32), ciphertext, label('attachment'));
}
