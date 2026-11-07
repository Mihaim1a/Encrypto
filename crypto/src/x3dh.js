/**
 * X3DH ("Extended Triple Diffie-Hellman") key agreement, as specified by Signal:
 * https://signal.org/docs/specifications/x3dh/
 *
 * Lets Alice start an encrypted conversation with Bob while Bob is offline, using the
 * "prekeys" Bob uploaded to the server in advance. The server only ever holds public keys.
 *
 *   DH1 = DH(IK_A, SPK_B)   DH2 = DH(EK_A, IK_B)   DH3 = DH(EK_A, SPK_B)   DH4 = DH(EK_A, OPK_B)
 *   SK  = HKDF(0xFF*32 || DH1 || DH2 || DH3 [|| DH4])
 *
 * IK = identity DH key, SPK = signed prekey, OPK = one-time prekey, EK = ephemeral key.
 */
import { bytesEqual, concatBytes, u32ToBytes } from './encoding.js';
import { verifyIdentityBinding } from './keys.js';
import { ZERO_SALT, ed25519Sign, ed25519Verify, generateX25519KeyPair, hkdf, label, x25519 } from './primitives.js';

/** Thrown when keys from the server do not match the contact code the user entered. */
export class UntrustedIdentityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UntrustedIdentityError';
  }
}

function signedPreKeyMessage(id, publicKey) {
  return concatBytes(label('signed-prekey'), u32ToBytes(id), publicKey);
}

export function verifySignedPreKey(identityKey, id, publicKey, signature) {
  return ed25519Verify(identityKey, signedPreKeyMessage(id, publicKey), signature);
}

export async function createSignedPreKey(identity, id) {
  const keyPair = await generateX25519KeyPair();
  const signature = await ed25519Sign(identity.signing.privateKey, signedPreKeyMessage(id, keyPair.publicKey));
  return { id, keyPair, signature, createdAt: Date.now() };
}

/**
 * Verifies a prekey bundle fetched from the server against the contact code the user typed.
 * This is what stops a compromised server from swapping in its own keys (man-in-the-middle).
 */
export async function verifyPreKeyBundle(bundle, expectedIdentityKey) {
  if (!bytesEqual(bundle.identityKey, expectedIdentityKey)) {
    throw new UntrustedIdentityError('The server returned keys for a different identity than this contact code');
  }
  const bindingOk = await verifyIdentityBinding({
    signingKey: bundle.identityKey,
    dhKey: bundle.identityDHKey,
    binding: bundle.identityBinding,
  });
  if (!bindingOk) throw new UntrustedIdentityError('The identity key signature in the bundle is invalid');

  const { id, publicKey, signature } = bundle.signedPreKey;
  if (!(await ed25519Verify(bundle.identityKey, signedPreKeyMessage(id, publicKey), signature))) {
    throw new UntrustedIdentityError('The signed prekey signature in the bundle is invalid');
  }
}

async function deriveSharedSecret(dhOutputs) {
  const padding = new Uint8Array(32).fill(0xff);
  return hkdf(concatBytes(padding, ...dhOutputs), ZERO_SALT, label('x3dh'), 32);
}

/** Alice's side. `bundle` must already have passed verifyPreKeyBundle. */
export async function x3dhInitiate(ourIdentity, bundle) {
  const ephemeral = await generateX25519KeyPair();
  const dhOutputs = [
    await x25519(ourIdentity.dh.privateKey, bundle.signedPreKey.publicKey),
    await x25519(ephemeral.privateKey, bundle.identityDHKey),
    await x25519(ephemeral.privateKey, bundle.signedPreKey.publicKey),
  ];
  if (bundle.oneTimePreKey) {
    dhOutputs.push(await x25519(ephemeral.privateKey, bundle.oneTimePreKey.publicKey));
  }
  const sharedSecret = await deriveSharedSecret(dhOutputs);
  ephemeral.privateKey.fill(0);
  for (const output of dhOutputs) output.fill(0);

  // Associated data binds both identities to every message: initiator first, then responder.
  const associatedData = concatBytes(
    ourIdentity.signing.publicKey,
    ourIdentity.dh.publicKey,
    bundle.identityKey,
    bundle.identityDHKey,
  );
  return { sharedSecret, associatedData, ephemeralPublicKey: ephemeral.publicKey };
}

/** Bob's side, run when the first message from Alice arrives. */
export async function x3dhRespond({
  ourIdentity,
  signedPreKey,
  oneTimePreKey,
  theirIdentityKey,
  theirIdentityDHKey,
  theirEphemeralKey,
}) {
  const dhOutputs = [
    await x25519(signedPreKey.privateKey, theirIdentityDHKey),
    await x25519(ourIdentity.dh.privateKey, theirEphemeralKey),
    await x25519(signedPreKey.privateKey, theirEphemeralKey),
  ];
  if (oneTimePreKey) dhOutputs.push(await x25519(oneTimePreKey.privateKey, theirEphemeralKey));
  const sharedSecret = await deriveSharedSecret(dhOutputs);
  for (const output of dhOutputs) output.fill(0);

  const associatedData = concatBytes(
    theirIdentityKey,
    theirIdentityDHKey,
    ourIdentity.signing.publicKey,
    ourIdentity.dh.publicKey,
  );
  return { sharedSecret, associatedData };
}
