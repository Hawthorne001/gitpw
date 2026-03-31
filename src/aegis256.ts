/**
 * AEGIS-256 is an AES-round-based AEAD constructed as a state-based sponge
 * (6 AES rounds per block). It is structurally different from AES-GCM
 * (block cipher + polynomial MAC) and XChaCha20-Poly1305 (ARX stream cipher
 * + Poly1305 MAC), making it a strong third layer in a cascade.
 *
 * AEGIS-256 is key-committing and provides a 256-bit authentication tag,
 * offering better security margins than GCM's 128-bit GHASH tag.
 *
 * Requires hardware AES support for optimal performance, but this is
 * present on virtually all modern x86 and ARM64 CPUs.
 *
 * Wire format: [32-byte nonce][ciphertext + 32-byte tag]
 */

import { getSodium } from './sodium.js';
import { encoding } from './encoding.js';
import type { CipherSuite } from './types.js';

const NONCE_LENGTH = 32;
const KEY_LENGTH = 32;
const TAG_LENGTH = 32;
const MIN_CIPHERTEXT_LENGTH = NONCE_LENGTH + TAG_LENGTH;

function validateKey(key: Uint8Array): void {
  if (key.length !== KEY_LENGTH) {
    throw new Error(
      `AEGIS-256: key must be ${KEY_LENGTH} bytes (got ${key.length})`,
    );
  }
}

export const aegis256: CipherSuite = {
  algorithm: 'AEGIS-256',
  keyLength: KEY_LENGTH,

  async encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    validateKey(key);
    const sodium = await getSodium();
    const nonce = sodium.randombytes_buf(NONCE_LENGTH);
    const ciphertext = sodium.crypto_aead_aegis256_encrypt(
      data,
      null,
      null,
      nonce,
      key,
    );

    return encoding.concatBytes(nonce, ciphertext);
  },

  async decrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    validateKey(key);
    const sodium = await getSodium();

    if (data.length < MIN_CIPHERTEXT_LENGTH) {
      throw new Error('AEGIS-256: ciphertext too short');
    }

    const nonce = data.slice(0, NONCE_LENGTH);
    const ciphertext = data.slice(NONCE_LENGTH);

    return sodium.crypto_aead_aegis256_decrypt(
      null,
      ciphertext,
      null,
      nonce,
      key,
    );
  },
};
