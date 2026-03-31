import test from 'node:test';
import assert from 'node:assert/strict';
import { aegis256 } from '../aegis256.js';
import { getSodium } from '../sodium.js';

/** Generate a random 32-byte key for AEGIS-256. */
async function generateTestKey(): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.randombytes_buf(32);
}

// ---------------------------------------------------------------------------
// Basic properties
// ---------------------------------------------------------------------------

test('aegis256: algorithm name and key length', () => {
  assert.equal(aegis256.algorithm, 'AEGIS-256');
  assert.equal(aegis256.keyLength, 32);
});

// ---------------------------------------------------------------------------
// Round-trip encryption and decryption
// ---------------------------------------------------------------------------

test('aegis256: encrypt then decrypt recovers original data', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('Hello, AEGIS-256!');
  const ciphertext = await aegis256.encrypt(plaintext, key);
  const recovered = await aegis256.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

test('aegis256: round-trip with binary data containing all 256 byte values', async () => {
  const key = await generateTestKey();
  const plaintext = new Uint8Array(256);
  for (let i = 0; i < 256; i++) plaintext[i] = i;
  const ciphertext = await aegis256.encrypt(plaintext, key);
  const recovered = await aegis256.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

test('aegis256: round-trip with empty data', async () => {
  const key = await generateTestKey();
  const plaintext = new Uint8Array(0);
  const ciphertext = await aegis256.encrypt(plaintext, key);
  const recovered = await aegis256.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

test('aegis256: round-trip with large data (1 MB)', async () => {
  const key = await generateTestKey();
  const plaintext = new Uint8Array(1024 * 1024);
  for (let offset = 0; offset < plaintext.length; offset += 65536) {
    globalThis.crypto.getRandomValues(
      plaintext.subarray(offset, offset + 65536),
    );
  }
  const ciphertext = await aegis256.encrypt(plaintext, key);
  const recovered = await aegis256.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

// ---------------------------------------------------------------------------
// Ciphertext properties
// ---------------------------------------------------------------------------

test('aegis256: ciphertext is longer than plaintext (nonce + tag overhead)', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('some data');
  const ciphertext = await aegis256.encrypt(plaintext, key);

  // 32-byte nonce + plaintext length + 32-byte AEGIS-256 tag
  assert.equal(ciphertext.length, 32 + plaintext.length + 32);
});

test('aegis256: encrypting the same data twice produces different ciphertext', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('deterministic?');
  const ct1 = await aegis256.encrypt(plaintext, key);
  const ct2 = await aegis256.encrypt(plaintext, key);

  // Different random nonces => different ciphertext
  assert.notDeepEqual(ct1, ct2);

  // But both decrypt to the same plaintext
  assert.deepEqual(await aegis256.decrypt(ct1, key), plaintext);
  assert.deepEqual(await aegis256.decrypt(ct2, key), plaintext);
});

// ---------------------------------------------------------------------------
// Authentication and error cases
// ---------------------------------------------------------------------------

test('aegis256: decryption fails with wrong key', async () => {
  const key1 = await generateTestKey();
  const key2 = await generateTestKey();
  const plaintext = new TextEncoder().encode('secret');
  const ciphertext = await aegis256.encrypt(plaintext, key1);
  await assert.rejects(() => aegis256.decrypt(ciphertext, key2));
});

test('aegis256: decryption fails when ciphertext is tampered', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('tamper test');
  const ciphertext = await aegis256.encrypt(plaintext, key);

  // Flip a byte in the ciphertext body (after the 32-byte nonce)
  const tampered = new Uint8Array(ciphertext);
  tampered[36] ^= 0xff;

  await assert.rejects(() => aegis256.decrypt(tampered, key));
});

test('aegis256: decryption fails when nonce is tampered', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('nonce tamper');
  const ciphertext = await aegis256.encrypt(plaintext, key);

  // Flip a byte in the nonce
  const tampered = new Uint8Array(ciphertext);
  tampered[0] ^= 0xff;

  await assert.rejects(() => aegis256.decrypt(tampered, key));
});

test('aegis256: decryption fails with truncated ciphertext', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('truncate me');
  const ciphertext = await aegis256.encrypt(plaintext, key);

  // Remove the last byte (breaks the tag)
  const truncated = ciphertext.slice(0, ciphertext.length - 1);

  await assert.rejects(() => aegis256.decrypt(truncated, key));
});

test('aegis256: decryption fails with data too short', async () => {
  const key = await generateTestKey();

  // Less than nonce (32) + tag (32) = 64 bytes minimum
  const tooShort = new Uint8Array(50);

  await assert.rejects(
    () => aegis256.decrypt(tooShort, key),
    /ciphertext too short/,
  );
});

test('aegis256: encrypt rejects invalid key length', async () => {
  const shortKey = new Uint8Array(16);
  const data = new TextEncoder().encode('test');

  await assert.rejects(
    () => aegis256.encrypt(data, shortKey),
    /key must be 32 bytes/,
  );
});

test('aegis256: decrypt rejects invalid key length', async () => {
  const shortKey = new Uint8Array(16);
  const data = new Uint8Array(70); // long enough to pass length check

  await assert.rejects(
    () => aegis256.decrypt(data, shortKey),
    /key must be 32 bytes/,
  );
});
