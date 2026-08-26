import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface EncryptedValue {
  iv: Buffer;
  ciphertext: Buffer;
  authTag: Buffer;
}

export function encryptJson(value: unknown, key: Uint8Array, context: string): EncryptedValue {
  if (key.byteLength !== 32) throw new Error("Backend encryption requires a 32-byte key.");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(context, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return { iv, ciphertext, authTag: cipher.getAuthTag() };
}

export function decryptJson<T>(value: EncryptedValue, key: Uint8Array, context: string): T {
  const decipher = createDecipheriv("aes-256-gcm", key, value.iv);
  decipher.setAAD(Buffer.from(context, "utf8"));
  decipher.setAuthTag(value.authTag);
  const plaintext = Buffer.concat([decipher.update(value.ciphertext), decipher.final()]).toString("utf8");
  return JSON.parse(plaintext) as T;
}
