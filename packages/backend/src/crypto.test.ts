import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { decryptJson, encryptJson } from "./crypto";

describe("authenticated tenant-bound encryption", () => {
  it("decrypts only with the original tenant context", () => {
    const key = randomBytes(32);
    const encrypted = encryptJson({ tenantId: "tenant-a", token: "sensitive" }, key, "snapshot:id:tenant-a:time");
    expect(decryptJson(encrypted, key, "snapshot:id:tenant-a:time")).toEqual({ tenantId: "tenant-a", token: "sensitive" });
    expect(() => decryptJson(encrypted, key, "snapshot:id:tenant-b:time")).toThrow();
  });

  it("rejects modified ciphertext", () => {
    const key = randomBytes(32);
    const encrypted = encryptJson({ tenantId: "tenant-a" }, key, "session:id:tenant-a");
    encrypted.ciphertext[0] = (encrypted.ciphertext[0] ?? 0) ^ 1;
    expect(() => decryptJson(encrypted, key, "session:id:tenant-a")).toThrow();
  });
});

describe("key and context requirements", () => {
  it("refuses to encrypt with a key that is not 32 bytes", () => {
    for (const size of [0, 16, 31, 33, 64]) {
      expect(() => encryptJson({ a: 1 }, randomBytes(size), "ctx"), String(size)).toThrow(/32-byte key/);
    }
    expect(() => encryptJson({ a: 1 }, randomBytes(32), "ctx")).not.toThrow();
  });

  it("refuses to decrypt with a different key", () => {
    const encrypted = encryptJson({ secret: "value" }, randomBytes(32), "ctx");
    expect(() => decryptJson(encrypted, randomBytes(32), "ctx")).toThrow();
  });

  it("produces a distinct nonce for every encryption of the same value", () => {
    const key = randomBytes(32);
    const first = encryptJson({ a: 1 }, key, "ctx");
    const second = encryptJson({ a: 1 }, key, "ctx");
    expect(first.iv.equals(second.iv)).toBe(false);
    expect(first.ciphertext.equals(second.ciphertext)).toBe(false);
  });

  it("uses a 12-byte nonce and a 16-byte authentication tag", () => {
    const encrypted = encryptJson({ a: 1 }, randomBytes(32), "ctx");
    expect(encrypted.iv).toHaveLength(12);
    expect(encrypted.authTag).toHaveLength(16);
  });

  it("rejects a tampered nonce or authentication tag", () => {
    const key = randomBytes(32);
    const encrypted = encryptJson({ a: 1 }, key, "ctx");
    const badIv = { ...encrypted, iv: Buffer.from(encrypted.iv) };
    badIv.iv[0] = (badIv.iv[0] ?? 0) ^ 1;
    expect(() => decryptJson(badIv, key, "ctx")).toThrow();
    const badTag = { ...encrypted, authTag: Buffer.from(encrypted.authTag) };
    badTag.authTag[0] = (badTag.authTag[0] ?? 0) ^ 1;
    expect(() => decryptJson(badTag, key, "ctx")).toThrow();
  });

  it("never leaves the plaintext readable in the ciphertext", () => {
    const encrypted = encryptJson({ token: "super-secret-value" }, randomBytes(32), "ctx");
    expect(encrypted.ciphertext.toString("utf8")).not.toContain("super-secret-value");
    expect(encrypted.ciphertext.toString("latin1")).not.toContain("super-secret-value");
  });

  it("round-trips the value types the backend actually stores", () => {
    const key = randomBytes(32);
    for (const value of [{ nested: { list: [1, 2, 3], flag: true } }, [], "plain string", 42, null]) {
      expect(decryptJson(encryptJson(value, key, "ctx"), key, "ctx")).toEqual(value);
    }
  });

  it("treats an empty context as its own distinct binding", () => {
    const key = randomBytes(32);
    const encrypted = encryptJson({ a: 1 }, key, "");
    expect(decryptJson(encrypted, key, "")).toEqual({ a: 1 });
    expect(() => decryptJson(encrypted, key, "x")).toThrow();
  });
});
