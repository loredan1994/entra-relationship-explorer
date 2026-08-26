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
