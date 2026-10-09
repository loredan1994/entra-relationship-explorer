import { expect, it } from "vitest";
import { canonicalOpaqueId } from "./opaque-id";

const id = "abcdefab-cdef-4abc-8def-abcdefabcdef";

it.each([id, id.toUpperCase(), "AbCdEfAb-cdef-4abc-8def-abcdefabcdef"])("canonicalizes the exact UUID spelling %s", value => {
  expect(canonicalOpaqueId(value)).toBe(id);
});

it.each([undefined, "", "invalid", ` ${id}`, `${id} `, `${id}\n`, `${id}\r`, `${id}\u2028`, id.replaceAll("-", ""), `{${id}}`, `urn:uuid:${id}`, id.replace("a", "g"), id.replace("-", "_")])("rejects malformed opaque identifier %j", value => {
  expect(canonicalOpaqueId(value)).toBeNull();
});
