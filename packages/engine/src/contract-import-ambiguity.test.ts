import { expect, it } from "vitest";
import { compileSnapshot, evaluateContract, parseContract, type AccessContract } from "./index";
import { query, snapshot } from "./test-support";

const contract: AccessContract = {
  version: 1, tenantId: query.tenantId, id: "synthetic-allowlist", kind: "only-principals",
  resourceId: "resource", permissionId: "read-id", allowedPrincipalIds: ["client"],
};

it.each([
  ['"tenantId"', '"another-synthetic-tenant"'],
  ['"tenant\\u0049d"', '"another-synthetic-tenant"'],
  ['"allowedPrincipalIds"', "[]"],
  ['"allowedPrincipal\\u0049ds"', "[]"],
  ['"version"', "2"],
  ['"allowedPrincipalIds"', '["client"]'],
])("rejects overwritten contract field %s with first value %s", (key, first) => {
  const original = JSON.stringify(contract);
  const ambiguous = `{${key}:${first},${original.slice(1)}`;
  expect(JSON.parse(ambiguous)).toEqual(contract);
  expect(() => parseContract(ambiguous)).toThrow("Duplicate contract field");
});

it("cannot silently replace a restrictive allowlist with one that makes a configured grant pass", () => {
  const model = compileSnapshot(snapshot());
  expect(evaluateContract(model, { ...contract, allowedPrincipalIds: [] }).status).toBe("fail");
  expect(evaluateContract(model, contract).status).toBe("pass");
  const ambiguous = JSON.stringify(contract).replace('"allowedPrincipalIds":["client"]', '"allowedPrincipalIds":[],"allowedPrincipalIds":["client"]');
  expect(() => parseContract(ambiguous)).toThrow("Duplicate contract field");
});

it("accepts key-like identifier text and escaped values without mistaking them for object fields", () => {
  const value = { ...contract, id: '{"tenantId":"a","tenantId":"b"}', allowedPrincipalIds: ['[{}]:"\\'] };
  expect(parseContract(JSON.stringify(value, null, "\t"))).toEqual(value);
});

it.each(['quoted " identifier', 'backslash \\" identifier', 'fake field ","tenantId":"other"'])("still rejects ambiguous tenant and allowlist fields after escaped identifier %j", id => {
    const value = { id, version: contract.version, tenantId: contract.tenantId, kind: contract.kind,
      resourceId: contract.resourceId, permissionId: contract.permissionId, allowedPrincipalIds: contract.allowedPrincipalIds };
    const original = JSON.stringify(value);
    for (const [key, first] of [["tenantId", '"another-synthetic-tenant"'], ["allowedPrincipalIds", "[]"]]) {
      const ambiguous = original.replace(`"${key}":`, `"${key}":${first},"${key}":`);
      expect(JSON.parse(ambiguous)).toEqual(value);
      expect(() => parseContract(ambiguous)).toThrow("Duplicate contract field");
    }
  });
