import fs from "node:fs";

const manifests = [
  "apps/web/package.json",
  "packages/backend/package.json",
  "packages/domain/package.json",
  "packages/graph/package.json",
];

for (const manifest of manifests) {
  const parsed = JSON.parse(fs.readFileSync(manifest, "utf8"));
  delete parsed.devDependencies;
  delete parsed.scripts;
  fs.writeFileSync(manifest, `${JSON.stringify(parsed, null, 2)}\n`);
}
