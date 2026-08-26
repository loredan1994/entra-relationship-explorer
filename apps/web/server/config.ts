import "server-only";
import { parseEntraConfig } from "./config-core";

export function getEntraConfig() {
  return parseEntraConfig(process.env);
}
