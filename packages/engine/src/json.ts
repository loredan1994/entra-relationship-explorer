/** Native JSON parsing discards earlier duplicate fields, including their unsafe contents. */
export function parseUniqueJson(text: string, context: "Investigation" | "Contract", maxDepth = Infinity): unknown {
  const scopes: Array<Set<string> | null> = [];
  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (character === "{" || character === "[") {
      if (scopes.length > maxDepth) throw new Error(`${context} exceeds structural limits.`);
      scopes.push(character === "{" ? new Set() : null);
      continue;
    }
    if (character === "}" || character === "]") { scopes.pop(); continue; }
    if (character !== '"') continue;
    const start = index;
    // Skip an entire JSON string, so braces and key-like text inside evidence
    // cannot change the object scope. JSON.parse still validates the grammar.
    while (++index < text.length) {
      if (text[index] === "\\") index++;
      else if (text[index] === '"') break;
    }
    let next = index + 1;
    while (/[ \t\r\n]/.test(text.charAt(next))) next++;
    const keys = scopes.at(-1);
    if (text[next] === ":" && keys) {
      const key = JSON.parse(text.slice(start, index + 1)) as string;
      if (keys.has(key)) throw new Error(`Duplicate ${context.toLowerCase()} field.`);
      keys.add(key);
    }
  }
  return JSON.parse(text);
}

