import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const runtimeSource = await readFile(join(root, "index.js"), "utf8");
const forbiddenPattern = /\bconsole\.(log|info|warn|error|debug|trace)\s*\(/;

if (forbiddenPattern.test(runtimeSource)) {
  throw new Error("index.js must not use console.*; stdout is reserved for MCP stdio messages.");
}
