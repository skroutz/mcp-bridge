import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

process.env.MCP_BRIDGE_TEST_MODE = "1";

const { buildBrowserEnvCommand, openBrowserLinuxCommands, tokenizeShellWords } = await import("../index.js");

const testDirectory = dirname(fileURLToPath(import.meta.url));
const argvEchoScript = join(testDirectory, "..", "test-fixtures", "argv-echo.mjs");
const target = "https://mcp.example.test/oauth/callback?state=abc123";

async function withTemporaryDirectory(run) {
  const directory = await mkdtemp(join(tmpdir(), "mcp-bridge-browser-open-test-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function runCommand(command, args) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { stdio: "ignore" });
    child.once("error", rejectRun);
    child.once("exit", (code) => (code === 0 ? resolveRun() : rejectRun(new Error(`exited ${code}`))));
  });
}

test("tokenizeShellWords splits bare, single-quoted, and double-quoted words", () => {
  assert.deepEqual(tokenizeShellWords("firefox %s"), ["firefox", "%s"]);
  assert.deepEqual(tokenizeShellWords("firefox '%s'"), ["firefox", "%s"]);
  assert.deepEqual(tokenizeShellWords('firefox "%s"'), ["firefox", "%s"]);
  assert.deepEqual(tokenizeShellWords("sh -c 'firefox %s'"), ["sh", "-c", "firefox %s"]);
});

test("buildBrowserEnvCommand substitutes a bare %s placeholder without a shell", () => {
  const result = buildBrowserEnvCommand("firefox %s", target);
  assert.deepEqual(result, { args: [target], command: "firefox", method: "browser-env:firefox %s" });
});

test("buildBrowserEnvCommand substitutes a single-quoted %s placeholder", () => {
  const result = buildBrowserEnvCommand("firefox '%s'", target);
  assert.equal(result.command, "firefox");
  assert.deepEqual(result.args, [target]);
});

test("buildBrowserEnvCommand substitutes a double-quoted %s placeholder", () => {
  const result = buildBrowserEnvCommand('firefox "%s"', target);
  assert.equal(result.command, "firefox");
  assert.deepEqual(result.args, [target]);
});

test("buildBrowserEnvCommand substitutes repeated %s placeholders", () => {
  const separate = buildBrowserEnvCommand("firefox %s %s", target);
  assert.deepEqual(separate.args, [target, target]);

  const sameArg = buildBrowserEnvCommand("firefox --url=%s&fallback=%s", target);
  assert.deepEqual(sameArg.args, [`--url=${target}&fallback=${target}`]);
});

test("buildBrowserEnvCommand appends the URL when there is no placeholder", () => {
  const result = buildBrowserEnvCommand("firefox --new-window", target);
  assert.equal(result.command, "firefox");
  assert.deepEqual(result.args, ["--new-window", target]);
});

test("buildBrowserEnvCommand keeps a URL with shell-significant characters as literal data", () => {
  const hostile = "https://mcp.example.test/cb?a=1; touch pwn; `touch pwn2` $(touch pwn3)";
  const result = buildBrowserEnvCommand("firefox %s", hostile);
  assert.deepEqual(result.args, [hostile]);
});

test("buildBrowserEnvCommand routes an explicit sh -c wrapper's URL through a positional argument, not the script text", () => {
  const result = buildBrowserEnvCommand("sh -c 'firefox %s'", target);
  assert.equal(result.command, "sh");
  assert.deepEqual(result.args, ["-c", 'firefox "$0"', target]);
});

test("buildBrowserEnvCommand preserves extra positional args after an sh -c wrapper's script", () => {
  const result = buildBrowserEnvCommand("sh -c 'firefox %s' --flag", target);
  assert.deepEqual(result.args, ["-c", 'firefox "$0"', target, "--flag"]);
});

test("buildBrowserEnvCommand finds -c after other shell flags, not just at args[0]", () => {
  const result = buildBrowserEnvCommand("bash --norc -c 'chromium %s'", target);
  assert.equal(result.command, "bash");
  assert.deepEqual(result.args, ["--norc", "-c", 'chromium "$0"', target]);
});

test("buildBrowserEnvCommand recognizes an absolute path to a shell interpreter", () => {
  const result = buildBrowserEnvCommand("/bin/bash -c 'chromium %s'", target);
  assert.equal(result.command, "/bin/bash");
  assert.deepEqual(result.args, ["-c", 'chromium "$0"', target]);
});

test("buildBrowserEnvCommand routes %s through $0 for a -c wrapper even when the shell isn't in the known-names list", () => {
  const result = buildBrowserEnvCommand("fish -c 'firefox %s'", target);
  assert.equal(result.command, "fish");
  assert.deepEqual(result.args, ["-c", 'firefox "$0"', target]);
});

test("buildBrowserEnvCommand appends the URL without rewriting the script when an sh -c wrapper has no placeholder", () => {
  const result = buildBrowserEnvCommand("sh -c 'firefox --new-window'", target);
  assert.equal(result.command, "sh");
  assert.deepEqual(result.args, ["-c", "firefox --new-window", target]);
});

test("buildBrowserEnvCommand never splices %s into shell source when -c can't be confidently located", () => {
  const hostile = "https://mcp.example.test/cb?a=$(touch pwn)";
  const result = buildBrowserEnvCommand("bash -ic 'chromium %s'", hostile);
  assert.equal(result.command, "bash");
  assert.deepEqual(result.args, ["-ic", "chromium %s", hostile]);
});

test("buildBrowserEnvCommand finds a shell reached through a wrapper like env, not just as the command itself", () => {
  const result = buildBrowserEnvCommand("env sh -c 'xdg-open %s'", target);
  assert.equal(result.command, "env");
  assert.deepEqual(result.args, ["sh", "-c", 'xdg-open "$0"', target]);
});

test("buildBrowserEnvCommand fails closed, never substituting %s, when -c's position is ambiguous", () => {
  const hostile = "https://mcp.example.test/cb?a=$(touch pwn)";
  const result = buildBrowserEnvCommand("bash --rcfile -c -c 'echo hi %s'", hostile);
  assert.equal(result.command, "bash");
  assert.deepEqual(result.args, ["--rcfile", "-c", "-c", "echo hi %s", hostile]);
});

test("openBrowserLinuxCommands builds candidates from BROWSER entries and the built-in openers", () => {
  const previousBrowser = process.env.BROWSER;
  process.env.BROWSER = "firefox %s:w3m";
  try {
    const commands = openBrowserLinuxCommands(target);
    assert.deepEqual(commands[0], { args: [target], command: "firefox", method: "browser-env:firefox %s" });
    assert.deepEqual(commands[1], { args: [target], command: "w3m", method: "browser-env:w3m" });
    assert.ok(commands.some((candidate) => candidate.method === "xdg-open"));
  } finally {
    if (previousBrowser === undefined) {
      delete process.env.BROWSER;
    } else {
      process.env.BROWSER = previousBrowser;
    }
  }
});

test("openBrowserLinuxCommands skips a malformed BROWSER entry instead of losing every candidate", () => {
  const previousBrowser = process.env.BROWSER;
  process.env.BROWSER = "firefox 'unterminated:w3m";
  try {
    const commands = openBrowserLinuxCommands(target);
    assert.deepEqual(commands[0], { args: [target], command: "w3m", method: "browser-env:w3m" });
    assert.ok(commands.some((candidate) => candidate.method === "xdg-open"));
  } finally {
    if (previousBrowser === undefined) {
      delete process.env.BROWSER;
    } else {
      process.env.BROWSER = previousBrowser;
    }
  }
});

test("a bare %s launcher passes a hostile URL to the target process unexecuted", async () => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "argv.json");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const entry = `${process.execPath} '${argvEchoScript}' '${outputPath}' %s`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    await runCommand(command, args);

    const received = JSON.parse(await readFile(outputPath, "utf8"));
    assert.deepEqual(received, [hostile]);
    assert.equal(existsSync(canaryPath), false);
  });
});

test("an explicit sh -c wrapper passes a hostile URL through $0 unexecuted", async () => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "argv.json");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const entry = `sh -c '${process.execPath} "${argvEchoScript}" "${outputPath}" %s'`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    await runCommand(command, args);

    const received = JSON.parse(await readFile(outputPath, "utf8"));
    assert.deepEqual(received, [hostile]);
    assert.equal(existsSync(canaryPath), false);
  });
});

test("an sh -c wrapper with a flag before -c still passes a hostile URL through $0 unexecuted", async () => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "argv.json");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const entry = `sh -e -c '${process.execPath} "${argvEchoScript}" "${outputPath}" %s'`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    await runCommand(command, args);

    const received = JSON.parse(await readFile(outputPath, "utf8"));
    assert.deepEqual(received, [hostile]);
    assert.equal(existsSync(canaryPath), false);
  });
});

test("a shell reached through an env wrapper still passes a hostile URL through $0 unexecuted", async () => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "argv.json");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const entry = `env sh -c '${process.execPath} "${argvEchoScript}" "${outputPath}" %s'`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    await runCommand(command, args);

    const received = JSON.parse(await readFile(outputPath, "utf8"));
    assert.deepEqual(received, [hostile]);
    assert.equal(existsSync(canaryPath), false);
  });
});
