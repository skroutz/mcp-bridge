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

test("buildBrowserEnvCommand routes a %s nested inside single quotes within a -c script through $0", () => {
  const result = buildBrowserEnvCommand(`sh -c "firefox '%s'"`, target);
  assert.equal(result.command, "sh");
  assert.deepEqual(result.args, ["-c", `firefox ''"$0"''`, target]);
});

test("buildBrowserEnvCommand routes a %s nested inside double quotes within a -c script through a bare $0", () => {
  const result = buildBrowserEnvCommand(`sh -c 'firefox "%s"'`, target);
  assert.equal(result.command, "sh");
  assert.deepEqual(result.args, ["-c", 'firefox "$0"', target]);
});

test("buildBrowserEnvCommand substitutes a %s that is a plain arg after the script, not inside it", () => {
  const result = buildBrowserEnvCommand(`sh -c 'exec firefox "$1"' launcher %s`, target);
  assert.equal(result.command, "sh");
  assert.deepEqual(result.args, ["-c", 'exec firefox "$1"', "launcher", target]);
});

test("buildBrowserEnvCommand leaves a non-shell -c interpreter's script untouched and substitutes a trailing %s", () => {
  const result = buildBrowserEnvCommand(`python3 -c 'webbrowser.open(sys.argv[1])' %s`, target);
  assert.equal(result.command, "python3");
  assert.deepEqual(result.args, ["-c", "webbrowser.open(sys.argv[1])", target]);
});

test("buildBrowserEnvCommand refuses a non-shell -c script whose only %s is inside the script text", () => {
  assert.throws(
    () => buildBrowserEnvCommand(`python3 -c 'webbrowser.open("%s")'`, target),
    /Cannot substitute %s inside a python3 -c script/
  );
});

test("buildBrowserEnvCommand does not throw when a non-shell script's %s is matched by a trailing %s too", () => {
  const result = buildBrowserEnvCommand(`python3 -c 'print("%s")' %s`, target);
  assert.equal(result.command, "python3");
  assert.deepEqual(result.args, ["-c", 'print("%s")', target]);
});

test("buildBrowserEnvCommand recognizes a versioned interpreter binary as non-shell", () => {
  for (const command of ["python3.11", "ruby3.2", "php8.1"]) {
    const script = `webbrowser.open("%s")`;
    const result = buildBrowserEnvCommand(`${command} -c ${JSON.stringify(script)} %s`, target);
    assert.equal(result.command, command);
    assert.deepEqual(result.args, ["-c", script, target], `for ${command}`);
  }
});

test("buildBrowserEnvCommand fails closed on any trailing -c, even one that looks like unrelated positional data", () => {
  const result = buildBrowserEnvCommand(`sh -c 'launch "$1" "$2"' %s -c`, target);
  assert.equal(result.command, "sh");
  assert.deepEqual(result.args, ["-c", 'launch "$1" "$2"', "%s", "-c", target]);
});

test("buildBrowserEnvCommand fails closed on a shell name anywhere in the entry, even inside an unrelated arg value", () => {
  const result = buildBrowserEnvCommand("firefox --profile /home/user/bash %s", target);
  assert.equal(result.command, "firefox");
  assert.deepEqual(result.args, ["--profile", "/home/user/bash", "%s", target]);
});

test("buildBrowserEnvCommand still fails closed on a bundled shell flag reached through an env wrapper", () => {
  const hostile = "https://mcp.example.test/cb?a=$(touch pwn)";
  const result = buildBrowserEnvCommand("env sh -ic 'chromium %s'", hostile);
  assert.equal(result.command, "env");
  assert.deepEqual(result.args, ["sh", "-ic", "chromium %s", hostile]);
});

test("a %s nested inside single quotes within a -c script passes a hostile URL through $0 unexecuted", async () => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "argv.json");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const entry = `sh -c "${process.execPath} '${argvEchoScript}' '${outputPath}' '%s'"`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    await runCommand(command, args);

    const received = JSON.parse(await readFile(outputPath, "utf8"));
    assert.deepEqual(received, [hostile]);
    assert.equal(existsSync(canaryPath), false);
  });
});

test("a %s given as a plain arg after the script passes a hostile URL through unexecuted", async () => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "argv.json");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const entry = `sh -c 'exec "${process.execPath}" "${argvEchoScript}" "${outputPath}" "$1"' launcher %s`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    await runCommand(command, args);

    const received = JSON.parse(await readFile(outputPath, "utf8"));
    assert.deepEqual(received, [hostile]);
    assert.equal(existsSync(canaryPath), false);
  });
});

test("a non-shell -c interpreter's trailing %s passes a hostile URL through argv unexecuted", async (t) => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "argv.json");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const pyScript = `import sys, json; open(sys.argv[1], "w").write(json.dumps(sys.argv[2:]))`;
    const entry = `python3 -c ${JSON.stringify(pyScript)} '${outputPath}' %s`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);

    try {
      await runCommand(command, args);
    } catch (error) {
      if (error.code === "ENOENT") {
        t.skip("python3 is not available in this environment.");
        return;
      }
      throw error;
    }

    const received = JSON.parse(await readFile(outputPath, "utf8"));
    assert.deepEqual(received, [hostile]);
    assert.equal(existsSync(canaryPath), false);
  });
});

test("buildBrowserEnvCommand still fails closed on a bundled shell flag reached through a non-env wrapper", () => {
  const hostile = "https://mcp.example.test/cb?a=$(touch pwn)";
  for (const wrapper of ["nice", "sudo", "flatpak run"]) {
    const result = buildBrowserEnvCommand(`${wrapper} bash -ic 'chromium %s'`, hostile);
    assert.deepEqual(
      result.args,
      [...wrapper.split(" ").slice(1), "bash", "-ic", "chromium %s", hostile],
      `for wrapper "${wrapper}"`
    );
  }
});

test("a bundled shell flag reached through a non-env wrapper never executes an injected payload", async () => {
  await withTemporaryDirectory(async (directory) => {
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}`;
    const entry = `nice bash -ic 'echo START %s END'`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    await runCommand(command, args);

    assert.equal(existsSync(canaryPath), false);
  });
});

test("buildBrowserEnvCommand recognizes a non-shell interpreter reached through the env wrapper", () => {
  const result = buildBrowserEnvCommand(`env python3 -c 'webbrowser.open(sys.argv[1])' %s`, target);
  assert.equal(result.command, "env");
  assert.deepEqual(result.args, ["python3", "-c", "webbrowser.open(sys.argv[1])", target]);
});

test("buildBrowserEnvCommand recognizes a non-shell interpreter given as an absolute path", () => {
  const result = buildBrowserEnvCommand(`/usr/bin/python3 -c 'webbrowser.open(sys.argv[1])' %s`, target);
  assert.equal(result.command, "/usr/bin/python3");
  assert.deepEqual(result.args, ["-c", "webbrowser.open(sys.argv[1])", target]);
});

test("buildBrowserEnvCommand recognizes further versioned and bare non-shell interpreters", () => {
  const cases = [
    ["perl5.34", `print("%s")`],
    ["lua5.4", `print("%s")`],
    ["tclsh8.6", `puts "%s"`],
    ["/usr/bin/python3.12", `print("%s")`]
  ];
  for (const [command, script] of cases) {
    const entry = `${command} -c ${JSON.stringify(script)} %s`;
    const result = buildBrowserEnvCommand(entry, target);
    assert.equal(result.command, command, `for ${command}`);
    assert.deepEqual(result.args, ["-c", script, target], `for ${command}`);
  }
});

test("buildBrowserEnvCommand does not mistake a non-shell-lookalike name for a recognized interpreter", () => {
  for (const command of ["pythonic", "perl-ish", "mypython3"]) {
    const result = buildBrowserEnvCommand(`${command} -c "print(%s)"`, target);
    assert.equal(result.command, command);
    assert.deepEqual(result.args, ["-c", 'print("$0")', target], `for ${command}`);
  }
});

test("buildBrowserEnvCommand substitutes %s independently in both a shell script and a trailing arg", () => {
  const result = buildBrowserEnvCommand(`sh -c 'firefox %s' extra-%s-arg`, target);
  assert.equal(result.command, "sh");
  assert.deepEqual(result.args, ["-c", 'firefox "$0"', target, `extra-${target}-arg`]);
});

test("buildBrowserEnvCommand fails closed on any number of extra -c tokens too", () => {
  const result = buildBrowserEnvCommand(`sh -c 'launch "$1"' %s -c -c`, target);
  assert.equal(result.command, "sh");
  assert.deepEqual(result.args, ["-c", 'launch "$1"', "%s", "-c", "-c", target]);
});

test("buildBrowserEnvCommand still fails closed when a genuinely ambiguous -c also has a trailing -c", () => {
  const hostile = "https://mcp.example.test/cb?a=$(touch pwn)";
  const result = buildBrowserEnvCommand(`bash --rcfile -c -c 'echo hi %s' -c`, hostile);
  assert.equal(result.command, "bash");
  assert.deepEqual(result.args, ["--rcfile", "-c", "-c", "echo hi %s", "-c", hostile]);
});

test("openBrowserLinuxCommands skips a non-shell -c entry with an unreachable script placeholder and keeps trying", () => {
  const previousBrowser = process.env.BROWSER;
  process.env.BROWSER = `python3 -c 'webbrowser.open("%s")':w3m`;
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

test("a shell name that is only a path segment inside an unrelated argument still fails closed end to end", async () => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "argv.json");
    const entry = `${process.execPath} '${argvEchoScript}' '${outputPath}' --profile /home/user/bash %s`;
    const { args, command } = buildBrowserEnvCommand(entry, target);
    await runCommand(command, args);

    const received = JSON.parse(await readFile(outputPath, "utf8"));
    assert.deepEqual(received, ["--profile", "/home/user/bash", "%s", target]);
  });
});

async function assertSpawnDoesNotInject(entry, t) {
  await withTemporaryDirectory(async (directory) => {
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    try {
      await runCommand(command, args);
    } catch (error) {
      if (t && error.code === "ENOENT") {
        t.skip(`${command} is not available in this environment.`);
        return;
      }
    }
    assert.equal(existsSync(canaryPath), false);
  });
}

test("buildBrowserEnvCommand fails closed when a decoy -c and the real one are separated by another flag", () => {
  const hostile = "https://mcp.example.test/cb?a=$(touch pwn)";
  const result = buildBrowserEnvCommand(`bash --rcfile -c -x -c 'echo hi %s'`, hostile);
  assert.equal(result.command, "bash");
  assert.deepEqual(result.args, ["--rcfile", "-c", "-x", "-c", "echo hi %s", hostile]);
});

test("a decoy -c separated from the real one by another flag never executes an injected payload", async () => {
  await assertSpawnDoesNotInject(`bash --rcfile -c -x -c 'echo hi %s'`);
});

test("buildBrowserEnvCommand fails closed on a bundled shell flag reached through a wrapper's own boolean flag", () => {
  const hostile = "https://mcp.example.test/cb?a=$(touch pwn)";
  for (const entry of [`env -i bash -ic 'echo START %s END'`, `sudo -n bash -ic 'echo START %s END'`]) {
    const result = buildBrowserEnvCommand(entry, hostile);
    assert.ok(result.args.includes("echo START %s END"), `%s must stay literal for "${entry}"`);
    assert.equal(result.args.at(-1), hostile, `target must only be appended for "${entry}"`);
  }
});

test("a bundled shell flag reached through a wrapper's own boolean flag never executes an injected payload", async () => {
  await assertSpawnDoesNotInject(`env -i bash -ic 'echo START %s END'`);
});

test("buildBrowserEnvCommand refuses a node -e script whose only %s is inside the eval text", () => {
  assert.throws(
    () => buildBrowserEnvCommand(`node -e 'require("child_process").execSync("%s")'`, target),
    /Cannot substitute %s inside a node -e script/
  );
});

test("buildBrowserEnvCommand refuses a perl -e or php -r script whose only %s is inside the eval text", () => {
  assert.throws(
    () => buildBrowserEnvCommand(`perl -e 'system("%s")'`, target),
    /Cannot substitute %s inside a perl -e script/
  );
  assert.throws(
    () => buildBrowserEnvCommand(`php -r 'system("%s");'`, target),
    /Cannot substitute %s inside a php -r script/
  );
});

test("buildBrowserEnvCommand leaves a node -e script untouched and substitutes a trailing %s", () => {
  const result = buildBrowserEnvCommand(`node -e 'require("child_process").execSync(process.argv[1])' %s`, target);
  assert.equal(result.command, "node");
  assert.deepEqual(result.args, ["-e", "require(\"child_process\").execSync(process.argv[1])", target]);
});

test("buildBrowserEnvCommand fails closed, never substituting %s, when -e's position is ambiguous", () => {
  const result = buildBrowserEnvCommand(`node --require -e -e 'require("child_process").execSync("%s")'`, target);
  assert.equal(result.command, "node");
  assert.deepEqual(result.args, ["--require", "-e", "-e", 'require("child_process").execSync("%s")', target]);
});

test("buildBrowserEnvCommand does not treat a shell's own bare -e (no -c) as an eval flag", () => {
  const result = buildBrowserEnvCommand(`sh -e 'firefox %s'`, target);
  assert.equal(result.command, "sh");
  assert.deepEqual(result.args, ["-e", "firefox %s", target]);
});

test("a node -e script with a trailing %s passes a hostile URL through argv unexecuted", async () => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "argv.json");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const jsScript = `require("fs").writeFileSync(${JSON.stringify(outputPath)}, JSON.stringify(process.argv.slice(1)))`;
    const entry = `${process.execPath} -e ${JSON.stringify(jsScript)} %s`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    await runCommand(command, args);

    const received = JSON.parse(await readFile(outputPath, "utf8"));
    assert.deepEqual(received, [hostile]);
    assert.equal(existsSync(canaryPath), false);
  });
});

test("a non-shell -c interpreter's own script keeps a literal %s inert while a trailing %s still delivers the real URL", async () => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "out.json");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const pyScript = `import sys, json, os; os.system("%s"); open(sys.argv[1], "w").write(json.dumps(sys.argv[2:]))`;
    const entry = `python3 -c ${JSON.stringify(pyScript)} '${outputPath}' %s`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    await runCommand(command, args);

    const received = JSON.parse(await readFile(outputPath, "utf8"));
    assert.deepEqual(received, [hostile]);
    assert.equal(existsSync(canaryPath), false);
  });
});

test("a node -e script's own literal %s stays inert while a trailing %s still delivers the real URL", async () => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "out.json");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const jsScript = `require("fs").writeFileSync(process.argv[1], JSON.stringify(process.argv.slice(2))); try { require("child_process").execSync("%s"); } catch {}`;
    const entry = `${process.execPath} -e ${JSON.stringify(jsScript)} '${outputPath}' %s`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    await runCommand(command, args);

    const received = JSON.parse(await readFile(outputPath, "utf8"));
    assert.deepEqual(received, [hostile]);
    assert.equal(existsSync(canaryPath), false);
  });
});

test("a perl -e script with a trailing %s passes a hostile URL through argv unexecuted", async (t) => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "out.txt");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const entry = `perl -e 'open(my $fh, ">", $ARGV[0]) or die $!; print $fh $ARGV[1];' '${outputPath}' %s`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    try {
      await runCommand(command, args);
    } catch (error) {
      if (error.code === "ENOENT") {
        t.skip("perl is not available in this environment.");
        return;
      }
      throw error;
    }

    assert.equal(await readFile(outputPath, "utf8"), hostile);
    assert.equal(existsSync(canaryPath), false);
  });
});

test("a php -r script with a trailing %s passes a hostile URL through argv unexecuted", async (t) => {
  await withTemporaryDirectory(async (directory) => {
    const outputPath = join(directory, "out.txt");
    const canaryPath = join(directory, "INJECTED");
    const hostile = `https://mcp.example.test/cb?a=1; touch ${canaryPath}; \`touch ${canaryPath}\` $(touch ${canaryPath})`;

    const entry = `php -r 'file_put_contents($argv[1], $argv[2]);' '${outputPath}' %s`;
    const { args, command } = buildBrowserEnvCommand(entry, hostile);
    try {
      await runCommand(command, args);
    } catch (error) {
      if (error.code === "ENOENT") {
        t.skip("php is not available in this environment.");
        return;
      }
      throw error;
    }

    assert.equal(await readFile(outputPath, "utf8"), hostile);
    assert.equal(existsSync(canaryPath), false);
  });
});

test("buildBrowserEnvCommand fails closed on awk's bare program argument, with no -c at all", () => {
  const hostile = "https://mcp.example.test/cb?a=$(touch pwn)";
  for (const command of ["awk", "gawk"]) {
    const result = buildBrowserEnvCommand(`${command} 'BEGIN{system("%s")}'`, hostile);
    assert.deepEqual(result.args, ['BEGIN{system("%s")}', hostile], `for ${command}`);
  }
});

test("buildBrowserEnvCommand fails closed on awk even when a value-taking flag like -v precedes the program", () => {
  const hostile = "https://mcp.example.test/cb?a=$(touch pwn)";
  const result = buildBrowserEnvCommand(`awk -v x=1 'BEGIN{system("%s")}'`, hostile);
  assert.deepEqual(result.args, ["-v", "x=1", 'BEGIN{system("%s")}', hostile]);
});

test("awk's bare program argument never executes an injected payload", async () => {
  await assertSpawnDoesNotInject(`awk 'BEGIN{system("%s")}'`);
});

test("gawk's bare program argument never executes an injected payload", async (t) => {
  await assertSpawnDoesNotInject(`gawk 'BEGIN{system("%s")}'`, t);
});
