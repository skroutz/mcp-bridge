import { mkdir, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { createWriteStream } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = parseArgs(process.argv.slice(2));
const inputPath = resolve(root, args.mcpb ?? "dist/skroutz-mcp-bridge-0.1.10.mcpb");
const timeoutMs = Number(args.timeoutMs ?? 70_000);
const protocolVersion = args.protocolVersion ?? "2025-11-25";
const inputStat = await stat(inputPath);
const extractedTempDir = inputStat.isDirectory() ? undefined : await mkdtemp(join(tmpdir(), "mcpb-emulate-"));
const extensionDir = extractedTempDir ?? inputPath;

try {
  if (extractedTempDir) {
    await run("unzip", ["-q", inputPath, "-d", extractedTempDir], { cwd: root });
  }

  const manifest = JSON.parse(await readFile(join(extensionDir, "manifest.json"), "utf8"));
  const mcpConfig = manifest.server?.mcp_config;
  if (!mcpConfig?.command) {
    throw new Error("manifest.json does not contain server.mcp_config.command");
  }

  const env = {
    ...baseEnvironment(args.cleanEnv),
    ...substituteObject(mcpConfig.env ?? {}, extensionDir)
  };
  const command = substitute(mcpConfig.command, extensionDir);
  const commandArgs = (mcpConfig.args ?? []).map((arg) => substitute(arg, extensionDir));
  const stdoutPath = resolve(root, args.stdout ?? "dist/mcpb-emulate.stdout");
  const stderrPath = resolve(root, args.stderr ?? "dist/mcpb-emulate.stderr");
  await mkdir(dirname(stdoutPath), { recursive: true });
  await mkdir(dirname(stderrPath), { recursive: true });
  const stdoutStream = createWriteStream(stdoutPath, { flags: "w" });
  const stderrStream = createWriteStream(stderrPath, { flags: "w" });

  process.stderr.write(`MCPB input: ${inputPath}\n`);
  process.stderr.write(inputStat.isDirectory()
    ? `Extension directory: ${extensionDir}\n`
    : `Extracted: ${extensionDir}\n`);
  process.stderr.write(`Command: ${command} ${commandArgs.join(" ")}\n`);
  process.stderr.write(`Stdout: ${stdoutPath}\n`);
  process.stderr.write(`Stderr: ${stderrPath}\n`);
  process.stderr.write(`Timeout: ${timeoutMs}ms\n`);

  const child = spawn(command, commandArgs, {
    cwd: extensionDir,
    env,
    stdio: ["pipe", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  let sawInitializeResponse = false;
  const initializeMessage = {
    jsonrpc: "2.0",
    id: 0,
    method: "initialize",
    params: {
      protocolVersion,
      capabilities: {
        extensions: {
          "io.modelcontextprotocol/ui": {
            mimeTypes: ["text/html;profile=mcp-app"]
          }
        }
      },
      clientInfo: {
        name: "claude-ai",
        version: "0.1.10"
      }
    }
  };

  const resultPromise = waitForChildResponseOrTimeout(child, timeoutMs, () => sawInitializeResponse);

  child.stdout.on("data", (chunk) => {
    const text = chunk.toString("utf8");
    stdout += text;
    stdoutStream.write(chunk);
    if (text.includes('"id":0') || text.includes('"id": 0')) {
      sawInitializeResponse = true;
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
    stderrStream.write(chunk);
  });
  child.once("spawn", () => {
    child.stdin.write(`${JSON.stringify(initializeMessage)}\n`);
  });

  const result = await resultPromise;
  child.stdin.end();
  if (result.sawResponse) {
    child.kill("SIGTERM");
  }
  stdoutStream.end();
  stderrStream.end();

  if (result.timedOut) {
    process.stderr.write("Result: timed out waiting for initialize response.\n");
    process.stderr.write(lastLines(stderr, "Recent stderr"));
    process.exitCode = 2;
  } else {
    process.stderr.write(result.sawResponse
      ? "Result: initialize response observed; stopped emulator process.\n"
      : `Result: process exited with code ${result.code}.\n`);
    process.stderr.write(sawInitializeResponse
      ? "Initialize response: observed on stdout.\n"
      : "Initialize response: not observed on stdout.\n");
    if (!sawInitializeResponse) {
      process.stderr.write(lastLines(stderr, "Recent stderr"));
      process.stderr.write(lastLines(stdout, "Recent stdout"));
      process.exitCode = 1;
    }
  }
} finally {
  if (extractedTempDir && !args.keepExtracted) {
    await rm(extractedTempDir, { recursive: true, force: true });
  }
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    switch (arg) {
      case "--mcpb":
        parsed.mcpb = readValue(argv, index, arg);
        index += 1;
        break;
      case "--timeout-ms":
        parsed.timeoutMs = readValue(argv, index, arg);
        index += 1;
        break;
      case "--protocol-version":
        parsed.protocolVersion = readValue(argv, index, arg);
        index += 1;
        break;
      case "--stdout":
        parsed.stdout = readValue(argv, index, arg);
        index += 1;
        break;
      case "--stderr":
        parsed.stderr = readValue(argv, index, arg);
        index += 1;
        break;
      case "--keep-extracted":
        parsed.keepExtracted = true;
        break;
      case "--clean-env":
        parsed.cleanEnv = true;
        break;
      default:
        if (!parsed.mcpb && !arg.startsWith("-")) {
          parsed.mcpb = arg;
          break;
        }
        throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return parsed;
}

function readValue(argv, index, arg) {
  const value = argv[index + 1];
  if (!value) {
    throw new Error(`${arg} requires a value`);
  }
  return value;
}

function substituteObject(input, extensionDir) {
  return Object.fromEntries(
    Object.entries(input).map(([key, value]) => [key, substitute(String(value), extensionDir)])
  );
}

function substitute(value, extensionDir) {
  return value.replaceAll("${__dirname}", extensionDir);
}

function baseEnvironment(cleanEnv) {
  if (!cleanEnv) {
    return process.env;
  }

  const keep = [
    "HOME",
    "LOGNAME",
    "PATH",
    "SystemRoot",
    "TMPDIR",
    "TEMP",
    "TMP",
    "USER",
    "USERNAME",
    "WINDIR"
  ];
  return Object.fromEntries(
    keep
      .filter((key) => process.env[key])
      .map((key) => [key, process.env[key]])
  );
}

function run(command, commandArgs, options) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, commandArgs, {
      ...options,
      stdio: "inherit"
    });
    child.once("error", rejectRun);
    child.once("exit", (code) => {
      if (code === 0) {
        resolveRun();
        return;
      }
      rejectRun(new Error(`${command} exited with code ${code}`));
    });
  });
}

function waitForChildResponseOrTimeout(child, timeoutMs, hasResponse) {
  return new Promise((resolveWait, rejectWait) => {
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      resolveWait({ timedOut: true });
    }, timeoutMs);
    const interval = setInterval(() => {
      if (!hasResponse()) {
        return;
      }
      clearTimeout(timeout);
      clearInterval(interval);
      resolveWait({ sawResponse: true, timedOut: false });
    }, 50);
    child.once("error", (error) => {
      clearTimeout(timeout);
      clearInterval(interval);
      rejectWait(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timeout);
      clearInterval(interval);
      resolveWait({ code, signal, timedOut: false });
    });
  });
}

function lastLines(text, label) {
  const lines = text.trim().split(/\r?\n/).filter(Boolean).slice(-20);
  if (lines.length === 0) {
    return `${label}: <empty>\n`;
  }
  return `${label}:\n${lines.join("\n")}\n`;
}
