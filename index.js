#!/usr/bin/env node

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ENTRYPOINT = fileURLToPath(import.meta.url);
const PACKAGE_ROOT = dirname(ENTRYPOINT);
const RESERVED_HEADERS = new Set([
  "accept",
  "connection",
  "content-length",
  "content-type",
  "host",
  "mcp-protocol-version",
  "mcp-session-id",
  "transfer-encoding"
]);

const HELP = `mcp-bridge

Securely proxy MCP JSON-RPC from local stdio to a remote Streamable-HTTP MCP endpoint.

Usage:
  mcp-bridge --url https://mcp.example.com/mcp
  MCP_BRIDGE_URL=https://mcp.example.com/mcp mcp-bridge

Options:
  --url, --endpoint <url>       Remote Streamable-HTTP MCP endpoint. Required.
  --bearer-token <token>        Bearer token for Authorization. Prefer env/config for secrets.
  --api-key <key>               API key sent as X-API-Key. Prefer env/config for secrets.
  --header <name:value>         Additional static HTTP header. Repeatable.
  --config <path>               JSON config file path. Supports ~ and relative paths.
  --allow-http                  Allow non-HTTPS endpoints. Intended only for local development.
  --timeout-ms <ms>             Optional fetch timeout. Disabled by default.
  --max-buffer-size <bytes>     Maximum local stdio message buffer. Default: 10485760.
  --help                        Show this help.
  --version                     Print package version.

Environment:
  MCP_BRIDGE_URL
  MCP_BRIDGE_BEARER_TOKEN
  MCP_BRIDGE_API_KEY
  MCP_BRIDGE_HEADERS            JSON object of additional headers.
  MCP_BRIDGE_CONFIG
  MCP_BRIDGE_ALLOW_HTTP
  MCP_BRIDGE_TIMEOUT_MS
  MCP_BRIDGE_MAX_BUFFER_SIZE
`;

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfigError";
  }
}

let stdioTransport;
let remoteTransport;
let closing = false;

function log(level, message, extra = undefined) {
  const suffix = extra ? ` ${JSON.stringify(extra, redactSecrets)}` : "";
  process.stderr.write(`[mcp-bridge] ${level}: ${message}${suffix}\n`);
}

function redactSecrets(key, value) {
  if (/authorization|token|api[-_]?key|secret/i.test(key)) {
    return "[redacted]";
  }
  return value;
}

function parseArgs(argv) {
  const parsed = {
    headers: []
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    switch (arg) {
      case "--help":
      case "-h":
        parsed.help = true;
        break;
      case "--version":
      case "-v":
        parsed.version = true;
        break;
      case "--allow-http":
        parsed.allowHttp = true;
        break;
      case "--url":
      case "--endpoint":
        parsed.endpoint = readRequiredValue(argv, index, arg);
        index += 1;
        break;
      case "--bearer-token":
        parsed.bearerToken = readRequiredValue(argv, index, arg);
        index += 1;
        break;
      case "--api-key":
        parsed.apiKey = readRequiredValue(argv, index, arg);
        index += 1;
        break;
      case "--header":
        parsed.headers.push(readRequiredValue(argv, index, arg));
        index += 1;
        break;
      case "--config":
        parsed.configPath = readRequiredValue(argv, index, arg);
        index += 1;
        break;
      case "--timeout-ms":
        parsed.timeoutMs = readRequiredValue(argv, index, arg);
        index += 1;
        break;
      case "--max-buffer-size":
        parsed.maxBufferSize = readRequiredValue(argv, index, arg);
        index += 1;
        break;
      default:
        if (arg.startsWith("-")) {
          throw new ConfigError(`Unknown option: ${arg}`);
        }
        if (!parsed.endpoint) {
          parsed.endpoint = arg;
          break;
        }
        throw new ConfigError(`Unexpected positional argument: ${arg}`);
    }
  }

  return parsed;
}

function readRequiredValue(argv, index, optionName) {
  const value = argv[index + 1];
  if (value === undefined) {
    throw new ConfigError(`${optionName} requires a value.`);
  }
  return value;
}

async function readPackageVersion() {
  try {
    const packageJson = await readJsonFile(resolve(PACKAGE_ROOT, "package.json"));
    return packageJson.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

async function readJsonFile(path) {
  const raw = await readFile(path, "utf8");
  return JSON.parse(raw);
}

function resolveConfigPath(inputPath) {
  if (!inputPath) {
    return undefined;
  }

  const expanded = inputPath === "~" || inputPath.startsWith("~/")
    ? resolve(homedir(), inputPath.slice(2))
    : inputPath;

  return isAbsolute(expanded) ? expanded : resolve(process.cwd(), expanded);
}

async function buildConfig(args, env) {
  const configPath = args.configPath ?? env.MCP_BRIDGE_CONFIG;
  const resolvedConfigPath = resolveConfigPath(configPath);
  const fileConfig = resolvedConfigPath ? await loadConfigFile(resolvedConfigPath) : {};
  const envHeaders = parseJsonHeaders(env.MCP_BRIDGE_HEADERS, "MCP_BRIDGE_HEADERS");
  const cliHeaders = parseCliHeaders(args.headers ?? []);
  const endpoint = args.endpoint ?? env.MCP_BRIDGE_URL ?? fileConfig.url ?? fileConfig.endpoint;
  const bearerToken = args.bearerToken ?? env.MCP_BRIDGE_BEARER_TOKEN ?? env.MCP_BRIDGE_TOKEN ?? fileConfig.bearerToken;
  const apiKey = args.apiKey ?? env.MCP_BRIDGE_API_KEY ?? fileConfig.apiKey;
  const allowHttp = parseOptionalBoolean(args.allowHttp)
    ?? parseOptionalBoolean(env.MCP_BRIDGE_ALLOW_HTTP)
    ?? parseOptionalBoolean(fileConfig.allowHttp)
    ?? false;
  const timeoutMs = parseOptionalInteger(args.timeoutMs ?? env.MCP_BRIDGE_TIMEOUT_MS ?? fileConfig.timeoutMs, "timeoutMs");
  const maxBufferSize = parseOptionalInteger(
    args.maxBufferSize ?? env.MCP_BRIDGE_MAX_BUFFER_SIZE ?? fileConfig.maxBufferSize,
    "maxBufferSize"
  ) ?? 10 * 1024 * 1024;
  const headers = normalizeHeaders({
    ...normalizeHeaders(fileConfig.headers ?? {}),
    ...envHeaders,
    ...cliHeaders
  });

  if (bearerToken) {
    headers.authorization = `Bearer ${bearerToken}`;
  }

  if (apiKey) {
    headers["x-api-key"] = apiKey;
  }

  const url = validateEndpoint(endpoint, allowHttp);
  validateHeaders(headers);

  if (maxBufferSize < 1024) {
    throw new ConfigError("maxBufferSize must be at least 1024 bytes.");
  }

  return {
    allowHttp,
    headers,
    maxBufferSize,
    timeoutMs,
    url
  };
}

async function loadConfigFile(configPath) {
  if (!existsSync(configPath)) {
    throw new ConfigError(`Config file does not exist: ${configPath}`);
  }

  try {
    const config = await readJsonFile(configPath);
    if (!config || typeof config !== "object" || Array.isArray(config)) {
      throw new ConfigError(`Config file must contain a JSON object: ${configPath}`);
    }
    return config;
  } catch (error) {
    if (error instanceof ConfigError) {
      throw error;
    }
    throw new ConfigError(`Unable to read config file ${configPath}: ${error.message}`);
  }
}

function parseOptionalBoolean(value) {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value !== "string") {
    throw new ConfigError(`Expected a boolean-compatible value, got ${typeof value}.`);
  }

  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  throw new ConfigError(`Invalid boolean value: ${value}`);
}

function parseOptionalInteger(value, name) {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }

  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) {
    throw new ConfigError(`${name} must be a positive integer.`);
  }
  return number;
}

function parseJsonHeaders(raw, sourceName) {
  if (!raw) {
    return {};
  }

  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new ConfigError(`${sourceName} must be a JSON object.`);
    }
    return normalizeHeaders(parsed);
  } catch (error) {
    if (error instanceof ConfigError) {
      throw error;
    }
    throw new ConfigError(`${sourceName} is not valid JSON: ${error.message}`);
  }
}

function parseCliHeaders(headerArgs) {
  const headers = {};

  for (const header of headerArgs) {
    const separator = header.indexOf(":");
    if (separator <= 0) {
      throw new ConfigError(`Invalid --header value "${header}". Expected "name:value".`);
    }

    const name = header.slice(0, separator).trim().toLowerCase();
    const value = header.slice(separator + 1).trim();
    headers[name] = value;
  }

  return headers;
}

function normalizeHeaders(headers) {
  const normalized = {};

  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || value === null) {
      continue;
    }
    normalized[name.toLowerCase()] = String(value);
  }

  return normalized;
}

function validateHeaders(headers) {
  const headerNamePattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

  for (const name of Object.keys(headers)) {
    if (!headerNamePattern.test(name)) {
      throw new ConfigError(`Invalid HTTP header name: ${name}`);
    }
    if (RESERVED_HEADERS.has(name)) {
      throw new ConfigError(`Header "${name}" is controlled by the MCP transport and cannot be overridden.`);
    }
  }
}

function validateEndpoint(endpoint, allowHttp) {
  if (!endpoint) {
    throw new ConfigError("Remote MCP endpoint is required. Set MCP_BRIDGE_URL or pass --url.");
  }

  let url;
  try {
    url = new URL(endpoint);
  } catch {
    throw new ConfigError(`Remote MCP endpoint is not a valid URL: ${endpoint}`);
  }

  if (url.username || url.password) {
    throw new ConfigError("Do not put credentials in the endpoint URL. Use bearerToken, apiKey, or headers.");
  }

  if (url.protocol !== "https:" && !(allowHttp && url.protocol === "http:")) {
    throw new ConfigError("Remote MCP endpoint must use HTTPS. Use --allow-http only for local development.");
  }

  return url;
}

function makeTimeoutFetch(timeoutMs) {
  if (!timeoutMs) {
    return undefined;
  }

  return async (url, init = {}) => {
    const timeoutController = new AbortController();
    const timeout = setTimeout(() => {
      timeoutController.abort(new Error(`Request timed out after ${timeoutMs}ms.`));
    }, timeoutMs);
    const signals = [timeoutController.signal, init.signal].filter(Boolean);
    const signal = typeof AbortSignal.any === "function"
      ? AbortSignal.any(signals)
      : combineAbortSignals(signals);

    try {
      return await fetch(url, {
        ...init,
        signal
      });
    } finally {
      clearTimeout(timeout);
    }
  };
}

function combineAbortSignals(signals) {
  const controller = new AbortController();

  for (const signal of signals) {
    if (signal.aborted) {
      controller.abort(signal.reason);
      break;
    }
    signal.addEventListener("abort", () => controller.abort(signal.reason), { once: true });
  }

  return controller.signal;
}

async function startBridge(config) {
  const [
    { StdioServerTransport },
    { StreamableHTTPClientTransport }
  ] = await Promise.all([
    import("@modelcontextprotocol/sdk/server/stdio.js"),
    import("@modelcontextprotocol/sdk/client/streamableHttp.js")
  ]);

  stdioTransport = new StdioServerTransport(process.stdin, process.stdout, {
    maxBufferSize: config.maxBufferSize
  });
  remoteTransport = new StreamableHTTPClientTransport(config.url, {
    fetch: makeTimeoutFetch(config.timeoutMs),
    requestInit: {
      headers: config.headers
    }
  });

  stdioTransport.onmessage = async (message) => {
    await forwardMessage("stdio->http", remoteTransport, message);
  };
  remoteTransport.onmessage = async (message) => {
    captureProtocolVersion(remoteTransport, message);
    await forwardMessage("http->stdio", stdioTransport, message);
  };

  stdioTransport.onerror = (error) => log("error", "stdio transport error", { message: error.message });
  remoteTransport.onerror = (error) => log("error", "remote transport error", { message: error.message });
  stdioTransport.onclose = () => requestShutdown(0, "stdio closed");
  remoteTransport.onclose = () => requestShutdown(0, "remote transport closed");

  installShutdownHooks();

  await remoteTransport.start();
  await stdioTransport.start();

  log("info", "bridge started", {
    allowHttp: config.allowHttp,
    endpoint: safeUrlForLog(config.url),
    timeoutMs: config.timeoutMs ?? "disabled"
  });
}

async function forwardMessage(direction, targetTransport, message) {
  if (closing) {
    return;
  }

  try {
    await targetTransport.send(message);
  } catch (error) {
    log("error", `failed to forward ${direction}`, { message: error.message });
    await requestShutdown(1, `forwarding failed: ${direction}`);
  }
}

function captureProtocolVersion(transport, message) {
  const protocolVersion = message?.result?.protocolVersion;
  if (typeof protocolVersion === "string" && typeof transport.setProtocolVersion === "function") {
    transport.setProtocolVersion(protocolVersion);
  }
}

function safeUrlForLog(url) {
  const copy = new URL(url.toString());
  copy.search = copy.search ? "?[redacted]" : "";
  return copy.toString();
}

function installShutdownHooks() {
  const signals = process.platform === "win32"
    ? ["SIGINT", "SIGTERM", "SIGBREAK"]
    : ["SIGINT", "SIGTERM", "SIGHUP"];

  for (const signal of signals) {
    process.on(signal, () => {
      requestShutdown(0, signal).finally(() => process.exit(0));
    });
  }

  process.stdin.on("end", () => {
    requestShutdown(0, "stdin ended").catch(() => undefined);
  });

  process.on("uncaughtException", (error) => {
    log("error", "uncaught exception", { message: error.message, stack: error.stack });
    requestShutdown(1, "uncaught exception").finally(() => process.exit(1));
  });

  process.on("unhandledRejection", (reason) => {
    const error = reason instanceof Error ? reason : new Error(String(reason));
    log("error", "unhandled rejection", { message: error.message, stack: error.stack });
    requestShutdown(1, "unhandled rejection").finally(() => process.exit(1));
  });
}

async function requestShutdown(exitCode, reason) {
  if (closing) {
    return;
  }

  closing = true;
  log("info", "shutting down", { reason });

  await Promise.race([
    closeTransports(),
    delay(2500)
  ]);

  process.exitCode = exitCode;
}

async function closeTransports() {
  if (remoteTransport?.terminateSession) {
    await Promise.race([
      remoteTransport.terminateSession(),
      delay(1500)
    ]).catch((error) => {
      log("error", "remote session termination failed", { message: error.message });
    });
  }

  const closeOperations = [];

  if (remoteTransport) {
    closeOperations.push(remoteTransport.close());
  }
  if (stdioTransport) {
    closeOperations.push(stdioTransport.close());
  }

  await Promise.allSettled(closeOperations);
}

function delay(milliseconds) {
  return new Promise((resolveDelay) => {
    const timeout = setTimeout(resolveDelay, milliseconds);
    timeout.unref?.();
  });
}

async function main() {
  try {
    const args = parseArgs(process.argv.slice(2));

    if (args.help) {
      process.stdout.write(HELP);
      return;
    }

    if (args.version) {
      process.stdout.write(`${await readPackageVersion()}\n`);
      return;
    }

    const config = await buildConfig(args, process.env);
    await startBridge(config);
  } catch (error) {
    const message = error instanceof ConfigError ? error.message : `${error.name}: ${error.message}`;
    log("error", message);
    process.exitCode = 1;
  }
}

await main();
