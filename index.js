#!/usr/bin/env node

import { existsSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { mkdir, open, readFile, rename, stat, unlink, writeFile } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import { dirname, isAbsolute, join, resolve } from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { Readable } from "node:stream";
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
  --oauth                       Enable OAuth 2.1/DCR browser login for remote MCP auth.
  --oauth-login                 Run OAuth login only, cache credentials, then exit.
  --oauth-clear-cache           Clear the current OAuth session before continuing.
  --oauth-callback-port <port>  Loopback callback port. Default: 33418.
  --oauth-storage <path>        OAuth cache path. Defaults to user config directory.
  --oauth-scope <scope>         Optional OAuth scope override.
  --oauth-open-browser <bool>   Open system browser for OAuth. Default: true.
  --ca-bundle <path>            Optional PEM CA bundle used by the bridge HTTP client.
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
  MCP_BRIDGE_OAUTH
  MCP_BRIDGE_OAUTH_LOGIN
  MCP_BRIDGE_OAUTH_CLEAR_CACHE
  MCP_BRIDGE_OAUTH_CALLBACK_PORT
  MCP_BRIDGE_OAUTH_STORAGE
  MCP_BRIDGE_OAUTH_SCOPE
  MCP_BRIDGE_OAUTH_OPEN_BROWSER
  MCP_BRIDGE_CA_BUNDLE
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

class OAuthAuthorizationError extends Error {
  constructor(error, description = undefined) {
    super(description ? `OAuth authorization failed: ${error}: ${description}` : `OAuth authorization failed: ${error}`);
    this.name = "OAuthAuthorizationError";
    this.oauthError = error;
  }
}

const OAUTH_CACHE_SESSION_VERSION = 1;
const OAUTH_BROWSER_STABILIZATION_MS = 5_000;
const STALE_CLIENT_OAUTH_ERRORS = new Set(["invalid_client", "unauthorized_client"]);

let stdioTransport;
let remoteTransport;
let oauthProvider;
let oauthFlowCoordinator;
let initializationBarrier;
let closing = false;

function log(level, message, extra = undefined) {
  const suffix = extra ? ` ${JSON.stringify(extra, redactSecrets)}` : "";
  process.stderr.write(`[mcp-bridge] ${level}: ${message}${suffix}\n`);
}

function formatError(error) {
  if (!(error instanceof Error)) {
    return String(error);
  }

  const cause = error.cause instanceof Error ? `; cause: ${error.cause.message}` : "";
  return `${error.name}: ${error.message}${cause}`;
}

function errorMetadata(error) {
  if (!(error instanceof Error)) {
    return { message: String(error) };
  }

  const metadata = {
    message: error.message,
    name: error.name
  };

  if (error.code) {
    metadata.code = error.code;
  }
  if (error.errorCode || error.oauthError) {
    metadata.oauthError = error.errorCode ?? error.oauthError;
  }
  if (error.oauthGrantType) {
    metadata.grantType = error.oauthGrantType;
  }

  if (error.cause instanceof Error) {
    metadata.cause = error.cause.message;
    metadata.causeName = error.cause.name;
    if (error.cause.code) {
      metadata.causeCode = error.cause.code;
    }
  }

  return metadata;
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
      case "--oauth":
        parsed.oauth = true;
        break;
      case "--oauth-login":
        parsed.oauthLogin = true;
        parsed.oauth = true;
        break;
      case "--oauth-clear-cache":
        parsed.oauthClearCache = true;
        parsed.oauth = true;
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
      case "--oauth-callback-port":
        parsed.oauthCallbackPort = readRequiredValue(argv, index, arg);
        index += 1;
        break;
      case "--oauth-storage":
        parsed.oauthStoragePath = readRequiredValue(argv, index, arg);
        index += 1;
        break;
      case "--oauth-scope":
        parsed.oauthScope = readRequiredValue(argv, index, arg);
        index += 1;
        break;
      case "--oauth-open-browser":
        parsed.oauthOpenBrowser = readRequiredValue(argv, index, arg);
        index += 1;
        break;
      case "--ca-bundle":
        parsed.caBundlePath = readRequiredValue(argv, index, arg);
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
  const oauthLogin = parseOptionalBoolean(args.oauthLogin)
    ?? parseOptionalBoolean(env.MCP_BRIDGE_OAUTH_LOGIN)
    ?? parseOptionalBoolean(fileConfig.oauthLogin)
    ?? false;
  const oauthClearCache = parseOptionalBoolean(args.oauthClearCache)
    ?? parseOptionalBoolean(env.MCP_BRIDGE_OAUTH_CLEAR_CACHE)
    ?? parseOptionalBoolean(fileConfig.oauthClearCache)
    ?? false;
  const oauthEnabled = oauthLogin || oauthClearCache || (
    parseOptionalBoolean(args.oauth)
    ?? parseOptionalBoolean(env.MCP_BRIDGE_OAUTH)
    ?? parseOptionalBoolean(fileConfig.oauth)
    ?? false
  );
  const oauthCallbackPort = parseOptionalInteger(
    args.oauthCallbackPort ?? env.MCP_BRIDGE_OAUTH_CALLBACK_PORT ?? fileConfig.oauthCallbackPort,
    "oauthCallbackPort"
  ) ?? 33418;
  const oauthStoragePath = resolveConfigPath(
    args.oauthStoragePath ?? env.MCP_BRIDGE_OAUTH_STORAGE ?? fileConfig.oauthStoragePath ?? defaultOAuthStoragePath()
  );
  const oauthScope = args.oauthScope ?? env.MCP_BRIDGE_OAUTH_SCOPE ?? fileConfig.oauthScope;
  const oauthOpenBrowser = parseOptionalBoolean(
    args.oauthOpenBrowser ?? env.MCP_BRIDGE_OAUTH_OPEN_BROWSER ?? fileConfig.oauthOpenBrowser
  ) ?? true;
  const caBundlePath = resolveConfigPath(
    args.caBundlePath ?? env.MCP_BRIDGE_CA_BUNDLE ?? fileConfig.caBundle ?? fileConfig.caBundlePath
  );
  const caBundle = caBundlePath ? await readCaBundle(caBundlePath) : undefined;
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

  if (oauthCallbackPort < 1024 || oauthCallbackPort > 65535) {
    throw new ConfigError("oauthCallbackPort must be between 1024 and 65535.");
  }

  if (oauthEnabled && (bearerToken || apiKey || headers.authorization || headers["x-api-key"])) {
    throw new ConfigError("Use either OAuth browser login or static bearer/API-key auth, not both.");
  }

  return {
    allowHttp,
    caBundle,
    headers,
    maxBufferSize,
    oauth: oauthEnabled
      ? {
        callbackPort: oauthCallbackPort,
        browserLaunchDelayMs: oauthLogin ? 0 : OAUTH_BROWSER_STABILIZATION_MS,
        clearCache: oauthClearCache,
        loginOnly: oauthLogin,
        redirectUrl: new URL(`http://127.0.0.1:${oauthCallbackPort}/oauth/callback`),
        openBrowser: oauthOpenBrowser,
        scope: oauthScope,
        storagePath: oauthStoragePath
      }
      : undefined,
    timeoutMs,
    url
  };
}

function defaultOAuthStoragePath() {
  switch (platform()) {
    case "darwin":
      return join(homedir(), "Library", "Application Support", "mcp-bridge", "oauth-cache.json");
    case "win32":
      return join(process.env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "mcp-bridge", "oauth-cache.json");
    default:
      return join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "mcp-bridge", "oauth-cache.json");
  }
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

async function readCaBundle(caBundlePath) {
  if (!existsSync(caBundlePath)) {
    throw new ConfigError(`CA bundle file does not exist: ${caBundlePath}`);
  }

  try {
    const pem = await readFile(caBundlePath, "utf8");
    if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
      throw new ConfigError(`CA bundle does not look like a PEM certificate bundle: ${caBundlePath}`);
    }
    return {
      path: caBundlePath,
      pem
    };
  } catch (error) {
    if (error instanceof ConfigError) {
      throw error;
    }
    throw new ConfigError(`Unable to read CA bundle ${caBundlePath}: ${error.message}`);
  }
}

function makeBridgeFetch(config, defaultTimeoutMs = undefined) {
  const timeoutMs = config.timeoutMs ?? defaultTimeoutMs;
  const baseFetch = config.caBundle ? makeCaBundleFetch(config.caBundle.pem) : fetch;

  if (!timeoutMs && !config.caBundle) {
    return undefined;
  }

  return async (url, init = {}) => {
    if (!timeoutMs) {
      return await baseFetch(url, init);
    }

    const timeoutController = new AbortController();
    const timeout = setTimeout(() => {
      timeoutController.abort(new Error(`Request timed out after ${timeoutMs}ms.`));
    }, timeoutMs);
    const signals = [timeoutController.signal, init.signal].filter(Boolean);
    const signal = typeof AbortSignal.any === "function"
      ? AbortSignal.any(signals)
      : combineAbortSignals(signals);

    try {
      return await baseFetch(url, {
        ...init,
        signal
      });
    } finally {
      clearTimeout(timeout);
    }
  };
}

function makeCaBundleFetch(ca) {
  return async (url, init = {}) => fetchWithNodeHttp(url, init, { ca, redirectCount: 0 });
}

async function fetchWithNodeHttp(input, init = {}, { ca, redirectCount }) {
  const url = new URL(input instanceof Request ? input.url : input);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new TypeError(`Unsupported protocol for bridge fetch: ${url.protocol}`);
  }

  const method = init.method ?? (input instanceof Request ? input.method : "GET");
  const headers = headersToObject(init.headers ?? (input instanceof Request ? input.headers : undefined));
  const body = await normalizeFetchBody(init.body);
  const requestImpl = url.protocol === "https:" ? httpsRequest : httpRequest;

  return new Promise((resolveFetch, rejectFetch) => {
    if (init.signal?.aborted) {
      rejectFetch(init.signal.reason ?? new DOMException("The operation was aborted.", "AbortError"));
      return;
    }

    const request = requestImpl(url, {
      ca: url.protocol === "https:" ? ca : undefined,
      headers,
      method
    }, (response) => {
      const status = response.statusCode ?? 0;
      const location = response.headers.location;

      if (isRedirectStatus(status) && location && redirectCount < 5 && init.redirect !== "manual") {
        response.resume();
        const redirectUrl = new URL(location, url);
        const redirectInit = {
          ...init,
          body: status === 303 ? undefined : init.body,
          headers: sanitizeRedirectHeaders(headers, url, redirectUrl),
          method: status === 303 ? "GET" : method
        };
        fetchWithNodeHttp(redirectUrl, redirectInit, { ca, redirectCount: redirectCount + 1 })
          .then(resolveFetch, rejectFetch);
        return;
      }

      const responseBody = responseCanHaveBody(status) ? Readable.toWeb(response) : null;
      if (!responseBody) {
        response.resume();
      }
      resolveFetch(new Response(responseBody, {
        headers: responseHeaders(response.headers),
        status,
        statusText: response.statusMessage
      }));
    });

    request.once("error", rejectFetch);
    init.signal?.addEventListener("abort", () => {
      request.destroy(init.signal.reason ?? new DOMException("The operation was aborted.", "AbortError"));
    }, { once: true });

    if (body === undefined) {
      request.end();
      return;
    }

    if (body instanceof Readable) {
      body.once("error", rejectFetch);
      body.pipe(request);
      return;
    }

    request.end(body);
  });
}

function headersToObject(headersInit) {
  if (!headersInit) {
    return {};
  }

  const headers = new Headers(headersInit);
  return Object.fromEntries(headers.entries());
}

function responseHeaders(headers) {
  const normalized = new Headers();

  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        normalized.append(name, item);
      }
      continue;
    }
    normalized.set(name, String(value));
  }

  return normalized;
}

async function normalizeFetchBody(body) {
  if (body === undefined || body === null) {
    return undefined;
  }
  if (typeof body === "string" || Buffer.isBuffer(body) || body instanceof Readable) {
    return body;
  }
  if (body instanceof URLSearchParams) {
    return body.toString();
  }
  if (body instanceof ArrayBuffer) {
    return Buffer.from(body);
  }
  if (ArrayBuffer.isView(body)) {
    return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  }
  if (typeof Blob !== "undefined" && body instanceof Blob) {
    return Buffer.from(await body.arrayBuffer());
  }

  throw new TypeError(`Unsupported request body type for bridge fetch: ${body.constructor?.name ?? typeof body}`);
}

function isRedirectStatus(status) {
  return [301, 302, 303, 307, 308].includes(status);
}

function sanitizeRedirectHeaders(headers, fromUrl, toUrl) {
  if (isSameOrigin(fromUrl, toUrl)) {
    return headers;
  }

  const sanitized = { ...headers };
  delete sanitized.authorization;
  delete sanitized.cookie;
  delete sanitized["proxy-authorization"];
  delete sanitized["x-api-key"];
  return sanitized;
}

function isSameOrigin(a, b) {
  return a.protocol === b.protocol && a.hostname === b.hostname && a.port === b.port;
}

function responseCanHaveBody(status) {
  return ![204, 205, 304].includes(status);
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

class OAuthFlowCoordinator {
  constructor(provider, { fetchFn, authFetchFn } = {}) {
    this.provider = provider;
    this.config = provider.config;
    this.resourceFetch = fetchFn ?? makeBridgeFetch(this.config) ?? fetch;
    this.authorizationFetch = authFetchFn ?? fetchFn ?? makeBridgeFetch(this.config, 30_000) ?? fetch;
    this.authorizationTail = Promise.resolve();
    this.abortController = new AbortController();
    this.fetch = this.fetch.bind(this);
  }

  // All SDK transport requests, including SSE reconnects, use this fetch. OAuth
  // itself still runs through the SDK, but never outside our authorization lock.
  async fetch(url, init = {}) {
    const { extractWWWAuthenticateParams } = await import("@modelcontextprotocol/sdk/client/auth.js");
    const attemptedChallenges = new Set();
    while (true) {
      init.signal?.throwIfAborted();
      const previousTokens = await this.provider.tokens();
      const headers = new Headers(init.headers);
      if (previousTokens?.access_token) {
        headers.set("authorization", `Bearer ${previousTokens.access_token}`);
      } else {
        headers.delete("authorization");
      }
      const response = await this.resourceFetch(url, { ...init, headers });
      // Session termination must not open a browser or start a refresh.
      if (this.abortController.signal.aborted || init.method?.toUpperCase() === "DELETE") {
        return response;
      }
      const challenge = extractWWWAuthenticateParams(response);
      const upscope = response.status === 403 && challenge.error === "insufficient_scope";
      if (response.status !== 401 && !upscope) {
        return response;
      }

      // At most one 401 recovery and one insufficient-scope recovery per HTTP
      // request. Return subsequent errors to the SDK without an auth provider.
      if (attemptedChallenges.has(response.status)) {
        return response;
      }
      attemptedChallenges.add(response.status);
      await response.body?.cancel();
      await this.authorize({
        previousTokens,
        resourceMetadataUrl: challenge.resourceMetadataUrl,
        scope: challenge.scope,
        requiredScope: upscope ? challenge.scope : undefined
      });
    }
  }

  async fetchAuthorization(url, init = {}) {
    const headers = new Headers(this.config.headers);
    new Headers(init.headers).forEach((value, key) => headers.set(key, value));
    const response = await this.authorizationFetch(url, { ...init, headers });
    if (response.status === 400 && init.method === "POST"
      && init.body instanceof URLSearchParams && init.body.get("grant_type") === "refresh_token") {
      const { parseErrorResponse } = await import("@modelcontextprotocol/sdk/client/auth.js");
      const error = await parseErrorResponse(response.clone());
      if (error.errorCode === "invalid_request") {
        await response.body?.cancel();
        // Keep the SDK OAuthError type so its refresh handler propagates this
        // failure. Only this grant-specific error is eligible for our reset.
        error.oauthGrantType = "refresh_token";
        throw error;
      }
    }
    return response;
  }

  async authorize(options = {}) {
    // Queue authorization attempts, not tool calls or response streams. Each
    // waiter rechecks the cache under the process lock before using a refresh token.
    let release;
    const previous = this.authorizationTail;
    this.authorizationTail = new Promise((resolveRelease) => {
      release = resolveRelease;
    });
    await previous;
    try {
      this.abortController.signal.throwIfAborted();
      const owner = await this.provider.prepareAuthorization({
        ...options,
        signal: this.abortController.signal
      });
      if (!owner) {
        return;
      }
      this.abortController.signal.throwIfAborted();
      await this.runAuthorization(options);
    } finally {
      try {
        await this.provider.releaseAuthorizationOwnership();
      } finally {
        release();
      }
    }
  }

  async runAuthorization(options) {
    const { auth } = await import("@modelcontextprotocol/sdk/client/auth.js");
    const authenticate = (authorizationCode) => auth(this.provider, {
      serverUrl: this.config.url,
      resourceMetadataUrl: options.resourceMetadataUrl,
      scope: options.scope,
      authorizationCode,
      fetchFn: this.fetchAuthorization.bind(this)
    });
    const startAuthorization = async () => {
      await this.provider.prepareAuthorization();
      const result = await authenticate();
      if (result !== "REDIRECT") {
        throw new Error(`Expected OAuth authorization redirect after clearing stale credentials, got ${result}.`);
      }
    };
    let result;
    try {
      result = await authenticate();
    } catch (error) {
      if (!await recoverStaleOAuthClient({
        config: this.config, provider: this.provider, error, startAuthorization
      })) {
        throw error;
      }
      result = "REDIRECT";
    }
    if (result === "REDIRECT") {
      await completeOAuthAuthorization({
        config: this.config,
        provider: this.provider,
        startAuthorization,
        finishAuthorization: authenticate
      });
    }
  }

  async close() {
    this.abortController.abort(new Error("OAuth authorization was cancelled."));
    this.provider.authorizationClosed = true;
    await this.provider.resetAuthorizationFlow();
    // A refresh already in flight retains its lock until saveTokens completes.
    await this.authorizationTail;
  }
}

class McpInitializationBarrier {
  constructor() {
    this.initializationStarted = false;
    this.initialized = false;
    this.initialization = deferredPromise();
    // A failed initialization is also returned to its caller. This handler
    // prevents a second unhandled rejection when no later MCP message waits.
    this.initialization.promise.catch(() => undefined);
  }

  async forward(message, operation) {
    if (this.initialized) {
      return await operation();
    }

    if (isInitializeMessage(message) && !this.initializationStarted) {
      this.initializationStarted = true;
      try {
        const result = await operation();
        this.initialized = true;
        this.initialization.resolve();
        return result;
      } catch (error) {
        this.initialization.reject(error);
        throw error;
      }
    }

    await this.initialization.promise;
    return await operation();
  }
}

function isInitializeMessage(message) {
  const messages = Array.isArray(message) ? message : [message];
  return messages.some((item) => item?.method === "initialize" && item?.id !== undefined);
}

function deferredPromise() {
  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return { promise, reject: rejectPromise, resolve: resolvePromise };
}

class BridgeOAuthProvider {
  constructor(config) {
    this.config = config;
    this.configuredRedirectUrl = new URL(config.oauth.redirectUrl);
    this.sessionKey = createOAuthSessionKey(config.url, this.configuredRedirectUrl);
    this.sessionFingerprint = createOAuthSessionFingerprint(config.url, this.configuredRedirectUrl, config.oauth.scope);
    this.authorizationLockPath = `${config.oauth.storagePath}.${this.sessionKey}.authorization.lock`;
    this.authorizationLock = undefined;
    this.pendingCallback = undefined;
    this.currentState = undefined;
    this.codeVerifierValue = undefined;
    this.authorizationRedirectPromise = undefined;
    this.authorizationFlowGeneration = 0;
    this.staleClientRecoveryUsed = false;
    this.authorizationClosed = false;
  }

  get redirectUrl() {
    return this.config.oauth.redirectUrl;
  }

  async prepareAuthorization(options = {}) {
    options.signal?.throwIfAborted();
    if (this.authorizationClosed) {
      throw new Error("OAuth authorization was cancelled.");
    }
    if (this.authorizationLock) {
      await this.prepareAuthorizationCallback();
      return true;
    }

    const startingTokenFingerprint = tokenFingerprint(Object.hasOwn(options, "previousTokens")
      ? options.previousTokens : await this.tokens());
    let loggedWaiting = false;
    while (true) {
      options.signal?.throwIfAborted();
      const lock = await tryAcquireProcessLock(this.authorizationLockPath);
      if (lock) {
        try {
          options.signal?.throwIfAborted();
          const currentTokens = await this.tokens();
          if (currentTokens?.access_token && tokenFingerprint(currentTokens) !== startingTokenFingerprint
            && hasOAuthScope(currentTokens, options.requiredScope)) {
            await lock.release();
            return false;
          }
          this.authorizationLock = lock;
          await this.prepareAuthorizationCallback();
          log("info", "acquired OAuth authorization ownership", {
            callback: this.redirectUrl.toString()
          });
          return true;
        } catch (error) {
          this.authorizationLock = undefined;
          try {
            await this.resetAuthorizationFlow();
          } finally {
            await lock.release();
          }
          throw error;
        }
      }

      if (!loggedWaiting) {
        loggedWaiting = true;
        log("info", "another bridge process owns OAuth authorization; waiting for cached credentials");
      }
      await delay(200);
    }
  }

  async prepareAuthorizationCallback() {
    if (this.authorizationClosed) {
      throw new Error("OAuth authorization was cancelled.");
    }
    if (this.pendingCallback) {
      return;
    }

    const session = await this.readSession();
    const configuredPort = validCallbackPort(this.config.oauth.callbackPort)
      ? this.config.oauth.callbackPort
      : Number(this.configuredRedirectUrl.port);
    const preferredPort = validCallbackPort(session.callbackPort)
      ? session.callbackPort
      : configuredPort;
    const callbackWaiterFactory = this.config.oauth.callbackWaiterFactory ?? createOAuthCallbackWaiter;
    const expectedState = await this.state();
    const callback = await callbackWaiterFactory({
      expectedPath: this.configuredRedirectUrl.pathname,
      expectedState,
      host: this.configuredRedirectUrl.hostname,
      port: preferredPort,
      timeoutMs: 10 * 60 * 1000
    });
    callback.codePromise.catch(() => undefined);
    this.pendingCallback = callback;
    this.config.oauth.redirectUrl = new URL(this.configuredRedirectUrl);
    this.config.oauth.redirectUrl.port = String(callback.port);
    await this.mutateSession((currentSession) => {
      const previousCallbackPort = validCallbackPort(currentSession.callbackPort)
        ? currentSession.callbackPort
        : configuredPort;
      if (previousCallbackPort !== callback.port) {
        delete currentSession.clientInformation;
        delete currentSession.tokens;
      }
      currentSession.callbackPort = callback.port;
      return currentSession;
    });

    if (callback.port !== preferredPort) {
      log("info", "OAuth callback port was occupied; selected next available port", {
        preferredPort,
        selectedPort: callback.port
      });
    }
  }

  async releaseAuthorizationOwnership() {
    const lock = this.authorizationLock;
    this.authorizationLock = undefined;
    if (!lock) {
      return;
    }
    try {
      if (this.pendingCallback) {
        await this.resetAuthorizationFlow();
      }
    } finally {
      await lock.release();
    }
  }

  get clientMetadata() {
    const metadata = {
      client_name: "mcp-bridge",
      redirect_uris: [this.redirectUrl.toString()],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none"
    };

    if (this.config.oauth.scope) {
      metadata.scope = this.config.oauth.scope;
    }

    return metadata;
  }

  async state() {
    if (!this.currentState) {
      this.currentState = randomBytes(24).toString("base64url");
    }
    return this.currentState;
  }

  async clientInformation() {
    const session = await this.readSession();
    if (clientRegistrationExpired(session.clientInformation)) {
      await this.invalidateCredentials("all");
      log("info", "cleared expired OAuth client registration for current session");
      return undefined;
    }
    return session.clientInformation;
  }

  async saveClientInformation(clientInformation) {
    await this.mutateSession((session) => {
      if (session.clientInformation?.client_id !== clientInformation.client_id) {
        delete session.tokens;
      }
      return { ...session, clientInformation };
    });
  }

  async tokens() {
    const session = await this.readSession();
    if (clientRegistrationExpired(session.clientInformation)) {
      await this.invalidateCredentials("all");
      log("info", "cleared expired OAuth client registration for current session");
      return undefined;
    }
    return session.tokens;
  }

  async saveTokens(tokens) {
    await this.updateSession({ tokens });
  }

  async redirectToAuthorization(authorizationUrl) {
    const authorizationState = authorizationUrl.searchParams.get("state");
    if (this.currentState && authorizationState !== this.currentState) {
      log("info", "ignoring superseded OAuth authorization redirect");
      return;
    }

    const codeChallenge = authorizationUrl.searchParams.get("code_challenge");
    if (this.codeVerifierValue && codeChallenge && codeChallenge !== createPkceCodeChallenge(this.codeVerifierValue)) {
      log("info", "ignoring OAuth authorization redirect for a superseded PKCE verifier");
      return;
    }

    if (this.authorizationRedirectPromise) {
      log("info", "OAuth browser authorization is already active; reusing it");
      return await this.authorizationRedirectPromise;
    }

    const redirectPromise = this.startAuthorizationRedirect(authorizationUrl);
    this.authorizationRedirectPromise = redirectPromise;

    try {
      await redirectPromise;
    } catch (error) {
      if (this.authorizationRedirectPromise === redirectPromise) {
        this.authorizationRedirectPromise = undefined;
      }
      throw error;
    }
  }

  async startAuthorizationRedirect(authorizationUrl) {
    const redirectStartedAt = Date.now();
    if (this.config.oauth.openBrowser) {
      await this.prepareAuthorizationCallback();
      if (!await this.waitForBrowserLaunchStability()) {
        return;
      }
    }

    await this.assertAuthorizationClientIsValid(authorizationUrl);
    await this.prepareAuthorizationCallback();

    log("info", this.config.oauth.openBrowser
      ? "OAuth authorization required; opening browser"
      : "OAuth authorization required; browser opening disabled", {
      oauthUrl: authorizationUrl.toString(),
      callback: this.redirectUrl.toString()
    });

    if (!this.config.oauth.openBrowser) {
      return;
    }

    const browserOpener = this.config.oauth.browserOpener ?? openBrowser;
    await browserOpener(authorizationUrl).then((method) => {
      log("info", "OAuth browser launch command completed", {
        durationMs: Date.now() - redirectStartedAt,
        method
      });
    }).catch((error) => {
      log("error", "unable to open browser automatically", {
        oauthUrl: authorizationUrl.toString(),
        message: error.message
      });
      throw error;
    });
  }

  async waitForBrowserLaunchStability() {
    const delayMs = this.config.oauth.browserLaunchDelayMs ?? 0;
    if (delayMs <= 0) {
      return true;
    }

    const generation = this.authorizationFlowGeneration;
    log("info", "delaying OAuth browser launch while bridge process stabilizes", { delayMs });
    const stabilizer = this.config.oauth.browserLaunchStabilizer ?? delay;
    await stabilizer(delayMs);
    if (generation !== this.authorizationFlowGeneration) {
      log("info", "OAuth browser launch cancelled before stabilization completed");
      return false;
    }
    return true;
  }

  async assertAuthorizationClientIsValid(authorizationUrl) {
    const fetchFn = makeBridgeFetch(this.config, 10_000) ?? fetch;
    let response;

    try {
      response = await fetchFn(authorizationUrl, { redirect: "manual" });
    } catch (error) {
      // The browser may have network access or session configuration that this
      // utility process lacks. Preflight is an enhancement, never a reason to
      // block a normal interactive OAuth attempt.
      log("info", "unable to preflight OAuth authorization endpoint; continuing in browser", errorMetadata(error));
      return;
    }

    if (response.status !== 400) {
      await response.body?.cancel();
      return;
    }

    const body = await response.text().catch(() => "");
    if (/\binvalid[ _-]?client\b/i.test(body)) {
      throw new OAuthAuthorizationError("invalid_client");
    }

    log("info", "OAuth authorization endpoint returned HTTP 400 without an invalid_client error; continuing in browser");
  }

  async waitForAuthorizationCode() {
    if (!this.pendingCallback) {
      throw new Error("OAuth authorization callback was not started.");
    }

    const pendingCallback = this.pendingCallback;
    try {
      return await pendingCallback.codePromise;
    } finally {
      await pendingCallback.close();
      if (this.pendingCallback === pendingCallback) {
        this.pendingCallback = undefined;
      }
    }
  }

  async saveCodeVerifier(codeVerifier) {
    if (!this.codeVerifierValue) {
      this.codeVerifierValue = codeVerifier;
    }
  }

  async codeVerifier() {
    if (!this.codeVerifierValue) {
      throw new Error("No OAuth PKCE code verifier is available.");
    }
    return this.codeVerifierValue;
  }

  async saveDiscoveryState(discoveryState) {
    await this.updateSession({ discoveryState });
  }

  async discoveryState() {
    return (await this.readSession()).discoveryState;
  }

  async invalidateCredentials(scope) {
    if (scope === "all" || scope === "verifier") {
      this.codeVerifierValue = undefined;
    }
    await this.mutateSession((session) => {
      if (scope === "all" || scope === "client") {
        delete session.clientInformation;
      }
      if (scope === "all" || scope === "tokens" || scope === "client") {
        delete session.tokens;
      }
      if (scope === "all" || scope === "discovery") {
        delete session.discoveryState;
      }
      return session;
    });
  }

  async recoverStaleClient(reason) {
    if (this.staleClientRecoveryUsed) {
      return false;
    }

    this.staleClientRecoveryUsed = true;
    await this.resetAuthorizationFlow();
    await this.invalidateCredentials("all");
    log("info", "cleared stale OAuth client cache; restarting authorization", { reason });
    return true;
  }

  async clearSession() {
    await this.invalidateCredentials("all");
  }

  async resetAuthorizationFlow() {
    this.authorizationFlowGeneration += 1;
    const pendingCallback = this.pendingCallback;
    this.pendingCallback = undefined;
    this.currentState = undefined;
    this.codeVerifierValue = undefined;
    this.authorizationRedirectPromise = undefined;
    pendingCallback?.cancel?.(new Error("OAuth authorization was cancelled."));
    await pendingCallback?.close();
  }

  async readStore() {
    try {
      const raw = await readFile(this.config.oauth.storagePath, "utf8");
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { sessions: {} };
      }
      return {
        ...parsed,
        sessions: parsed.sessions && typeof parsed.sessions === "object" && !Array.isArray(parsed.sessions)
          ? parsed.sessions
          : {}
      };
    } catch (error) {
      if (error.code === "ENOENT") {
        return { sessions: {} };
      }
      throw error;
    }
  }

  async readSession() {
    const store = await this.readStore();
    const session = store.sessions[this.sessionKey];
    if (!session || typeof session !== "object" || Array.isArray(session)) {
      return {};
    }
    if (session.version !== OAUTH_CACHE_SESSION_VERSION || session.fingerprint !== this.sessionFingerprint) {
      return {};
    }
    return session;
  }

  async updateSession(patch) {
    await this.mutateSession((session) => ({ ...session, ...patch }));
  }

  async mutateSession(mutation) {
    const cacheLock = await acquireProcessLock(`${this.config.oauth.storagePath}.write.lock`);
    try {
      const store = await this.readStore();
      const storedSession = store.sessions[this.sessionKey];
      const currentSession = storedSession
        && typeof storedSession === "object"
        && !Array.isArray(storedSession)
        && storedSession.version === OAUTH_CACHE_SESSION_VERSION
        && storedSession.fingerprint === this.sessionFingerprint
        ? storedSession
        : {};
      const session = mutation({ ...currentSession });
      store.sessions[this.sessionKey] = {
        ...session,
        fingerprint: this.sessionFingerprint,
        version: OAUTH_CACHE_SESSION_VERSION
      };
      store.updatedAt = new Date().toISOString();
      await writeJsonPrivate(this.config.oauth.storagePath, store);
    } finally {
      await cacheLock.release();
    }
  }
}

function createPkceCodeChallenge(codeVerifier) {
  return createHash("sha256").update(codeVerifier).digest("base64url");
}

function tokenFingerprint(tokens) {
  return createHash("sha256").update(JSON.stringify(tokens ?? null)).digest("base64url");
}

function hasOAuthScope(tokens, requiredScope) {
  if (!requiredScope) {
    return true;
  }
  const granted = new Set((tokens.scope ?? "").split(/\s+/));
  return requiredScope.split(/\s+/).every((scope) => granted.has(scope));
}

function createOAuthSessionKey(endpointUrl, redirectUrl) {
  return createHash("sha256")
    .update(endpointUrl.toString())
    .update("\0")
    .update(redirectUrl.toString())
    .digest("base64url");
}

function createOAuthSessionFingerprint(endpointUrl, redirectUrl, scope) {
  return createHash("sha256")
    .update(JSON.stringify({
      endpointUrl: endpointUrl.toString(),
      redirectUrl: redirectUrl.toString(),
      scope: scope ?? "",
      version: OAUTH_CACHE_SESSION_VERSION
    }))
    .digest("base64url");
}

function clientRegistrationExpired(clientInformation) {
  if (!clientInformation || typeof clientInformation !== "object") {
    return false;
  }

  const expiresAt = Number(clientInformation.client_secret_expires_at);
  return Number.isFinite(expiresAt) && expiresAt > 0 && expiresAt <= Math.floor(Date.now() / 1000);
}

async function writeJsonPrivate(path, value) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tempPath = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await rename(tempPath, path);
}

function validCallbackPort(value) {
  return Number.isInteger(value) && value >= 1024 && value <= 65535;
}

async function acquireProcessLock(path) {
  while (true) {
    const lock = await tryAcquireProcessLock(path);
    if (lock) {
      return lock;
    }
    await delay(50);
  }
}

async function tryAcquireProcessLock(path) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  let handle;
  try {
    handle = await open(path, "wx", 0o600);
    await handle.writeFile(JSON.stringify({ createdAt: new Date().toISOString(), pid: process.pid }));
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (error.code !== "EEXIST") {
      throw error;
    }
    if (await removeStaleProcessLock(path)) {
      return await tryAcquireProcessLock(path);
    }
    return undefined;
  }

  let released = false;
  return {
    async release() {
      if (released) {
        return;
      }
      released = true;
      await handle.close();
      await unlink(path).catch((error) => {
        if (error.code !== "ENOENT") {
          throw error;
        }
      });
    }
  };
}

async function removeStaleProcessLock(path) {
  let owner;
  try {
    owner = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") {
      return true;
    }
    const lockStat = await stat(path).catch(() => undefined);
    if (!lockStat || Date.now() - lockStat.mtimeMs < 5_000) {
      return false;
    }
  }

  const pid = Number(owner?.pid);
  if (Number.isInteger(pid) && pid > 0 && processIsRunning(pid)) {
    return false;
  }

  const stalePath = `${path}.stale.${process.pid}.${randomBytes(6).toString("hex")}`;
  try {
    await rename(path, stalePath);
    await unlink(stalePath);
    return true;
  } catch (error) {
    return error.code === "ENOENT";
  }
}

function processIsRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code !== "ESRCH";
  }
}

async function createOAuthCallbackWaiter({ expectedPath, expectedState, host, port, timeoutMs }) {
  let server;
  let settled = false;
  let codeResolve;
  let codeReject;
  const codePromise = new Promise((resolveCode, rejectCode) => {
    codeResolve = resolveCode;
    codeReject = rejectCode;
  });

  const finish = (error, code) => {
    if (settled) {
      return;
    }
    settled = true;
    clearTimeout(timeout);
    if (error) {
      codeReject(error);
    } else {
      codeResolve(code);
    }
  };

  const timeout = setTimeout(() => {
    finish(new Error(`OAuth authorization timed out after ${timeoutMs}ms.`));
  }, timeoutMs);
  timeout.unref?.();

  server = createServer((request, response) => {
    const requestUrl = new URL(request.url ?? "/", `http://${host}:${port}`);
    const code = requestUrl.searchParams.get("code");
    const state = requestUrl.searchParams.get("state");
    const error = requestUrl.searchParams.get("error");

    if (requestUrl.pathname !== expectedPath) {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("Not found");
      return;
    }

    if (expectedState && state !== expectedState) {
      response.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      response.end("Invalid OAuth state.");
      return;
    }

    if (error) {
      response.writeHead(400, { "content-type": "text/html; charset=utf-8" });
      response.end(oauthHtml("Authorization failed", "Claude Desktop can be reopened after retrying the login."));
      finish(new OAuthAuthorizationError(error, requestUrl.searchParams.get("error_description") ?? undefined));
      return;
    }

    if (!code) {
      response.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      response.end("Missing authorization code.");
      finish(new Error("OAuth callback did not include an authorization code."));
      return;
    }

    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(oauthHtml("Authorization complete", "You can close this window and return to Claude Desktop."));
    finish(undefined, code);
  });

  try {
    await listenOnAvailableCallbackPort(server, host, port);
  } catch (error) {
    clearTimeout(timeout);
    codePromise.catch(() => undefined);
    await new Promise((resolveClose) => server.close(() => resolveClose())).catch(() => undefined);
    throw error;
  }
  server.on("error", (error) => finish(error));

  return {
    codePromise,
    port: server.address().port,
    cancel: (error = new Error("OAuth authorization was cancelled.")) => finish(error),
    close: () => new Promise((resolveClose) => {
      server.close(() => resolveClose());
    })
  };
}

async function listenOnAvailableCallbackPort(server, host, startingPort) {
  if (startingPort === 0) {
    await listenOnce(server, host, 0);
    return;
  }

  for (let port = startingPort; port <= 65535; port += 1) {
    try {
      await listenOnce(server, host, port);
      return;
    } catch (error) {
      if (error.code !== "EADDRINUSE") {
        throw error;
      }
    }
  }
  throw new Error(`No OAuth callback port is available at or above ${startingPort}.`);
}

function listenOnce(server, host, port) {
  return new Promise((resolveListen, rejectListen) => {
    const onError = (error) => {
      server.off("listening", onListening);
      rejectListen(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolveListen();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });
}

function oauthHtml(title, message) {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>${title}</title></head>
<body><h1>${title}</h1><p>${message}</p><script>setTimeout(() => window.close(), 1500);</script></body>
</html>`;
}

async function openBrowser(url) {
  const target = url.toString();
  const currentPlatform = platform();

  if (currentPlatform === "darwin") {
    await spawnAndWait("open", [target]);
    return "open";
  }

  if (currentPlatform === "win32") {
    return await openBrowserWindows(target);
  }

  return await openBrowserLinux(target);
}

// Not exhaustive - an unlisted/renamed shell via a standalone -c is still safe via findScriptArgIndex's name-agnostic search, but bundled flags (-ic) need a listed name.
const SHELL_INTERPRETER_NAMES = new Set(["sh", "bash", "dash", "zsh", "ash", "ksh", "fish", "csh", "tcsh", "mksh", "posh", "yash"]);

// awk/gawk/mawk/nawk are deliberately excluded: they're handled only via AWK_INTERPRETER_PATTERN below (a bare positional program, not a -c flag).
const NON_SHELL_INTERPRETER_PATTERN = /^(python|perl|ruby|node|nodejs|php|lua|tclsh|wish)[0-9.]*$/;

// perl/ruby/node/lua's eval flag is -e (not -c), php's is -r; gated on the interpreter name so this never misreads something unrelated, like bash's own -e.
const NON_SHELL_EVAL_FLAGS = [
  { flag: "-e", pattern: /^(perl|ruby|node|nodejs|lua)[0-9.]*$/ },
  { flag: "-r", pattern: /^php[0-9.]*$/ }
];

// awk's program is a bare positional arg with no flag to key off, so it's treated like a bundled-flag shell below: never substitute into any of its args.
const AWK_INTERPRETER_PATTERN = /^(awk|gawk|mawk|nawk)[0-9.]*$/;

function openBrowserLinuxCommands(target) {
  const commands = [];
  const browserEnv = process.env.BROWSER;

  if (browserEnv) {
    for (const entry of browserEnv.split(":")) {
      const trimmed = entry.trim();
      if (!trimmed) {
        continue;
      }
      try {
        commands.push(buildBrowserEnvCommand(trimmed, target));
      } catch (error) {
        log("info", "ignoring unusable BROWSER entry", { entry: trimmed, error: error.message });
      }
    }
  }

  for (const command of ["xdg-open", "gio", "gnome-open", "kde-open5", "kde-open", "wslview", "x-www-browser", "www-browser"]) {
    commands.push(command === "gio"
      ? { command: "gio", args: ["open", target], method: "gio-open" }
      : { command, args: [target], method: command });
  }

  return commands;
}

function buildBrowserEnvCommand(entry, target) {
  const [command, ...args] = tokenizeShellWords(entry);
  const tokens = [command, ...args];
  const scriptIndex = findScriptArgIndex(tokens);

  if (scriptIndex >= 0) {
    // Duplicate `-c` tokens mean indexOf may have picked the wrong one don't touch any arg then.
    // Also ambiguous if a different script flag (-e/-r) is present too, e.g. PHP's own -c <ini-path> alongside its real -r <script>.
    const isAmbiguous = countScriptIntroducingFlags(tokens) > 1;
    if (isAmbiguous) {
      return { args: [...args, target], command, method: `browser-env:${entry}` };
    }

    const nonShellInterpreter = findNonShellInterpreter(tokens, scriptIndex);
    if (nonShellInterpreter) {
      // A non-shell -c interpreter (python, perl, ruby, ...) doesn't use sh.Only substitute a trailing positional %s, never the script text.
      return buildProtectedScriptCommand(command, args, target, entry, scriptIndex, "-c script", nonShellInterpreter);
    }

    return buildShellWrapperCommand(command, args, scriptIndex, target, entry);
  }

  // Same protection as -c above, for perl/ruby/node/lua's -e or php's -r; the interpreter must precede the flag, so a later token can't misroute this.
  for (const { flag, pattern } of NON_SHELL_EVAL_FLAGS) {
    const evalScriptIndex = findScriptArgIndex(tokens, flag);
    if (evalScriptIndex < 0) {
      continue;
    }
    const interpreter = tokens.slice(0, evalScriptIndex).find((token) => pattern.test(String(token).split("/").pop()));
    if (!interpreter) {
      continue;
    }
    // Found the flag for a recognized interpreter, but not unambiguously: fail closed rather than falling through to unprotected substitution.
    if (countScriptIntroducingFlags(tokens) > 1) {
      return { args: [...args, target], command, method: `browser-env:${entry}` };
    }
    return buildProtectedScriptCommand(command, args, target, entry, evalScriptIndex, `${flag} script`, interpreter);
  }

  // No plain -c flag found, but a token still looks like a shell name (e.g.
  // bundled flags like `-ic`): don't splice %s into any arg, since it could
  // still end up parsed as script source once that shell reads its flags.
  // A non-shell interpreter only joins this bucket alongside a bundled-short-flag-shaped token too, or a plain `node script.mjs %s` would be needlessly refused.
  const hasUnprotectedInterpreter = tokens.some((token) => isShellInterpreterName(token) || isAwkInterpreterName(token))
    || (tokens.some((token) => isNonShellInterpreterName(token)) && tokens.some((token) => isBundledShortFlagCandidate(token)));
  if (hasUnprotectedInterpreter) {
    return { args: [...args, target], command, method: `browser-env:${entry}` };
  }

  return buildPositionalArgsCommand(command, args, target, entry, 0);
}

// Shared "leave this script argument alone, substitute only elsewhere" logic; throws if %s is only ever inside that protected argument.
function buildProtectedScriptCommand(command, args, target, entry, scriptIndex, descriptor, interpreterLabel = command) {
  const script = args[scriptIndex];
  const trailingHasPlaceholder = args.slice(scriptIndex + 1).some((arg) => arg.includes("%s"));
  if (script.includes("%s") && !trailingHasPlaceholder) {
    throw new ConfigError(`Cannot substitute %s inside a ${interpreterLabel} ${descriptor}; pass the URL as a trailing argument instead: ${entry}`);
  }
  return buildPositionalArgsCommand(command, args, target, entry, scriptIndex + 1);
}

// Rewrites %s inside an explicit `-c` shell script into $0 (quote-aware), and substitutes %s directly in trailing args.
function buildShellWrapperCommand(command, args, scriptIndex, target, entry) {
  const script = args[scriptIndex];
  const { script: rewrittenScript, hasPlaceholder: scriptHasPlaceholder } = substitutePlaceholderInScript(script);

  const before = [...args.slice(0, scriptIndex), rewrittenScript];
  const after = args.slice(scriptIndex + 1);
  const trailingHasPlaceholder = after.some((arg) => arg.includes("%s"));
  const substitutedAfter = trailingHasPlaceholder ? after.map((arg) => arg.replaceAll("%s", target)) : after;

  if (scriptHasPlaceholder) {
    return { args: [...before, target, ...substitutedAfter], command, method: `browser-env:${entry}` };
  }

  const finalArgs = trailingHasPlaceholder
    ? [...before, ...substitutedAfter]
    : [...before, ...substitutedAfter, target];
  return { args: finalArgs, command, method: `browser-env:${entry}` };
}

// Substitutes %s directly into args, and appends the target only when no placeholder was found there.
function buildPositionalArgsCommand(command, args, target, entry, from) {
  const before = args.slice(0, from);
  const after = args.slice(from);
  const hasPlaceholder = after.some((arg) => arg.includes("%s"));
  const substitutedAfter = hasPlaceholder ? after.map((arg) => arg.replaceAll("%s", target)) : after;
  const finalArgs = hasPlaceholder ? [...before, ...substitutedAfter] : [...before, ...substitutedAfter, target];
  return { args: finalArgs, command, method: `browser-env:${entry}` };
}

// Rewrites %s in a `-c` script's own text into a valid $0 reference, tracking the script's own quoting.
function substitutePlaceholderInScript(script) {
  let output = "";
  let hasPlaceholder = false;
  // A stack of nested contexts: $(...) starts a fresh, independent one, even inside an outer double-quoted string.
  const stack = [{ quote: null }];
  let index = 0;

  while (index < script.length) {
    const top = stack[stack.length - 1];
    const char = script[index];

    if (top.quote === "'") {
      if (char === "'") {
        top.quote = null;
        output += char;
        index += 1;
        continue;
      }
      if (script.startsWith("%s", index)) {
        output += `'"$0"'`;
        hasPlaceholder = true;
        index += 2;
        continue;
      }
      output += char;
      index += 1;
      continue;
    }

    if (top.quote === '"') {
      if (char === '"') {
        top.quote = null;
        output += char;
        index += 1;
        continue;
      }
      if (char === "\\" && '"\\$`'.includes(script[index + 1])) {
        output += char + script[index + 1];
        index += 2;
        continue;
      }
      if (script.startsWith("$(", index)) {
        stack.push({ quote: null });
        output += "$(";
        index += 2;
        continue;
      }
      // A surviving backslash here would escape the substituted $, turning "\%s" into the dead literal text "\$0" instead of expanding.
      if (script.startsWith("\\%s", index)) {
        output += "$0";
        hasPlaceholder = true;
        index += 3;
        continue;
      }
      if (script.startsWith("%s", index)) {
        output += "$0";
        hasPlaceholder = true;
        index += 2;
        continue;
      }
      output += char;
      index += 1;
      continue;
    }

    // top.quote === null: bare text, at the top level or inside a $(...); single quotes suppress $(...) so it's only recognized here and in double quotes.
    if (char === "'" || char === '"') {
      top.quote = char;
      output += char;
      index += 1;
      continue;
    }

    if (script.startsWith("$(", index)) {
      stack.push({ quote: null });
      output += "$(";
      index += 2;
      continue;
    }

    if (char === ")" && stack.length > 1) {
      stack.pop();
      output += char;
      index += 1;
      continue;
    }

    if (script.startsWith("\\%s", index)) {
      output += '"$0"';
      hasPlaceholder = true;
      index += 3;
      continue;
    }

    if (char === "\\" && index + 1 < script.length) {
      output += char + script[index + 1];
      index += 2;
      continue;
    }

    if (script.startsWith("%s", index)) {
      output += '"$0"';
      hasPlaceholder = true;
      index += 2;
      continue;
    }

    output += char;
    index += 1;
  }

  return { hasPlaceholder, script: output };
}

function isShellInterpreterName(token) {
  return typeof token === "string" && SHELL_INTERPRETER_NAMES.has(token.split("/").pop());
}

function isNonShellInterpreterName(token) {
  return typeof token === "string" && NON_SHELL_INTERPRETER_PATTERN.test(token.split("/").pop());
}

function isAwkInterpreterName(token) {
  return typeof token === "string" && AWK_INTERPRETER_PATTERN.test(token.split("/").pop());
}

// A short multi-letter flag group (-ic, -pe, ...) that could be bundling a real -c/-e/-r; excludes -c/-e/-r themselves and long --flags.
function isBundledShortFlagCandidate(token) {
  return typeof token === "string" && /^-[a-zA-Z]{2,4}$/.test(token);
}

// Returns the matched interpreter token (for use in error messages), or undefined.
function findNonShellInterpreter(tokens, scriptIndex) {
  return tokens.slice(0, scriptIndex).find((token) => isNonShellInterpreterName(token));
}

// -c always counts (any program could be an unlisted shell). -e/-r only
// count when a matching interpreter is actually present, so e.g. sh's own
// unrelated -e (errexit) alongside a real -c doesn't trip this.
function countScriptIntroducingFlags(tokens) {
  let count = tokens.filter((token) => token === "-c").length;
  for (const { flag, pattern } of NON_SHELL_EVAL_FLAGS) {
    if (tokens.some((token) => pattern.test(String(token).split("/").pop()))) {
      count += tokens.filter((token) => token === flag).length;
    }
  }
  return count;
}

// Args-relative index of a script flag's argument (default -c, also used for -e/-r), found anywhere in tokens; -1 if the flag isn't found with something after it.
function findScriptArgIndex(tokens, flag = "-c") {
  const flagIndex = tokens.indexOf(flag);
  if (flagIndex === -1 || typeof tokens[flagIndex + 1] !== "string") {
    return -1;
  }
  return flagIndex; // tokens[flagIndex + 1] (the script) is args[flagIndex].
}

function tokenizeShellWords(input) {
  const words = [];
  let current = "";
  let hasCurrent = false;
  let quote = null;

  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];

    if (quote === "'") {
      if (char === "'") {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (quote === '"') {
      if (char === '"') {
        quote = null;
      } else if (char === "\\" && '"\\$`'.includes(input[index + 1])) {
        current += input[index += 1];
      } else {
        current += char;
      }
      continue;
    }

    if (char === "'" || char === '"') {
      quote = char;
      hasCurrent = true;
      continue;
    }

    if (char === "\\" && index + 1 < input.length) {
      current += input[index += 1];
      hasCurrent = true;
      continue;
    }

    if (/\s/.test(char)) {
      if (hasCurrent) {
        words.push(current);
        current = "";
        hasCurrent = false;
      }
      continue;
    }

    current += char;
    hasCurrent = true;
  }

  if (quote) {
    throw new ConfigError(`Unterminated ${quote === "'" ? "single" : "double"}-quoted string in BROWSER entry: ${input}`);
  }

  if (hasCurrent) {
    words.push(current);
  }

  return words;
}

async function openBrowserLinux(target) {
  const env = resolveLinuxOpenerEnv();
  log("info", "Linux browser launch environment", {
    display: Boolean(env.DISPLAY),
    waylandDisplay: Boolean(env.WAYLAND_DISPLAY),
    dbusSessionBus: Boolean(env.DBUS_SESSION_BUS_ADDRESS),
    xdgRuntimeDir: Boolean(env.XDG_RUNTIME_DIR),
    path: Boolean(env.PATH)
  });

  const failures = [];

  for (const candidate of openBrowserLinuxCommands(target)) {
    try {
      await spawnAndWait(candidate.command, candidate.args, { env });
      return candidate.method;
    } catch (error) {
      failures.push(`${candidate.method}: ${error.message}`);
    }
  }

  throw new Error(`No Linux URL opener succeeded. Tried: ${failures.join("; ")}`);
}

function resolveLinuxOpenerEnv() {
  // Claude Desktop's MCP utility process can start the bridge with an almost
  // empty environment (only the vars from the manifest's mcp_config.env), so
  // desktop-session variables normally inherited from a login shell may be
  // missing here. Fill gaps from well-known Linux conventions without
  // overriding anything that is already present.
  const env = { ...process.env };

  if (!env.PATH) {
    env.PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
  }

  if (!env.HOME) {
    env.HOME = homedir();
  }

  if (!env.XDG_RUNTIME_DIR && typeof process.getuid === "function") {
    const candidate = `/run/user/${process.getuid()}`;
    if (existsSync(candidate)) {
      env.XDG_RUNTIME_DIR = candidate;
    }
  }

  if (!env.DISPLAY && existsSync("/tmp/.X11-unix/X0")) {
    env.DISPLAY = ":0";
  }

  if (!env.WAYLAND_DISPLAY && env.XDG_RUNTIME_DIR && existsSync(join(env.XDG_RUNTIME_DIR, "wayland-0"))) {
    env.WAYLAND_DISPLAY = "wayland-0";
  }

  if (!env.DBUS_SESSION_BUS_ADDRESS && env.XDG_RUNTIME_DIR && existsSync(join(env.XDG_RUNTIME_DIR, "bus"))) {
    env.DBUS_SESSION_BUS_ADDRESS = `unix:path=${join(env.XDG_RUNTIME_DIR, "bus")}`;
  }

  return env;
}

async function openBrowserWindows(target) {
  const commands = [
    {
      command: "rundll32.exe",
      args: ["url.dll,FileProtocolHandler", target],
      method: "rundll32-url"
    },
    {
      command: "explorer.exe",
      args: [target],
      method: "explorer-url"
    },
    {
      command: "powershell.exe",
      args: [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "Start-Process -FilePath $args[0]",
        target
      ],
      method: "powershell-start-process"
    }
  ];

  const failures = [];

  for (const candidate of commands) {
    try {
      await spawnAndWait(candidate.command, candidate.args);
      return candidate.method;
    } catch (error) {
      failures.push(`${candidate.method}: ${error.message}`);
    }
  }

  throw new Error(failures.join("; "));
}

function spawnAndWait(command, args, { env, waitForExitMs = 4000 } = {}) {
  return new Promise((resolveSpawn, rejectSpawn) => {
    const child = spawn(command, args, {
      detached: true,
      env: env ?? process.env,
      stdio: ["ignore", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";
    let settled = false;

    const settle = (result, error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(graceTimer);
      child.unref();
      if (error) {
        rejectSpawn(error);
      } else {
        resolveSpawn(result);
      }
    };

    child.stdout?.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr?.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });

    child.once("error", (error) => settle(undefined, error));
    child.once("exit", (code, signal) => {
      if (code === 0) {
        settle({ code });
        return;
      }
      const detail = stderr.trim() || stdout.trim() || "no output";
      settle(undefined, new Error(`exited with code ${code ?? "null"}${signal ? ` (signal ${signal})` : ""}: ${detail}`));
    });

    // Some openers exec into a long-lived browser process instead of exiting
    // quickly. Treat "still running after a grace period" as success rather
    // than waiting indefinitely.
    const graceTimer = setTimeout(() => {
      settle({ stillRunning: true });
    }, waitForExitMs);
    graceTimer.unref?.();
  });
}

async function startBridge(config) {
  const [
    { StdioServerTransport },
    { StreamableHTTPClientTransport }
  ] = await Promise.all([
    import("@modelcontextprotocol/sdk/server/stdio.js"),
    import("@modelcontextprotocol/sdk/client/streamableHttp.js")
  ]);
  oauthProvider = config.oauth ? new BridgeOAuthProvider(config) : undefined;
  oauthFlowCoordinator = oauthProvider ? new OAuthFlowCoordinator(oauthProvider) : undefined;
  initializationBarrier = new McpInitializationBarrier();
  await clearOAuthSessionIfRequested(config, oauthProvider);

  stdioTransport = new StdioServerTransport(process.stdin, process.stdout, {
    maxBufferSize: config.maxBufferSize
  });
  remoteTransport = new StreamableHTTPClientTransport(config.url, {
    fetch: oauthFlowCoordinator?.fetch ?? makeBridgeFetch(config),
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

  stdioTransport.onerror = (error) => log("error", "stdio transport error", errorMetadata(error));
  remoteTransport.onerror = (error) => log("error", "remote transport error", errorMetadata(error));
  stdioTransport.onclose = () => requestShutdown(0, "stdio closed");
  remoteTransport.onclose = () => requestShutdown(0, "remote transport closed");

  installShutdownHooks();

  await remoteTransport.start();
  await stdioTransport.start();

  log("info", "bridge started", {
    allowHttp: config.allowHttp,
    endpoint: safeUrlForLog(config.url),
    oauth: Boolean(config.oauth),
    bridgeCaBundle: Boolean(config.caBundle),
    bridgeCaBundlePath: config.caBundle?.path,
    tlsExtraCaCerts: Boolean(process.env.NODE_EXTRA_CA_CERTS),
    tlsVerification: process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0" ? "disabled" : "default",
    timeoutMs: config.timeoutMs ?? "disabled"
  });
}

async function forwardMessage(direction, targetTransport, message) {
  if (closing) {
    return;
  }

  if (direction === "stdio->http") {
    await initializationBarrier.forward(message, async () => {
      await forwardMessageAttempt(direction, targetTransport, message);
    });
    return;
  }

  await forwardMessageAttempt(direction, targetTransport, message);
}

async function forwardMessageAttempt(direction, targetTransport, message) {
  if (closing) {
    return;
  }

  try {
    await targetTransport.send(message);
  } catch (error) {
    log("error", `failed to forward ${direction}`, errorMetadata(error));
    await requestShutdown(1, `forwarding failed: ${direction}`);
  }
}

async function completeOAuthAuthorization({ config, provider, finishAuthorization, startAuthorization }) {
  while (true) {
    log("info", "waiting for OAuth browser authorization");
    const callbackWaitStartedAt = Date.now();
    try {
      const authorizationCode = await provider.waitForAuthorizationCode();
      log("info", "OAuth callback received", {
        waitDurationMs: Date.now() - callbackWaitStartedAt
      });
      const tokenExchangeStartedAt = Date.now();
      await finishAuthorization(authorizationCode);
      log("info", "OAuth token exchange completed", {
        durationMs: Date.now() - tokenExchangeStartedAt
      });
      await provider.resetAuthorizationFlow?.();
      return;
    } catch (error) {
      if (await recoverStaleOAuthClient({ config, error, provider, startAuthorization })) {
        continue;
      }
      await provider.resetAuthorizationFlow?.();
      await invalidateOAuthSession(provider, "OAuth authorization failed");
      throw error;
    }
  }
}

async function recoverStaleOAuthClient({ config, error, provider, startAuthorization }) {
  if (!isStaleOAuthClientError(error, provider)) {
    return false;
  }

  const reason = error.oauthGrantType === "refresh_token"
    ? "refresh request rejected: invalid_request"
    : error.errorCode ?? error.oauthError ?? error.message;
  const recovered = await provider.recoverStaleClient(reason);
  if (!recovered) {
    log("error", "OAuth stale-client recovery was already attempted; refusing to retry again", errorMetadata(error));
    return false;
  }

  await startAuthorization(provider, config);
  return true;
}

function isStaleOAuthClientError(error, provider) {
  if (STALE_CLIENT_OAUTH_ERRORS.has(error?.errorCode ?? error?.oauthError)) {
    return true;
  }
  if (error?.errorCode === "invalid_request" && error.oauthGrantType === "refresh_token") {
    return true;
  }

  // The SDK clears an invalid client during token exchange, then reports this
  // follow-up error because the original authorization code belongs to the old
  // client. Treat it as the same bounded recovery case.
  return error instanceof Error
    && error.message === "Existing OAuth client information is required when exchanging an authorization code"
    && provider.staleClientRecoveryUsed === false;
}

async function invalidateOAuthSession(provider, reason) {
  if (!provider?.invalidateCredentials) {
    return;
  }

  await provider.invalidateCredentials("all").then(() => {
    log("info", "cleared OAuth cache for current session", { reason });
  }).catch((error) => {
    log("error", "failed to clear OAuth cache for current session", errorMetadata(error));
  });
}

async function clearOAuthSessionIfRequested(config, provider) {
  if (!config.oauth?.clearCache || !provider) {
    return;
  }

  await provider.clearSession();
  log("info", "cleared OAuth cache for current session by request", {
    storagePath: config.oauth.storagePath
  });
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
  await oauthFlowCoordinator?.close().catch((error) => {
    log("error", "failed to close OAuth authorization", errorMetadata(error));
  });

  if (remoteTransport?.terminateSession) {
    await Promise.race([
      remoteTransport.terminateSession(),
      delay(1500)
    ]).catch((error) => {
      log("error", "remote session termination failed", errorMetadata(error));
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

async function runOAuthLogin(config) {
  const [
    { Client },
    { StreamableHTTPClientTransport }
  ] = await Promise.all([
    import("@modelcontextprotocol/sdk/client/index.js"),
    import("@modelcontextprotocol/sdk/client/streamableHttp.js")
  ]);

  oauthProvider = new BridgeOAuthProvider(config);
  await clearOAuthSessionIfRequested(config, oauthProvider);
  oauthFlowCoordinator = new OAuthFlowCoordinator(oauthProvider, {
    fetchFn: makeBridgeFetch(config, 30000)
  });

  log("info", "starting OAuth login", {
    bridgeCaBundle: Boolean(config.caBundle),
    bridgeCaBundlePath: config.caBundle?.path,
    endpoint: safeUrlForLog(config.url),
    timeoutMs: config.timeoutMs ?? 30000
  });

  try {
    await oauthFlowCoordinator.authorize();

    await connectOAuthClient({
      Client,
      StreamableHTTPClientTransport,
      config,
      fetchFn: oauthFlowCoordinator.fetch
    });
  } finally {
    await oauthFlowCoordinator.close();
  }

  log("info", "OAuth login complete", {
    endpoint: safeUrlForLog(config.url),
    storagePath: config.oauth.storagePath
  });
}

async function connectOAuthClient({ Client, StreamableHTTPClientTransport, config, fetchFn }) {
  const version = await readPackageVersion();
  const transport = new StreamableHTTPClientTransport(config.url, {
    fetch: fetchFn ?? makeBridgeFetch(config),
    requestInit: {
      headers: config.headers
    }
  });
  const client = new Client({
    name: "mcp-bridge-login",
    version
  }, {
    capabilities: {}
  });

  try {
    await client.connect(transport);
    await Promise.race([
      transport.terminateSession(),
      delay(1500)
    ]).catch(() => undefined);
  } finally {
    await client.close();
  }
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
    if (config.oauth?.loginOnly) {
      await runOAuthLogin(config);
      return;
    }

    await startBridge(config);
  } catch (error) {
    const message = error instanceof ConfigError ? error.message : formatError(error);
    log("error", message);
    process.exitCode = 1;
  }
}

if (process.env.MCP_BRIDGE_TEST_MODE !== "1") {
  await main();
}

export {
  BridgeOAuthProvider,
  McpInitializationBarrier,
  OAuthAuthorizationError,
  OAuthFlowCoordinator,
  buildBrowserEnvCommand,
  completeOAuthAuthorization,
  createOAuthCallbackWaiter,
  fetchWithNodeHttp,
  isSameOrigin,
  openBrowserLinuxCommands,
  sanitizeRedirectHeaders,
  tokenizeShellWords
};
