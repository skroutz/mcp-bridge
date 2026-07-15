#!/usr/bin/env node

import { existsSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
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
const STALE_CLIENT_OAUTH_ERRORS = new Set(["invalid_client", "unauthorized_client"]);

let stdioTransport;
let remoteTransport;
let oauthProvider;
let UnauthorizedErrorCtor;
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
          headers,
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

class BridgeOAuthProvider {
  constructor(config) {
    this.config = config;
    this.sessionKey = createOAuthSessionKey(config.url, config.oauth.redirectUrl);
    this.sessionFingerprint = createOAuthSessionFingerprint(config.url, config.oauth.redirectUrl, config.oauth.scope);
    this.pendingCallback = undefined;
    this.currentState = undefined;
    this.codeVerifierValue = undefined;
    this.staleClientRecoveryUsed = false;
  }

  get redirectUrl() {
    return this.config.oauth.redirectUrl;
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
    this.currentState = randomBytes(24).toString("base64url");
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
    await this.updateSession({ clientInformation });
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
    await this.assertAuthorizationClientIsValid(authorizationUrl);

    if (!this.pendingCallback) {
      this.pendingCallback = await createOAuthCallbackWaiter({
        expectedPath: this.redirectUrl.pathname,
        expectedState: this.currentState,
        host: this.redirectUrl.hostname,
        port: Number(this.redirectUrl.port),
        timeoutMs: 10 * 60 * 1000
      });
    }

    log("info", this.config.oauth.openBrowser
      ? "OAuth authorization required; opening browser"
      : "OAuth authorization required; browser opening disabled", {
      oauthUrl: authorizationUrl.toString(),
      callback: this.redirectUrl.toString()
    });

    if (!this.config.oauth.openBrowser) {
      return;
    }

    await openBrowser(authorizationUrl).then((method) => {
      log("info", "OAuth browser launch command completed", { method });
    }).catch((error) => {
      log("error", "unable to open browser automatically", {
        oauthUrl: authorizationUrl.toString(),
        message: error.message
      });
      throw error;
    });
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

    try {
      return await this.pendingCallback.codePromise;
    } finally {
      await this.pendingCallback.close();
      this.pendingCallback = undefined;
    }
  }

  async saveCodeVerifier(codeVerifier) {
    this.codeVerifierValue = codeVerifier;
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
    const session = await this.readSession();

    if (scope === "all" || scope === "client") {
      delete session.clientInformation;
    }
    if (scope === "all" || scope === "tokens") {
      delete session.tokens;
    }
    if (scope === "all" || scope === "verifier") {
      this.codeVerifierValue = undefined;
    }
    if (scope === "all" || scope === "discovery") {
      delete session.discoveryState;
    }

    await this.writeSession(session);
  }

  async recoverStaleClient(reason) {
    if (this.staleClientRecoveryUsed) {
      return false;
    }

    this.staleClientRecoveryUsed = true;
    await this.invalidateCredentials("all");
    log("info", "cleared stale OAuth client cache; restarting authorization", { reason });
    return true;
  }

  async clearSession() {
    await this.invalidateCredentials("all");
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
    await this.writeSession({
      ...await this.readSession(),
      ...patch
    });
  }

  async writeSession(session) {
    const store = await this.readStore();
    store.sessions[this.sessionKey] = {
      ...session,
      fingerprint: this.sessionFingerprint,
      version: OAUTH_CACHE_SESSION_VERSION
    };
    store.updatedAt = new Date().toISOString();
    await writeJsonPrivate(this.config.oauth.storagePath, store);
  }
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

async function createOAuthCallbackWaiter({ expectedPath, expectedState, host, port, timeoutMs }) {
  let server;
  let settled = false;
  let readyResolve;
  let readyReject;
  let codeResolve;
  let codeReject;
  const readyPromise = new Promise((resolveReady, rejectReady) => {
    readyResolve = resolveReady;
    readyReject = rejectReady;
  });
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

    if (expectedState && state !== expectedState) {
      response.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      response.end("Invalid OAuth state.");
      finish(new Error("OAuth callback state did not match."));
      return;
    }

    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(oauthHtml("Authorization complete", "You can close this window and return to Claude Desktop."));
    finish(undefined, code);
  });

  server.on("error", readyReject);
  server.listen(port, host, readyResolve);
  await readyPromise;

  return {
    codePromise,
    port: server.address().port,
    close: () => new Promise((resolveClose) => {
      server.close(() => resolveClose());
    })
  };
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

function openBrowserLinuxCommands(target) {
  const commands = [];
  const browserEnv = process.env.BROWSER;

  if (browserEnv) {
    for (const entry of browserEnv.split(":")) {
      const command = entry.trim();
      if (!command) {
        continue;
      }
      commands.push(command.includes("%s")
        ? { command: "sh", args: ["-c", `${command} "$0"`, target], method: `browser-env:${command}` }
        : { command, args: [target], method: `browser-env:${command}` });
    }
  }

  for (const command of ["xdg-open", "gio", "gnome-open", "kde-open5", "kde-open", "wslview", "x-www-browser", "www-browser"]) {
    commands.push(command === "gio"
      ? { command: "gio", args: ["open", target], method: "gio-open" }
      : { command, args: [target], method: command });
  }

  return commands;
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
    { StreamableHTTPClientTransport },
    { UnauthorizedError }
  ] = await Promise.all([
    import("@modelcontextprotocol/sdk/server/stdio.js"),
    import("@modelcontextprotocol/sdk/client/streamableHttp.js"),
    import("@modelcontextprotocol/sdk/client/auth.js")
  ]);
  UnauthorizedErrorCtor = UnauthorizedError;
  oauthProvider = config.oauth ? new BridgeOAuthProvider(config) : undefined;
  await clearOAuthSessionIfRequested(config, oauthProvider);

  stdioTransport = new StdioServerTransport(process.stdin, process.stdout, {
    maxBufferSize: config.maxBufferSize
  });
  remoteTransport = new StreamableHTTPClientTransport(config.url, {
    authProvider: oauthProvider,
    fetch: makeBridgeFetch(config),
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

  try {
    await targetTransport.send(message);
  } catch (error) {
    if (direction === "stdio->http" && oauthProvider && isStaleOAuthClientError(error, oauthProvider)) {
      await recoverStaleOAuthClient({
        config: oauthProvider.config,
        error,
        provider: oauthProvider,
        startAuthorization: beginOAuthAuthorization
      }).then(async (recovered) => {
        if (!recovered) {
          throw error;
        }
        await completeOAuthAndRetry(targetTransport, message);
      }).catch(async (authError) => {
        log("error", "OAuth stale-client recovery failed", errorMetadata(authError));
        await invalidateOAuthSession(oauthProvider, "OAuth stale-client recovery failed");
        await requestShutdown(1, "OAuth stale-client recovery failed");
      });
      return;
    }

    if (direction === "stdio->http" && oauthProvider && isUnauthorizedError(error)) {
      await completeOAuthAndRetry(targetTransport, message).catch(async (authError) => {
        log("error", "OAuth authorization failed", errorMetadata(authError));
        await invalidateOAuthSession(oauthProvider, "OAuth authorization failed");
        await requestShutdown(1, "OAuth authorization failed");
      });
      return;
    }

    log("error", `failed to forward ${direction}`, errorMetadata(error));
    await requestShutdown(1, `forwarding failed: ${direction}`);
  }
}

function isUnauthorizedError(error) {
  return Boolean(UnauthorizedErrorCtor && error instanceof UnauthorizedErrorCtor);
}

async function completeOAuthAndRetry(targetTransport, message) {
  await completeOAuthAuthorization({
    config: oauthProvider.config,
    provider: oauthProvider,
    finishAuthorization: async (authorizationCode) => {
      await targetTransport.finishAuth(authorizationCode);
    }
  });
  log("info", "OAuth authorization complete; retrying MCP request");
  await targetTransport.send(message);
}

async function completeOAuthAuthorization({ config, provider, finishAuthorization, startAuthorization = beginOAuthAuthorization }) {
  while (true) {
    log("info", "waiting for OAuth browser authorization");
    try {
      const authorizationCode = await provider.waitForAuthorizationCode();
      await finishAuthorization(authorizationCode);
      return;
    } catch (error) {
      if (await recoverStaleOAuthClient({ config, error, provider, startAuthorization })) {
        continue;
      }
      await invalidateOAuthSession(provider, "OAuth authorization failed");
      throw error;
    }
  }
}

async function recoverStaleOAuthClient({ config, error, provider, startAuthorization }) {
  if (!isStaleOAuthClientError(error, provider)) {
    return false;
  }

  const recovered = await provider.recoverStaleClient(error.oauthError ?? error.message);
  if (!recovered) {
    log("error", "OAuth stale-client recovery was already attempted; refusing to retry again", errorMetadata(error));
    return false;
  }

  await startAuthorization(provider, config);
  return true;
}

function isStaleOAuthClientError(error, provider) {
  if (error?.oauthError && STALE_CLIENT_OAUTH_ERRORS.has(error.oauthError)) {
    return true;
  }

  // The SDK clears an invalid client during token exchange, then reports this
  // follow-up error because the original authorization code belongs to the old
  // client. Treat it as the same bounded recovery case.
  return error instanceof Error
    && error.message === "Existing OAuth client information is required when exchanging an authorization code"
    && provider.staleClientRecoveryUsed === false;
}

async function beginOAuthAuthorization(provider, config) {
  const { auth } = await import("@modelcontextprotocol/sdk/client/auth.js");
  const result = await auth(provider, {
    serverUrl: config.url,
    fetchFn: makeBridgeFetch(config, 30000)
  });
  if (result !== "REDIRECT") {
    throw new Error(`Expected OAuth authorization redirect after clearing stale client, got ${result}.`);
  }
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
    { auth, UnauthorizedError },
    { Client },
    { StreamableHTTPClientTransport }
  ] = await Promise.all([
    import("@modelcontextprotocol/sdk/client/auth.js"),
    import("@modelcontextprotocol/sdk/client/index.js"),
    import("@modelcontextprotocol/sdk/client/streamableHttp.js")
  ]);

  UnauthorizedErrorCtor = UnauthorizedError;
  oauthProvider = new BridgeOAuthProvider(config);
  await clearOAuthSessionIfRequested(config, oauthProvider);
  const fetchFn = makeBridgeFetch(config, 30000);

  log("info", "starting OAuth login", {
    bridgeCaBundle: Boolean(config.caBundle),
    bridgeCaBundlePath: config.caBundle?.path,
    endpoint: safeUrlForLog(config.url),
    timeoutMs: config.timeoutMs ?? 30000
  });

  let result;
  try {
    result = await auth(oauthProvider, {
      serverUrl: config.url,
      fetchFn
    });
  } catch (error) {
    const recovered = await recoverStaleOAuthClient({
      config,
      error,
      provider: oauthProvider,
      startAuthorization: beginOAuthAuthorization
    });
    if (!recovered) {
      await invalidateOAuthSession(oauthProvider, "OAuth login setup failed");
      throw error;
    }
    result = "REDIRECT";
  }

  if (result === "REDIRECT") {
    await completeOAuthAuthorization({
      config,
      provider: oauthProvider,
      finishAuthorization: async (authorizationCode) => {
        await auth(oauthProvider, {
          serverUrl: config.url,
          authorizationCode,
          fetchFn
        });
      }
    });
  }

  await connectOAuthClient({
    Client,
    StreamableHTTPClientTransport,
    config,
    fetchFn,
    provider: oauthProvider
  });

  log("info", "OAuth login complete", {
    endpoint: safeUrlForLog(config.url),
    storagePath: config.oauth.storagePath
  });
}

async function connectOAuthClient({ Client, StreamableHTTPClientTransport, config, fetchFn, provider }) {
  const version = await readPackageVersion();
  const transport = new StreamableHTTPClientTransport(config.url, {
    authProvider: provider,
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
    await client.close();
  } catch (error) {
    if (isUnauthorizedError(error) || isStaleOAuthClientError(error, provider)) {
      if (isStaleOAuthClientError(error, provider)) {
        const recovered = await recoverStaleOAuthClient({
          config,
          error,
          provider,
          startAuthorization: beginOAuthAuthorization
        });
        if (!recovered) {
          await transport.close().catch(() => undefined);
          throw error;
        }
      }
      await completeOAuthAuthorization({
        config,
        provider,
        finishAuthorization: async (authorizationCode) => {
          await transport.finishAuth(authorizationCode);
        }
      });
      await transport.close().catch(() => undefined);
      log("info", "OAuth authorization complete; verifying cached credentials");
      return connectOAuthClient({ Client, StreamableHTTPClientTransport, config, fetchFn, provider });
    }
    await transport.close().catch(() => undefined);
    throw error;
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
  OAuthAuthorizationError,
  completeOAuthAuthorization,
  createOAuthCallbackWaiter
};
