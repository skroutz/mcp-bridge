import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

process.env.MCP_BRIDGE_TEST_MODE = "1";
const { BridgeOAuthProvider, OAuthFlowCoordinator } = await import("../index.js");

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "mcp-bridge-refresh-"));
  const origin = "https://mcp.example.test";
  const metadata = {
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    registration_endpoint: `${origin}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"]
  };
  const resourceMetadata = { resource: `${origin}/mcp`, authorization_servers: [origin] };
  const state = {
    acceptedAccess: "old-access", refresh: "old-refresh", clientId: "old-client",
    refreshes: 0, exchanges: 0, registrations: 0, browsers: 0, callbacks: 0,
    unauthorized: 0, requests: [],
    expire() { this.acceptedAccess = undefined; }
  };
  let callback;
  const config = {
    url: new URL(resourceMetadata.resource),
    headers: {},
    oauth: {
      redirectUrl: new URL("http://127.0.0.1:33418/oauth/callback"),
      storagePath: join(directory, "cache.json"),
      openBrowser: true,
      callbackWaiterFactory: async ({ port, expectedState }) => {
        state.callbacks++;
        callback = deferred();
        callback.state = expectedState;
        return { port: port + (options.portDelta ?? 0), codePromise: callback.promise, cancel: callback.reject, close: async () => {} };
      },
      browserOpener: async (url) => {
        state.browsers++;
        assert.equal(url.searchParams.get("state"), callback.state);
        queueMicrotask(() => callback.resolve("new-code"));
        return "test-browser";
      }
    }
  };
  const fetchFn = async (input, init = {}) => {
    const url = new URL(input);
    if (url.pathname.includes("/.well-known/oauth-protected-resource")) return json(resourceMetadata);
    if (url.pathname.includes("/.well-known/")) return json(metadata);
    if (url.pathname === "/authorize") return new Response(null, { status: 302 });
    if (url.pathname === "/register") {
      state.registrations++;
      if (options.registrationReply) return options.registrationReply(state);
      state.clientId = `new-client-${state.registrations}`;
      return json({ ...JSON.parse(init.body), client_id: state.clientId }, 201);
    }
    if (url.pathname === "/token") {
      assert.equal(init.body.get("client_id"), state.clientId);
      const grant = init.body.get("grant_type");
      if (grant === "refresh_token") {
        state.refreshes++;
        assert.equal(init.body.get("refresh_token"), state.refresh);
        const custom = await options.refreshReply?.(state, init);
        if (custom) return custom;
      } else {
        assert.equal(grant, "authorization_code");
        state.exchanges++;
        const custom = await options.codeReply?.(state, init);
        if (custom) return custom;
      }
      state.acceptedAccess = `new-access-${state.refreshes}-${state.exchanges}`;
      state.refresh = `new-refresh-${state.refreshes}-${state.exchanges}`;
      return json({ access_token: state.acceptedAccess, refresh_token: state.refresh, token_type: "Bearer", scope: "tools.read tools.write" });
    }
    assert.equal(url.href, config.url.href);
    const access = new Headers(init.headers).get("authorization");
    state.requests.push({ method: init.method, access });
    const custom = await options.resourceReply?.(state, init);
    if (custom) return custom;
    if (!state.acceptedAccess || access !== `Bearer ${state.acceptedAccess}`) {
      state.unauthorized++;
      return new Response(null, { status: 401 });
    }
    if (init.method === "DELETE") return new Response(null, { status: 204 });
    if (init.method === "GET") return new Response(null, { status: 405 });
    const message = JSON.parse(init.body);
    if (message.id === undefined) return new Response(null, { status: 202 });
    return json({ jsonrpc: "2.0", id: message.id, result: {} });
  };
  t.mock.method(globalThis, "fetch", fetchFn); // Browser preflight uses the configured bridge fetch.
  const provider = new BridgeOAuthProvider(config);
  await provider.saveClientInformation({ client_id: state.clientId, token_endpoint_auth_method: "none" });
  await provider.saveTokens({ access_token: state.acceptedAccess, refresh_token: state.refresh, token_type: "Bearer" });
  await provider.saveDiscoveryState({ authorizationServerUrl: origin, authorizationServerMetadata: metadata, resourceMetadata });
  const coordinator = new OAuthFlowCoordinator(provider, { fetchFn });
  const transport = new StreamableHTTPClientTransport(config.url, { fetch: coordinator.fetch });
  transport.onmessage = () => {};
  await transport.start();
  t.after(async () => {
    await coordinator.close();
    await transport.close();
    await rm(directory, { recursive: true, force: true });
  });
  return { config, provider, coordinator, transport, state, send: (id) => transport.send({ jsonrpc: "2.0", id, method: "tools/list", params: {} }) };
}

test("client replacement and invalidation discard associated tokens atomically", async (t) => {
  const f = await fixture(t);
  await f.provider.saveClientInformation({ client_id: "old-client", client_name: "updated metadata" });
  assert.equal((await f.provider.tokens()).refresh_token, "old-refresh");
  await f.provider.saveClientInformation({ client_id: "replacement-client" });
  assert.equal(await f.provider.tokens(), undefined);
  await f.provider.saveTokens({ access_token: "new", token_type: "Bearer" });
  await f.provider.invalidateCredentials("client");
  assert.equal(await f.provider.clientInformation(), undefined);
  assert.equal(await f.provider.tokens(), undefined);
});

test("healthy requests do not reserve a callback or change the client", async (t) => {
  const f = await fixture(t, { portDelta: 1 });
  await f.send(1);
  assert.equal(f.state.callbacks, 0);
  assert.equal((await f.provider.clientInformation()).client_id, "old-client");
  assert.equal((await f.provider.tokens()).refresh_token, "old-refresh");
});

test("a slow authenticated request does not block other MCP requests", { timeout: 2_000 }, async (t) => {
  const entered = deferred();
  const resume = deferred();
  const f = await fixture(t, {
    resourceReply: async (_state, init) => {
      if (JSON.parse(init.body).id === 1) {
        entered.resolve();
        await resume.promise;
      }
    }
  });
  const slow = f.send(1);
  await entered.promise;
  try {
    await f.send(2);
  } finally {
    resume.resolve();
    await slow;
  }
});

test("callback fallback starts fresh authorization without refreshing the previous client's token", async (t) => {
  const f = await fixture(t, { portDelta: 1 });
  f.state.expire();
  await f.send(1);
  assert.equal(f.state.refreshes, 0);
  assert.equal(f.state.registrations, 1);
  assert.equal(f.state.exchanges, 1);
  assert.equal((await f.provider.clientInformation()).redirect_uris[0], "http://127.0.0.1:33419/oauth/callback");
  assert.equal((await f.provider.tokens()).access_token, f.state.acceptedAccess);
});

test("concurrent requests refresh once after initialization and reuse the saved rotation", async (t) => {
  const refreshing = deferred();
  const resume = deferred();
  const f = await fixture(t, { refreshReply: async () => { refreshing.resolve(); await resume.promise; } });
  await f.send(1);
  f.state.expire();
  const requests = Promise.all([2, 3, 4].map(f.send));
  await refreshing.promise;
  assert.equal(f.state.refreshes, 1);
  resume.resolve();
  await requests;
  assert.equal(f.state.refreshes, 1);
  assert.equal(f.state.browsers, 0);
  assert.equal((await f.provider.tokens()).refresh_token, f.state.refresh);
});

test("the optional SSE connection refreshes through the same coordinator", async (t) => {
  const sseRequested = deferred();
  const f = await fixture(t, {
    resourceReply: async (state, init) => {
      if (init.method === "POST" && JSON.parse(init.body).method === "notifications/initialized") {
        state.expire();
        return new Response(null, { status: 202 });
      }
      if (init.method === "GET" && state.acceptedAccess) sseRequested.resolve();
    }
  });
  await f.send(1);
  await f.transport.send({ jsonrpc: "2.0", method: "notifications/initialized" });
  await sseRequested.promise;
  assert.equal(f.state.refreshes, 1);
  assert.equal(f.state.browsers, 0);
});

test("invalid_request on refresh resets the session once and completes browser login", async (t) => {
  const f = await fixture(t, { refreshReply: () => json({ error: "invalid_request", error_description: "The token request is invalid." }, 400) });
  await f.send(1);
  f.state.expire();
  await f.send(2);
  assert.equal(f.state.refreshes, 1);
  assert.equal(f.state.registrations, 1);
  assert.equal(f.state.browsers, 1);
  assert.equal(f.state.exchanges, 1);
  assert.equal((await f.provider.tokens()).refresh_token, f.state.refresh);
  f.state.expire();
  await assert.rejects(f.send(3), { name: "InvalidRequestError" });
  assert.equal(f.state.registrations, 1);
  assert.equal(f.state.browsers, 1);
});

test("standard invalid_grant retains the client and authorizes again", async (t) => {
  const f = await fixture(t, { refreshReply: () => json({ error: "invalid_grant" }, 400) });
  f.state.expire();
  await f.send(1);
  assert.equal(f.state.registrations, 0);
  assert.equal(f.state.browsers, 1);
  assert.equal(f.provider.staleClientRecoveryUsed, false);
});

test("invalid_request during registration does not trigger fresh registration retries", async (t) => {
  const f = await fixture(t, { registrationReply: () => json({ error: "invalid_request" }, 400) });
  await f.provider.invalidateCredentials("all");
  await assert.rejects(f.send(1), { name: "InvalidRequestError" });
  assert.equal(f.state.registrations, 1);
  assert.equal(f.provider.staleClientRecoveryUsed, false);
});

test("invalid_request during code exchange does not restart browser authorization", async (t) => {
  const f = await fixture(t, { codeReply: () => json({ error: "invalid_request" }, 400) });
  await f.provider.invalidateCredentials("tokens");
  await assert.rejects(f.send(1), { name: "InvalidRequestError" });
  assert.equal(f.state.exchanges, 1);
  assert.equal(f.state.browsers, 1);
  assert.equal(f.provider.staleClientRecoveryUsed, false);
});

test("a server error on refresh does not trigger the invalid-request cache reset", async (t) => {
  const f = await fixture(t, { refreshReply: () => json({ error: "server_error" }, 503) });
  f.state.expire();
  await f.send(1); // The SDK falls back to browser authorization for server errors.
  assert.equal(f.state.registrations, 0);
  assert.equal(f.provider.staleClientRecoveryUsed, false);
});

test("persistent resource rejection is retried only once", async (t) => {
  const f = await fixture(t, { resourceReply: () => new Response(null, { status: 401 }) });
  await assert.rejects(f.send(1), { code: 401 });
  assert.equal(f.state.requests.length, 2);
  assert.equal(f.state.refreshes, 1);
  assert.equal(f.state.browsers, 0);
});

test("ordinary 403 and session termination do not start OAuth", async (t) => {
  const f = await fixture(t, { resourceReply: () => new Response(null, { status: 403 }) });
  await assert.rejects(f.send(1), { code: 403 });
  const response = await f.coordinator.fetch(f.config.url, { method: "DELETE" });
  assert.equal(response.status, 403);
  assert.equal(f.state.refreshes, 0);
  assert.equal(f.state.callbacks, 0);
});

test("insufficient_scope challenges are passed to OAuth and retried", async (t) => {
  const f = await fixture(t, {
    resourceReply: (state) => state.refreshes === 0 ? new Response(null, {
      status: 403, headers: { "www-authenticate": 'Bearer error="insufficient_scope", scope="tools.write"' }
    }) : undefined
  });
  await f.send(1);
  assert.equal(f.state.refreshes, 1);
});

test("shutdown allows an in-flight rotation to be saved before releasing ownership", async (t) => {
  const saving = deferred();
  const resume = deferred();
  const f = await fixture(t);
  const original = f.provider.saveTokens.bind(f.provider);
  f.provider.saveTokens = async (tokens) => { saving.resolve(); await resume.promise; await original(tokens); };
  f.state.expire();
  const request = f.send(1);
  await saving.promise;
  const closed = f.coordinator.close();
  const lock = JSON.parse(await readFile(f.provider.authorizationLockPath, "utf8"));
  assert.equal(lock.pid, process.pid);
  resume.resolve();
  await Promise.all([request, closed]);
  assert.equal((await f.provider.tokens()).refresh_token, f.state.refresh);
  await assert.rejects(readFile(f.provider.authorizationLockPath), { code: "ENOENT" });
});
