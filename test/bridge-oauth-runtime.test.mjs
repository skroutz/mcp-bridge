import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

process.env.MCP_BRIDGE_TEST_MODE = "1";
const { BridgeOAuthProvider } = await import("../index.js");
const entrypoint = fileURLToPath(new URL("../index.js", import.meta.url));

async function fixture(t) {
  const state = { access: "old-access", refreshes: 0 };
  const server = createServer(async (request, response) => {
    if (request.url === "/token") {
      let body = "";
      for await (const chunk of request) body += chunk;
      assert.equal(new URLSearchParams(body).get("refresh_token"), "old-refresh");
      state.refreshes++;
      state.access = "new-access";
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ access_token: "new-access", refresh_token: "new-refresh", token_type: "Bearer" }));
      return;
    }
    assert.equal(request.url, "/mcp");
    if (request.headers.authorization !== `Bearer ${state.access}`) {
      request.resume();
      response.writeHead(401);
      response.end();
      return;
    }
    if (request.method === "GET" || request.method === "DELETE") {
      response.writeHead(request.method === "GET" ? 405 : 204);
      response.end();
      return;
    }
    let body = "";
    for await (const chunk of request) body += chunk;
    const message = JSON.parse(body);
    if (message.id === undefined) {
      response.writeHead(202);
      response.end();
      return;
    }
    response.setHeader("content-type", "application/json");
    let result = { tools: [] };
    if (message.method === "initialize") {
      response.setHeader("mcp-session-id", "fixture-session");
      result = { protocolVersion: message.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } };
    }
    response.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }));
  });
  const portProbe = createServer();
  try {
    await listen(server);
    await listen(portProbe);
  } catch (error) {
    server.close();
    if (error.code === "EPERM") {
      t.skip("The sandbox does not permit loopback listeners.");
      return;
    }
    throw error;
  }
  const callbackPort = portProbe.address().port;
  await new Promise((resolve) => portProbe.close(resolve));
  const directory = await mkdtemp(join(tmpdir(), "mcp-runtime-oauth-"));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const storagePath = join(directory, "cache.json");
  const provider = new BridgeOAuthProvider({
    url: new URL(`${origin}/mcp`),
    oauth: { storagePath, redirectUrl: new URL(`http://127.0.0.1:${callbackPort}/oauth/callback`) }
  });
  await provider.saveClientInformation({ client_id: "client", token_endpoint_auth_method: "none" });
  await provider.saveTokens({ access_token: "old-access", refresh_token: "old-refresh", token_type: "Bearer" });
  await provider.saveDiscoveryState({
    authorizationServerUrl: origin,
    resourceMetadata: { resource: `${origin}/mcp`, authorization_servers: [origin] },
    authorizationServerMetadata: { token_endpoint: `${origin}/token`, authorization_endpoint: `${origin}/authorize`, response_types_supported: ["code"], token_endpoint_auth_methods_supported: ["none"] }
  });
  return {
    state, provider,
    args: [entrypoint, "--allow-http", "--url", `${origin}/mcp`],
    oauthArgs: ["--oauth", "--oauth-storage", storagePath, "--oauth-callback-port", String(callbackPort)]
  };
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
}

for (const oauth of [true, false]) {
  test(`stdio entrypoint ${oauth ? "refreshes after initialization" : "preserves static bearer authentication"}`, { timeout: 10_000 }, async (t) => {
    const f = await fixture(t);
    if (!f) return;
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [...f.args, ...(oauth ? f.oauthArgs : ["--bearer-token", "old-access"])],
      env: { MCP_BRIDGE_TEST_MODE: "0" },
      stderr: "pipe"
    });
    let stderr = "";
    transport.stderr.on("data", (chunk) => { stderr += chunk; });
    const client = new Client({ name: "fixture-client", version: "1" });
    try {
      await client.connect(transport, { timeout: 4_000 });
      if (oauth) f.state.access = undefined;
      assert.deepEqual(await client.listTools({}, { timeout: 4_000 }), { tools: [] });
      assert.equal(f.state.refreshes, oauth ? 1 : 0);
      if (oauth) assert.equal((await f.provider.tokens()).refresh_token, "new-refresh");
    } catch (error) {
      throw new Error(`${error.message}\nBridge stderr: ${stderr}`, { cause: error });
    } finally {
      await client.close();
    }
  });
}

test("login-only entrypoint refreshes, verifies MCP, and exits", { timeout: 10_000 }, async (t) => {
  const f = await fixture(t);
  if (!f) return;
  const child = spawn(process.execPath, [...f.args, ...f.oauthArgs, "--oauth-login"], {
    env: { ...process.env, MCP_BRIDGE_TEST_MODE: "0" }, stdio: ["ignore", "pipe", "pipe"]
  });
  t.after(() => { if (child.exitCode === null) child.kill("SIGKILL"); });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const exitCode = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });
  assert.equal(exitCode, 0, stderr);
  assert.equal(f.state.refreshes, 1);
  assert.equal((await f.provider.tokens()).refresh_token, "new-refresh");
  assert.match(stderr, /OAuth login complete/);
});
