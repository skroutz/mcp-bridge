import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

process.env.MCP_BRIDGE_TEST_MODE = "1";
const { BridgeOAuthProvider } = await import("../index.js");

test("separate initialized bridge processes share one refresh through cache persistence", { timeout: 10_000 }, async (t) => {
  let expired = false;
  let refreshes = 0;
  let rejectedRequests = 0;
  let rejectBoth;
  const bothRejected = new Promise((resolve) => { rejectBoth = resolve; });
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    response.setHeader("content-type", "application/json");
    if (request.url === "/token") {
      refreshes++;
      const params = new URLSearchParams(body);
      if (refreshes > 1 || params.get("refresh_token") !== "old-refresh" || params.get("client_id") !== "client") {
        response.writeHead(400);
        response.end(JSON.stringify({ error: "invalid_request", error_description: "The token request is invalid." }));
        return;
      }
      response.end(JSON.stringify({ access_token: "new-access", refresh_token: "new-refresh", token_type: "Bearer" }));
      return;
    }
    if (request.url !== "/mcp") {
      response.writeHead(404);
      response.end();
      return;
    }
    const expected = expired ? "Bearer new-access" : "Bearer old-access";
    if (request.headers.authorization !== expected) {
      if (++rejectedRequests === 2) rejectBoth();
      response.writeHead(401);
      response.end();
      return;
    }
    response.end(JSON.stringify({ jsonrpc: "2.0", id: JSON.parse(body).id, result: {} }));
  });
  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
  } catch (error) {
    if (error.code === "EPERM") {
      t.skip("The sandbox does not permit loopback listeners.");
      return;
    }
    throw error;
  }
  const directory = await mkdtemp(join(tmpdir(), "mcp-refresh-process-"));
  const workers = [];
  t.after(async () => {
    for (const worker of workers) if (worker.child.exitCode === null) worker.child.kill("SIGKILL");
    await Promise.allSettled(workers.map((worker) => worker.exited));
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const storagePath = join(directory, "cache.json");
  const provider = new BridgeOAuthProvider({
    url: new URL(`${origin}/mcp`),
    oauth: { storagePath, redirectUrl: new URL("http://127.0.0.1:33418/oauth/callback") }
  });
  await provider.saveClientInformation({ client_id: "client", token_endpoint_auth_method: "none" });
  await provider.saveTokens({ access_token: "old-access", refresh_token: "old-refresh", token_type: "Bearer" });
  await provider.saveDiscoveryState({
    authorizationServerUrl: origin,
    resourceMetadata: { resource: `${origin}/mcp`, authorization_servers: [origin] },
    authorizationServerMetadata: {
      token_endpoint: `${origin}/token`, authorization_endpoint: `${origin}/authorize`,
      response_types_supported: ["code"], token_endpoint_auth_methods_supported: ["none"]
    }
  });
  workers.push(startWorker(storagePath, `${origin}/mcp`), startWorker(storagePath, `${origin}/mcp`));
  await Promise.all(workers.map((worker) => worker.next("ready")));
  expired = true;
  workers.forEach((worker) => worker.child.send("refresh"));
  const owner = await Promise.race(workers.map(async (worker) => { await worker.next("saving"); return worker; }));
  await bothRejected;
  assert.equal(refreshes, 1);
  assert.equal((await provider.tokens()).refresh_token, "old-refresh");
  const lock = JSON.parse(await readFile(provider.authorizationLockPath, "utf8"));
  assert.equal(lock.pid, owner.child.pid);
  owner.child.send("save");
  await Promise.all(workers.map((worker) => worker.next("done")));
  await Promise.all(workers.map((worker) => worker.exited));
  assert.equal(refreshes, 1);
  assert.equal((await provider.tokens()).refresh_token, "new-refresh");
});

function startWorker(storagePath, endpoint) {
  const child = fork(new URL("../test-fixtures/oauth-refresh-worker.mjs", import.meta.url), [storagePath, endpoint], { silent: true });
  const received = new Set();
  const waiters = new Map();
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("message", ({ type }) => {
    received.add(type);
    waiters.get(type)?.resolve();
  });
  const exited = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => {
      const error = new Error(`Refresh worker exited with code ${code}: ${stderr}`);
      for (const [type, waiter] of waiters) if (!received.has(type)) waiter.reject(error);
      if (code === 0) resolve(); else reject(error);
    });
  });
  exited.catch(() => {});
  return {
    child, exited,
    next(type) {
      if (received.has(type)) return Promise.resolve();
      return new Promise((resolve, reject) => waiters.set(type, { resolve, reject }));
    }
  };
}
