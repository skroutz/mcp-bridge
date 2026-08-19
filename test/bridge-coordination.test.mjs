import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

process.env.MCP_BRIDGE_TEST_MODE = "1";

const {
  BridgeOAuthProvider,
  McpInitializationBarrier,
  createOAuthCallbackWaiter
} = await import("../index.js");

const testDirectory = dirname(fileURLToPath(import.meta.url));

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

async function withTemporaryDirectory(run) {
  const directory = await mkdtemp(join(tmpdir(), "mcp-bridge-coordination-test-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function oauthConfig(storagePath, endpoint = "https://mcp.example.test/mcp") {
  return {
    url: new URL(endpoint),
    oauth: {
      callbackPort: 33418,
      redirectUrl: new URL("http://127.0.0.1:33418/oauth/callback"),
      storagePath
    }
  };
}

test("messages after initialize wait until the remote session ID is established", async (t) => {
  const initializeReceived = deferred();
  const releaseInitialize = deferred();
  const requests = [];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) {
      body += chunk.toString("utf8");
    }
    const message = JSON.parse(body);
    requests.push({ message, sessionId: request.headers["mcp-session-id"] });

    if (message.method === "initialize") {
      initializeReceived.resolve();
      await releaseInitialize.promise;
      response.writeHead(200, {
        "content-type": "application/json",
        "mcp-session-id": "test-session"
      });
      response.end(JSON.stringify({
        id: message.id,
        jsonrpc: "2.0",
        result: {
          capabilities: {},
          protocolVersion: "2025-06-18",
          serverInfo: { name: "test", version: "1.0.0" }
        }
      }));
      return;
    }

    assert.equal(request.headers["mcp-session-id"], "test-session");
    response.writeHead(202);
    response.end();
  });

  try {
    await new Promise((resolveListen, rejectListen) => {
      server.once("error", rejectListen);
      server.listen(0, "127.0.0.1", resolveListen);
    });
  } catch (error) {
    if (error?.code === "EPERM") {
      t.skip("The sandbox does not permit loopback listeners.");
      return;
    }
    throw error;
  }

  const { StreamableHTTPClientTransport } = await import("@modelcontextprotocol/sdk/client/streamableHttp.js");
  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${server.address().port}/mcp`)
  );
  transport.onmessage = () => undefined;
  await transport.start();
  const barrier = new McpInitializationBarrier();
  const initialize = barrier.forward(
    { id: 1, jsonrpc: "2.0", method: "initialize", params: {} },
    async () => transport.send({ id: 1, jsonrpc: "2.0", method: "initialize", params: {} })
  );

  await initializeReceived.promise;
  const initialized = barrier.forward(
    { jsonrpc: "2.0", method: "notifications/initialized", params: {} },
    async () => transport.send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} })
  );
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 20));
  assert.equal(requests.length, 1);

  releaseInitialize.resolve();
  await Promise.all([initialize, initialized]);
  assert.equal(requests.length, 2);
  assert.equal(requests[1].sessionId, "test-session");

  await transport.close();
  await new Promise((resolveClose) => server.close(resolveClose));
});

test("OAuth callback listener advances to the next port when the preferred port is occupied", async (t) => {
  let first;
  let second;
  try {
    first = await createOAuthCallbackWaiter({
      expectedPath: "/oauth/callback",
      expectedState: "first",
      host: "127.0.0.1",
      port: 0,
      timeoutMs: 5_000
    });
    first.codePromise.catch(() => undefined);
    if (first.port === 65535) {
      first.cancel();
      await first.close();
      t.skip("The ephemeral listener used the final available port.");
      return;
    }
    second = await createOAuthCallbackWaiter({
      expectedPath: "/oauth/callback",
      expectedState: "second",
      host: "127.0.0.1",
      port: first.port,
      timeoutMs: 5_000
    });
    second.codePromise.catch(() => undefined);
  } catch (error) {
    if (error?.code === "EPERM") {
      t.skip("The sandbox does not permit loopback listeners.");
      return;
    }
    throw error;
  }

  assert.equal(second.port, first.port + 1);
  first.cancel();
  second.cancel();
  await Promise.all([first.close(), second.close()]);
});

test("OAuth registration metadata uses the selected callback port", async () => {
  await withTemporaryDirectory(async (directory) => {
    const callback = deferred();
    const config = oauthConfig(join(directory, "oauth-cache.json"));
    config.oauth.callbackWaiterFactory = async ({ port }) => ({
      cancel: callback.reject,
      close: async () => undefined,
      codePromise: callback.promise,
      port: port + 1
    });
    const provider = new BridgeOAuthProvider(config);
    await provider.saveClientInformation({ client_id: "old-port-client" });

    assert.equal(await provider.prepareAuthorization(), true);
    assert.equal(provider.redirectUrl.port, "33419");
    assert.deepEqual(provider.clientMetadata.redirect_uris, ["http://127.0.0.1:33419/oauth/callback"]);
    assert.equal(await provider.clientInformation(), undefined);

    await provider.releaseAuthorizationOwnership();
  });
});

test("concurrent providers preserve each other's OAuth cache entries", async () => {
  await withTemporaryDirectory(async (directory) => {
    const storagePath = join(directory, "oauth-cache.json");
    const first = new BridgeOAuthProvider(oauthConfig(storagePath, "https://one.example.test/mcp"));
    const second = new BridgeOAuthProvider(oauthConfig(storagePath, "https://two.example.test/mcp"));

    await Promise.all([
      first.saveTokens({ access_token: "first-token", token_type: "Bearer" }),
      second.saveTokens({ access_token: "second-token", token_type: "Bearer" })
    ]);

    const cache = JSON.parse(await readFile(storagePath, "utf8"));
    assert.equal(Object.keys(cache.sessions).length, 2);
    assert.deepEqual(await first.tokens(), { access_token: "first-token", token_type: "Bearer" });
    assert.deepEqual(await second.tokens(), { access_token: "second-token", token_type: "Bearer" });
  });
});

test("two bridge processes elect only one OAuth authorization owner", async () => {
  await withTemporaryDirectory(async (directory) => {
    const storagePath = join(directory, "oauth-cache.json");
    const seedProvider = new BridgeOAuthProvider(oauthConfig(storagePath, "https://shared.example.test/mcp"));
    await seedProvider.saveTokens({ access_token: "stale-token", token_type: "Bearer" });
    const workerPath = join(testDirectory, "..", "test-fixtures", "oauth-lock-worker.mjs");
    const first = startWorker(workerPath, storagePath);
    const firstMessage = await nextWorkerMessage(first);
    assert.equal(firstMessage.role, "owner");

    const second = startWorker(workerPath, storagePath);
    const secondMessagePromise = nextWorkerMessage(second);
    const prematureFollower = Promise.race([
      secondMessagePromise,
      new Promise((resolve) => setTimeout(() => resolve(undefined), 150))
    ]);
    assert.equal(await prematureFollower, undefined);

    first.send("complete");
    const secondMessage = await secondMessagePromise;
    assert.equal(secondMessage.role, "follower");
    assert.equal(secondMessage.accessToken, "shared-token");

    await Promise.all([waitForWorker(first), waitForWorker(second)]);
  });
});

function startWorker(workerPath, storagePath) {
  return fork(workerPath, [storagePath], {
    env: { ...process.env, MCP_BRIDGE_TEST_MODE: "1" },
    silent: true
  });
}

function nextWorkerMessage(worker) {
  return new Promise((resolve, reject) => {
    worker.once("message", resolve);
    worker.once("error", reject);
    worker.once("exit", (code) => {
      if (code !== 0) {
        reject(new Error(`OAuth lock worker exited with code ${code}.`));
      }
    });
  });
}

function waitForWorker(worker) {
  return new Promise((resolve, reject) => {
    if (worker.exitCode !== null) {
      resolve();
      return;
    }
    worker.once("error", reject);
    worker.once("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`OAuth lock worker exited with code ${code}.`));
      }
    });
  });
}
