import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

process.env.MCP_BRIDGE_TEST_MODE = "1";

const {
  BridgeOAuthProvider,
  OAuthAuthorizationError,
  completeOAuthAuthorization,
  createOAuthCallbackWaiter
} = await import("../index.js");

function oauthConfig(storagePath, { scope } = {}) {
  return {
    url: new URL("https://mcp.example.test/mcp"),
    oauth: {
      redirectUrl: new URL("http://127.0.0.1:33418/oauth/callback"),
      scope,
      storagePath
    }
  };
}

async function withTemporaryDirectory(run) {
  const directory = await mkdtemp(join(tmpdir(), "mcp-bridge-test-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("OAuth cache is fingerprinted and expired client registrations are discarded", async () => {
  await withTemporaryDirectory(async (directory) => {
    const storagePath = join(directory, "oauth-cache.json");
    const provider = new BridgeOAuthProvider(oauthConfig(storagePath, { scope: "tools.read" }));
    await provider.saveClientInformation({
      client_id: "registered-client",
      client_secret: "secret",
      client_secret_expires_at: Math.floor(Date.now() / 1000) - 1
    });
    await provider.saveTokens({ access_token: "access-token", token_type: "Bearer" });

    assert.equal(await provider.clientInformation(), undefined);
    assert.equal(await provider.tokens(), undefined);

    const cache = JSON.parse(await readFile(storagePath, "utf8"));
    const session = Object.values(cache.sessions)[0];
    assert.equal(session.version, 1);
    assert.equal(session.clientInformation, undefined);
    assert.equal(session.tokens, undefined);

    const changedScope = new BridgeOAuthProvider(oauthConfig(storagePath, { scope: "tools.write" }));
    assert.equal(await changedScope.clientInformation(), undefined);
  });
});

test("OAuth callback exposes authorization-endpoint invalid_client distinctly", async (t) => {
  let waiter;
  try {
    waiter = await createOAuthCallbackWaiter({
      expectedPath: "/oauth/callback",
      expectedState: "expected-state",
      host: "127.0.0.1",
      port: 0,
      timeoutMs: 5_000
    });
  } catch (error) {
    if (error?.code === "EPERM") {
      t.skip("The sandbox does not permit loopback listeners.");
      return;
    }
    throw error;
  }

  try {
    const rejection = assert.rejects(waiter.codePromise, (error) => (
      error instanceof OAuthAuthorizationError && error.oauthError === "invalid_client"
    ));
    const response = await fetch(
      `http://127.0.0.1:${waiter.port}/oauth/callback?error=invalid_client&state=expected-state`
    );
    assert.equal(response.status, 400);
    await rejection;
  } finally {
    await waiter.close();
  }
});

test("authorization-endpoint HTTP 400 invalid_client is detected before opening a browser", async () => {
  await withTemporaryDirectory(async (directory) => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response('{"error":"invalid_client"}', {
      status: 400,
      headers: { "content-type": "application/json" }
    });

    try {
      const provider = new BridgeOAuthProvider({
        ...oauthConfig(join(directory, "oauth-cache.json")),
        oauth: {
          ...oauthConfig(join(directory, "oauth-cache.json")).oauth,
          openBrowser: false
        }
      });
      await assert.rejects(
        provider.redirectToAuthorization(new URL("https://auth.example.test/authorize?client_id=stale")),
        (error) => error instanceof OAuthAuthorizationError && error.oauthError === "invalid_client"
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

test("invalid_client from the authorization endpoint restarts DCR once", async () => {
  let waitCalls = 0;
  let recoveryCalls = 0;
  let authorizationStarts = 0;
  const finishedCodes = [];
  const provider = {
    staleClientRecoveryUsed: false,
    async waitForAuthorizationCode() {
      waitCalls += 1;
      if (waitCalls === 1) {
        throw new OAuthAuthorizationError("invalid_client");
      }
      return "fresh-authorization-code";
    },
    async recoverStaleClient() {
      recoveryCalls += 1;
      if (this.staleClientRecoveryUsed) {
        return false;
      }
      this.staleClientRecoveryUsed = true;
      return true;
    }
  };

  await completeOAuthAuthorization({
    config: {},
    provider,
    startAuthorization: async () => {
      authorizationStarts += 1;
    },
    finishAuthorization: async (code) => {
      finishedCodes.push(code);
    }
  });

  assert.equal(recoveryCalls, 1);
  assert.equal(authorizationStarts, 1);
  assert.deepEqual(finishedCodes, ["fresh-authorization-code"]);
});
