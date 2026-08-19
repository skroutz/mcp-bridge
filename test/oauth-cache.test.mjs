import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

process.env.MCP_BRIDGE_TEST_MODE = "1";

const {
  BridgeOAuthProvider,
  OAuthAuthorizationError,
  OAuthFlowCoordinator,
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

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
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

test("OAuth callback ignores stale state and accepts the active callback", async (t) => {
  let waiter;
  try {
    waiter = await createOAuthCallbackWaiter({
      expectedPath: "/oauth/callback",
      expectedState: "active-state",
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
    const staleResponse = await fetch(
      `http://127.0.0.1:${waiter.port}/oauth/callback?error=access_denied&state=stale-state`
    );
    assert.equal(staleResponse.status, 400);

    const activeResponse = await fetch(
      `http://127.0.0.1:${waiter.port}/oauth/callback?code=authorization-code&state=active-state`
    );
    assert.equal(activeResponse.status, 200);
    assert.equal(await waiter.codePromise, "authorization-code");
  } finally {
    await waiter.close();
  }
});

test("concurrent authorization redirects reuse one callback and browser launch", async () => {
  await withTemporaryDirectory(async (directory) => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(null, { status: 302 });

    const callback = deferred();
    let callbackStarts = 0;
    let callbackCloses = 0;
    let browserLaunches = 0;
    const provider = new BridgeOAuthProvider({
      ...oauthConfig(join(directory, "oauth-cache.json")),
      oauth: {
        ...oauthConfig(join(directory, "oauth-cache.json")).oauth,
        browserOpener: async () => {
          browserLaunches += 1;
          return "test-browser";
        },
        callbackWaiterFactory: async () => {
          callbackStarts += 1;
          return {
            close: async () => {
              callbackCloses += 1;
            },
            codePromise: callback.promise,
            port: 33418
          };
        },
        openBrowser: true
      }
    });

    try {
      const states = await Promise.all(Array.from({ length: 5 }, () => provider.state()));
      assert.equal(new Set(states).size, 1);

      const codeVerifier = "shared-code-verifier";
      await Promise.all(Array.from({ length: 5 }, (_, index) => provider.saveCodeVerifier(
        index === 0 ? codeVerifier : `superseded-verifier-${index}`
      )));
      const authorizationUrl = new URL("https://auth.example.test/authorize");
      authorizationUrl.searchParams.set("state", states[0]);
      authorizationUrl.searchParams.set(
        "code_challenge",
        createHash("sha256").update(codeVerifier).digest("base64url")
      );

      const supersededAuthorizationUrl = new URL(authorizationUrl);
      supersededAuthorizationUrl.searchParams.set("code_challenge", "superseded-code-challenge");
      await provider.redirectToAuthorization(supersededAuthorizationUrl);
      assert.equal(callbackStarts, 0);
      assert.equal(browserLaunches, 0);

      await Promise.all(Array.from({ length: 5 }, () => provider.redirectToAuthorization(authorizationUrl)));
      assert.equal(callbackStarts, 1);
      assert.equal(browserLaunches, 1);

      const authorizationCode = provider.waitForAuthorizationCode();
      callback.resolve("authorization-code");
      assert.equal(await authorizationCode, "authorization-code");
      assert.equal(callbackCloses, 1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

test("OAuth browser launch waits for bridge process stabilization", async () => {
  await withTemporaryDirectory(async (directory) => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(null, { status: 302 });
    const callback = deferred();
    const stabilizationEntered = deferred();
    const releaseStabilization = deferred();
    let browserLaunches = 0;
    const provider = new BridgeOAuthProvider({
      ...oauthConfig(join(directory, "oauth-cache.json")),
      oauth: {
        ...oauthConfig(join(directory, "oauth-cache.json")).oauth,
        browserLaunchDelayMs: 5_000,
        browserLaunchStabilizer: async (delayMs) => {
          assert.equal(delayMs, 5_000);
          stabilizationEntered.resolve();
          await releaseStabilization.promise;
        },
        browserOpener: async () => {
          browserLaunches += 1;
          return "test-browser";
        },
        callbackWaiterFactory: async () => ({
          cancel: callback.reject,
          close: async () => undefined,
          codePromise: callback.promise,
          port: 33418
        }),
        openBrowser: true
      }
    });

    try {
      const redirect = provider.redirectToAuthorization(new URL("https://auth.example.test/authorize"));
      await stabilizationEntered.promise;
      assert.equal(browserLaunches, 0);
      releaseStabilization.resolve();
      await redirect;
      assert.equal(browserLaunches, 1);
      await provider.resetAuthorizationFlow();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

test("OAuth browser launch is cancelled when the probe exits during stabilization", async () => {
  await withTemporaryDirectory(async (directory) => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(null, { status: 302 });
    const callback = deferred();
    const stabilizationEntered = deferred();
    const releaseStabilization = deferred();
    let browserLaunches = 0;
    const provider = new BridgeOAuthProvider({
      ...oauthConfig(join(directory, "oauth-cache.json")),
      oauth: {
        ...oauthConfig(join(directory, "oauth-cache.json")).oauth,
        browserLaunchDelayMs: 5_000,
        browserLaunchStabilizer: async () => {
          stabilizationEntered.resolve();
          await releaseStabilization.promise;
        },
        browserOpener: async () => {
          browserLaunches += 1;
          return "test-browser";
        },
        callbackWaiterFactory: async () => ({
          cancel: callback.reject,
          close: async () => undefined,
          codePromise: callback.promise,
          port: 33418
        }),
        openBrowser: true
      }
    });

    try {
      const redirect = provider.redirectToAuthorization(new URL("https://auth.example.test/authorize"));
      await stabilizationEntered.promise;
      await provider.resetAuthorizationFlow();
      releaseStabilization.resolve();
      await redirect;
      assert.equal(browserLaunches, 0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

test("concurrent authorization completions exchange the code once", async () => {
  const coordinator = new OAuthFlowCoordinator({});
  let exchanges = 0;
  const completion = deferred();
  const complete = async () => {
    exchanges += 1;
    await completion.promise;
    return "authorized";
  };

  const waiters = Array.from({ length: 5 }, () => coordinator.completeAuthorization(complete));
  await Promise.resolve();
  assert.equal(exchanges, 1);
  completion.resolve();
  assert.deepEqual(await Promise.all(waiters), Array(5).fill("authorized"));
});

test("initial unauthenticated requests enter the OAuth path one at a time", async () => {
  const tokens = { value: undefined };
  const coordinator = new OAuthFlowCoordinator({
    async tokens() {
      return tokens.value;
    }
  });
  let activeOperations = 0;
  let maximumActiveOperations = 0;
  let operations = 0;
  const firstOperationEntered = deferred();
  const releaseFirstOperation = deferred();

  const run = async () => coordinator.runWithInitialAuthGate(async () => {
    operations += 1;
    activeOperations += 1;
    maximumActiveOperations = Math.max(maximumActiveOperations, activeOperations);
    if (operations === 1) {
      tokens.value = { access_token: "access-token" };
      firstOperationEntered.resolve();
      await releaseFirstOperation.promise;
    } else {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 2));
    }
    activeOperations -= 1;
  });

  const firstRequest = run();
  await firstOperationEntered.promise;
  const laterRequests = Array.from({ length: 4 }, run);
  releaseFirstOperation.resolve();
  await Promise.all([firstRequest, ...laterRequests]);
  assert.equal(operations, 5);
  assert.equal(maximumActiveOperations, 1);
});

test("concurrent MCP requests complete through one OAuth flow", async (t) => {
  await withTemporaryDirectory(async (directory) => {
    const { UnauthorizedError } = await import("@modelcontextprotocol/sdk/client/auth.js");
    const { StreamableHTTPClientTransport } = await import("@modelcontextprotocol/sdk/client/streamableHttp.js");
    const counters = {
      authorizationRequests: 0,
      authenticatedMcpRequests: 0,
      browserLaunches: 0,
      tokenExchanges: 0,
      unauthorizedMcpRequests: 0
    };
    const server = createServer(async (request, response) => {
      const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
      if (requestUrl.pathname === "/authorize") {
        counters.authorizationRequests += 1;
        response.writeHead(302, { location: "https://login.example.test/" });
        response.end();
        return;
      }
      if (requestUrl.pathname === "/token") {
        counters.tokenExchanges += 1;
        for await (const _chunk of request) {
          // Consume the form body before replying.
        }
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({
          access_token: "test-access-token",
          token_type: "Bearer"
        }));
        return;
      }
      if (requestUrl.pathname === "/mcp") {
        let body = "";
        for await (const chunk of request) {
          body += chunk.toString("utf8");
        }
        if (request.headers.authorization !== "Bearer test-access-token") {
          counters.unauthorizedMcpRequests += 1;
          response.writeHead(401, { "content-type": "text/plain" });
          response.end("OAuth required");
          return;
        }
        counters.authenticatedMcpRequests += 1;
        const message = JSON.parse(body);
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({
          id: message.id,
          jsonrpc: "2.0",
          result: { ok: true }
        }));
        return;
      }
      response.writeHead(404);
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

    const origin = `http://127.0.0.1:${server.address().port}`;
    const callback = deferred();
    const config = {
      allowHttp: true,
      headers: {},
      oauth: {
        browserOpener: async (authorizationUrl) => {
          counters.browserLaunches += 1;
          assert.equal(authorizationUrl.searchParams.get("state"), callback.expectedState);
          queueMicrotask(() => callback.resolve("authorization-code"));
          return "test-browser";
        },
        callbackWaiterFactory: async ({ expectedState }) => {
          callback.expectedState = expectedState;
          return {
            close: async () => undefined,
            codePromise: callback.promise,
            port: 33418
          };
        },
        openBrowser: true,
        redirectUrl: new URL("http://127.0.0.1:33418/oauth/callback"),
        storagePath: join(directory, "oauth-cache.json")
      },
      url: new URL(`${origin}/mcp`)
    };
    const provider = new BridgeOAuthProvider(config);
    await provider.saveClientInformation({ client_id: "test-client" });
    await provider.saveDiscoveryState({
      authorizationServerMetadata: {
        authorization_endpoint: `${origin}/authorize`,
        code_challenge_methods_supported: ["S256"],
        response_types_supported: ["code"],
        token_endpoint: `${origin}/token`
      },
      authorizationServerUrl: origin,
      resourceMetadata: {
        authorization_servers: [origin],
        resource: `${origin}/mcp`
      }
    });

    const coordinator = new OAuthFlowCoordinator(provider);
    const transport = new StreamableHTTPClientTransport(config.url, { authProvider: provider });
    const responses = [];
    transport.onmessage = (message) => responses.push(message);
    await transport.start();

    const send = (id) => coordinator.runWithInitialAuthGate(async () => {
      const message = { id, jsonrpc: "2.0", method: "tools/list", params: {} };
      try {
        await transport.send(message);
      } catch (error) {
        assert.ok(error instanceof UnauthorizedError);
        await coordinator.completeAuthorization(async () => {
          const authorizationCode = await provider.waitForAuthorizationCode();
          await transport.finishAuth(authorizationCode);
          await provider.resetAuthorizationFlow();
        });
        await transport.send(message);
      }
    });

    try {
      await Promise.all(Array.from({ length: 5 }, (_, index) => send(index + 1)));
      assert.equal(counters.authorizationRequests, 1);
      assert.equal(counters.browserLaunches, 1);
      assert.equal(counters.tokenExchanges, 1);
      assert.equal(counters.unauthorizedMcpRequests, 1);
      assert.equal(counters.authenticatedMcpRequests, 5);
      assert.equal(responses.length, 5);
    } finally {
      await transport.close();
      await new Promise((resolveClose) => server.close(resolveClose));
    }
  });
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
