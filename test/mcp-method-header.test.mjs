import assert from "node:assert/strict";
import test from "node:test";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

process.env.MCP_BRIDGE_TEST_MODE = "1";
const { withMcpMethodHeader } = await import("../index.js");

test("outgoing MCP POSTs carry the method in a matching header", async () => {
  const requests = [];
  const responses = [];
  const gatewayFetch = async (_url, init) => {
    const headers = new Headers(init.headers);
    requests.push({ method: init.method, headers, body: init.body });

    if (init.method === "GET") {
      return new Response(null, { status: 405 });
    }
    if (init.method === "DELETE") {
      return new Response(null, { status: 204 });
    }

    const message = JSON.parse(init.body);
    if (message.method === "server/discover" && headers.get("mcp-method") !== message.method) {
      return new Response(JSON.stringify({
        jsonrpc: "2.0",
        id: message.id,
        error: { code: -32020, message: "Mcp-Method header is absent" }
      }), { status: 400, headers: { "content-type": "application/json" } });
    }
    if (message.id === undefined) {
      return new Response(null, { status: 202 });
    }

    const result = message.method === "initialize"
      ? { protocolVersion: "2025-11-25", capabilities: {}, serverInfo: { name: "fixture", version: "1" } }
      : { servers: [] };
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        ...(message.method === "initialize" ? { "mcp-session-id": "test-session" } : {})
      }
    });
  };

  const transport = new StreamableHTTPClientTransport(new URL("https://portal.example.test/mcp"), {
    fetch: withMcpMethodHeader(gatewayFetch),
    requestInit: { headers: { "x-custom-header": "kept" } }
  });
  transport.onmessage = (message) => responses.push(message);
  await transport.start();
  try {
    await transport.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    transport.setProtocolVersion("2025-11-25");
    await transport.send({ jsonrpc: "2.0", method: "notifications/initialized" });
    await transport.send({ jsonrpc: "2.0", id: "server-discover-probe-1", method: "server/discover" });
    await transport.send({ jsonrpc: "2.0", id: 2, result: {} });
    await transport.terminateSession();

    const posts = requests.filter((request) => request.method === "POST");
    assert.deepEqual(posts.map((request) => request.headers.get("mcp-method")), [
      "initialize", "notifications/initialized", "server/discover", null
    ]);
    assert.ok(posts.every((request) => request.headers.get("x-custom-header") === "kept"));
    assert.equal(posts[2].headers.get("mcp-protocol-version"), "2025-11-25");
    assert.ok(requests.filter((request) => request.method !== "POST")
      .every((request) => request.headers.get("mcp-method") === null));
    assert.deepEqual(responses[1], {
      jsonrpc: "2.0", id: "server-discover-probe-1", result: { servers: [] }
    });
  } finally {
    await transport.close();
  }
});

test("OAuth form POSTs do not receive an MCP method header", async () => {
  let forwarded;
  const wrappedFetch = withMcpMethodHeader(async (_url, init) => {
    forwarded = init;
    return new Response(null, { status: 204 });
  });
  await wrappedFetch("https://portal.example.test/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token" })
  });
  assert.equal(new Headers(forwarded.headers).get("mcp-method"), null);
});
