import { once } from "node:events";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

process.env.MCP_BRIDGE_TEST_MODE = "1";
const { BridgeOAuthProvider, OAuthFlowCoordinator } = await import("../index.js");
const keepAlive = setInterval(() => {}, 1_000);
const provider = new BridgeOAuthProvider({
  url: new URL(process.argv[3]),
  oauth: {
    storagePath: process.argv[2],
    redirectUrl: new URL("http://127.0.0.1:33418/oauth/callback"),
    openBrowser: true,
    browserOpener: async () => { throw new Error("Refresh should not open a browser."); },
    callbackWaiterFactory: async ({ port }) => ({
      port, codePromise: new Promise(() => {}), close: async () => {}
    })
  }
});
const saveTokens = provider.saveTokens.bind(provider);
provider.saveTokens = async (tokens) => {
  // Pause after the server has rotated the token but before it reaches disk.
  process.send({ type: "saving" });
  await once(process, "message");
  await saveTokens(tokens);
};
const coordinator = new OAuthFlowCoordinator(provider);
const transport = new StreamableHTTPClientTransport(provider.config.url, { fetch: coordinator.fetch });
transport.onmessage = () => {};
try {
  await transport.start();
  await transport.send({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  process.send({ type: "ready" });
  await once(process, "message");
  await transport.send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  process.send({ type: "done" });
} finally {
  await coordinator.close();
  await transport.close();
  clearInterval(keepAlive);
  process.disconnect();
}
