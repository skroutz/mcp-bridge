process.env.MCP_BRIDGE_TEST_MODE = "1";

const { BridgeOAuthProvider } = await import("../index.js");

const storagePath = process.argv[2];
const keepAlive = setInterval(() => undefined, 1_000);
let callbackResolve;
const callbackPromise = new Promise((resolve) => {
  callbackResolve = resolve;
});
const provider = new BridgeOAuthProvider({
  url: new URL("https://shared.example.test/mcp"),
  oauth: {
    callbackPort: 33418,
    callbackWaiterFactory: async ({ port }) => ({
      cancel: () => callbackResolve(),
      close: async () => undefined,
      codePromise: callbackPromise,
      port
    }),
    redirectUrl: new URL("http://127.0.0.1:33418/oauth/callback"),
    storagePath
  }
});

const owner = await provider.prepareAuthorization();
if (owner) {
  process.send?.({ role: "owner" });
  await new Promise((resolve) => process.once("message", resolve));
  await provider.saveTokens({ access_token: "shared-token", token_type: "Bearer" });
  await provider.releaseAuthorizationOwnership();
} else {
  const tokens = await provider.tokens();
  process.send?.({ accessToken: tokens?.access_token, role: "follower" });
}
clearInterval(keepAlive);
