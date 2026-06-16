# MCP Bridge

`mcp-bridge` is a small local proxy that lets Claude Desktop speak MCP over local stdio while the real MCP server runs behind a secure Streamable-HTTP endpoint.

```text
Claude Desktop <-> local stdio <-> mcp-bridge <-> HTTPS Streamable HTTP <-> remote MCP server
```

The bridge intentionally uses only the official `@modelcontextprotocol/sdk` runtime transports for MCP framing and Streamable-HTTP behavior. The local code validates configuration, attaches authentication headers, forwards JSON-RPC messages, and cleans up remote sessions on termination.

## Requirements

- Node.js 20.11 or newer on macOS or Windows.
- A reachable Streamable-HTTP MCP endpoint, for example `https://mcp.example.com/mcp`.
- Optional bearer token, API key, or static headers required by your firewalled endpoint.

## Run With npx

From a public GitHub repository tag:

```bash
npx -y github:skroutz/mcp-bridge#v0.1.0 --url https://mcp.example.com/mcp
```

After publishing to npm:

```bash
npx -y mcp-bridge --url https://mcp.example.com/mcp
```

For secrets, prefer environment variables or a config file over command-line flags because command-line arguments may be visible in process listings.

## Claude Desktop Configuration

Claude Desktop starts MCP servers from its `claude_desktop_config.json`.

macOS path:

```text
~/Library/Application Support/Claude/claude_desktop_config.json
```

Windows path:

```text
%APPDATA%\Claude\claude_desktop_config.json
```

GitHub-backed `npx` configuration:

```json
{
  "mcpServers": {
    "secure-remote": {
      "command": "npx",
      "args": [
        "-y",
        "github:skroutz/mcp-bridge#v0.1.0"
      ],
      "env": {
        "MCP_BRIDGE_URL": "https://mcp.example.com/mcp",
        "MCP_BRIDGE_BEARER_TOKEN": "replace-with-token"
      }
    }
  }
}
```

On Windows, if Claude cannot resolve `npx` directly, run `where npx` in Command Prompt and set `command` to the full `npx.cmd` path.

## Configuration

Environment variables:

| Variable | Description |
| --- | --- |
| `MCP_BRIDGE_URL` | Required remote Streamable-HTTP MCP endpoint. Must be HTTPS unless `MCP_BRIDGE_ALLOW_HTTP=true`. |
| `MCP_BRIDGE_BEARER_TOKEN` | Optional bearer token sent as `Authorization: Bearer <token>`. |
| `MCP_BRIDGE_API_KEY` | Optional API key sent as `X-API-Key`. |
| `MCP_BRIDGE_HEADERS` | Optional JSON object of additional HTTP headers. |
| `MCP_BRIDGE_CONFIG` | Optional JSON config file path. Supports `~` and relative paths. |
| `MCP_BRIDGE_ALLOW_HTTP` | Set to `true` only for local development endpoints. |
| `MCP_BRIDGE_TIMEOUT_MS` | Optional fetch timeout. Disabled by default because MCP responses may stream. |
| `MCP_BRIDGE_MAX_BUFFER_SIZE` | Optional local stdio read buffer size in bytes. Default: `10485760`. |

CLI flags:

```bash
mcp-bridge \
  --url https://mcp.example.com/mcp \
  --bearer-token "$MCP_TOKEN" \
  --header "X-Tenant:tenant-a"
```

Config file:

```json
{
  "url": "https://mcp.example.com/mcp",
  "bearerToken": "replace-with-token",
  "apiKey": "replace-with-key",
  "headers": {
    "X-Tenant": "tenant-a"
  },
  "timeoutMs": 120000,
  "maxBufferSize": 10485760
}
```

Precedence is config file, then environment variables, then CLI flags.

## Security Notes

- HTTPS is required by default.
- stdout is reserved for MCP messages; logs are written to stderr.
- Secrets are redacted from bridge logs.
- Credentials embedded in endpoint URLs are rejected. Use environment variables or a config file instead.
- Headers controlled by the Streamable-HTTP transport, such as `content-type`, `accept`, `mcp-session-id`, and `mcp-protocol-version`, cannot be overridden.
- The bridge sends a Streamable-HTTP session termination request during normal shutdown when the remote server provided a session ID.

## Local Development

```bash
npm install
npm run check
npm run pack:dry-run
```

Run against a local development MCP server:

```bash
MCP_BRIDGE_ALLOW_HTTP=true MCP_BRIDGE_URL=http://127.0.0.1:3000/mcp npm start
```

## GitHub Release Orchestration

1. Keep `main` passing locally:

   ```bash
   npm ci
   npm run check
   npm run pack:dry-run
   ```

2. Update `package.json` version:

   ```bash
   npm version patch --no-git-tag-version
   ```

3. Commit the release version:

   ```bash
   git add package.json package-lock.json
   git commit -m "Release v0.1.1"
   ```

4. Create and push a signed tag:

   ```bash
   git tag -s v0.1.1 -m "v0.1.1"
   git push origin main v0.1.1
   ```

5. Create a GitHub release from the tag. Include:

   - The exact `npx -y github:skroutz/mcp-bridge#v0.1.1` command.
   - Supported Node.js version.
   - Configuration changes.
   - Security notes and dependency version.

6. Smoke-test the release tag on macOS and Windows:

   ```bash
   npx -y github:skroutz/mcp-bridge#v0.1.1 --help
   ```

7. Optional npm publication:

   ```bash
   npm publish --provenance
   ```
