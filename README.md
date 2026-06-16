# MCP Bridge

`mcp-bridge` is a small local proxy that lets Claude Desktop speak MCP over local stdio while the real MCP server runs behind a secure Streamable-HTTP endpoint.

```text
Claude Desktop <-> local stdio <-> mcp-bridge <-> HTTPS Streamable HTTP <-> remote MCP server
```

The bridge intentionally uses only the official `@modelcontextprotocol/sdk` runtime transports for MCP framing, Streamable-HTTP behavior, and OAuth client flows. The local code validates configuration, attaches authentication headers when configured, handles OAuth browser login when enabled, forwards JSON-RPC messages, and cleans up remote sessions on termination.

## Requirements

- Node.js 20.11 or newer on macOS or Windows.
- A reachable Streamable-HTTP MCP endpoint, for example `https://mcp.example.com/mcp`.
- Optional OAuth 2.1/DCR browser login, bearer token, API key, or static headers required by your firewalled endpoint.

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

OAuth-backed configuration:

```json
{
  "mcpServers": {
    "skroutz-mcp": {
      "command": "npx",
      "args": [
        "-y",
        "github:skroutz/mcp-bridge#main"
      ],
      "env": {
        "MCP_BRIDGE_URL": "https://mcp.example.com/mcp",
        "MCP_BRIDGE_OAUTH": "true"
      }
    }
  }
}
```

On Windows, if Claude cannot resolve `npx` directly, run `where npx` in Command Prompt and set `command` to the full `npx.cmd` path.

## OAuth Login

For OAuth-protected remote MCP servers, run a one-time login before starting Claude Desktop. This avoids Claude timing out while the first MCP `initialize` request waits for browser authorization.

```bash
npx -y github:skroutz/mcp-bridge#main \
  --oauth-login \
  --url https://mcp.example.com/mcp
```

Login-only OAuth HTTP requests use a default 30 second timeout so a broken endpoint cannot hang forever. Override it while debugging with `--timeout-ms`, for example `--timeout-ms 10000`.

The bridge will:

- Discover OAuth metadata from the remote MCP server or protected-resource challenge.
- Dynamically register a public client when the authorization server supports DCR.
- Open the system browser for interactive login.
- Receive the authorization callback on `http://127.0.0.1:33418/oauth/callback`.
- Store OAuth client information and tokens in the user config directory.

After login completes, restart Claude Desktop with `MCP_BRIDGE_OAUTH=true` in the server config.

If the callback port is already in use, set the same explicit port in both the login command and Claude config:

```bash
npx -y github:skroutz/mcp-bridge#main \
  --oauth-login \
  --url https://mcp.example.com/mcp \
  --oauth-callback-port 33419
```

```json
{
  "mcpServers": {
    "skroutz-mcp": {
      "command": "npx",
      "args": [
        "-y",
        "github:skroutz/mcp-bridge#main"
      ],
      "env": {
        "MCP_BRIDGE_URL": "https://mcp.example.com/mcp",
        "MCP_BRIDGE_OAUTH": "true",
        "MCP_BRIDGE_OAUTH_CALLBACK_PORT": "33419"
      }
    }
  }
}
```

If your company endpoint uses an internal CA, add the same CA bundle to both the one-time login command and Claude Desktop config. Prefer this over disabling TLS verification:

```bash
NODE_EXTRA_CA_CERTS=/absolute/path/to/company-ca.pem \
npx -y github:skroutz/mcp-bridge#main \
  --oauth-login \
  --url https://mcp.example.com/mcp
```

```json
{
  "mcpServers": {
    "skroutz-mcp": {
      "command": "npx",
      "args": [
        "-y",
        "github:skroutz/mcp-bridge#main"
      ],
      "env": {
        "MCP_BRIDGE_URL": "https://mcp.example.com/mcp",
        "MCP_BRIDGE_OAUTH": "true",
        "NODE_EXTRA_CA_CERTS": "/absolute/path/to/company-ca.pem"
      }
    }
  }
}
```

## Configuration

Environment variables:

| Variable | Description |
| --- | --- |
| `MCP_BRIDGE_URL` | Required remote Streamable-HTTP MCP endpoint. Must be HTTPS unless `MCP_BRIDGE_ALLOW_HTTP=true`. |
| `MCP_BRIDGE_BEARER_TOKEN` | Optional bearer token sent as `Authorization: Bearer <token>`. |
| `MCP_BRIDGE_API_KEY` | Optional API key sent as `X-API-Key`. |
| `MCP_BRIDGE_HEADERS` | Optional JSON object of additional HTTP headers. |
| `MCP_BRIDGE_CONFIG` | Optional JSON config file path. Supports `~` and relative paths. |
| `MCP_BRIDGE_OAUTH` | Set to `true` to enable OAuth 2.1/DCR browser login for the remote endpoint. |
| `MCP_BRIDGE_OAUTH_LOGIN` | Set to `true` to run login only, cache credentials, then exit. Equivalent to `--oauth-login`. |
| `MCP_BRIDGE_OAUTH_CALLBACK_PORT` | Optional loopback callback port. Default: `33418`. |
| `MCP_BRIDGE_OAUTH_STORAGE` | Optional OAuth cache file path. Defaults to the user config directory. |
| `MCP_BRIDGE_OAUTH_SCOPE` | Optional OAuth scope override. |
| `MCP_BRIDGE_OAUTH_OPEN_BROWSER` | Set to `false` for headless login/debugging. The authorization URL is still written to stderr. |
| `MCP_BRIDGE_ALLOW_HTTP` | Set to `true` only for local development endpoints. |
| `MCP_BRIDGE_TIMEOUT_MS` | Optional fetch timeout. Disabled by default because MCP responses may stream. |
| `MCP_BRIDGE_MAX_BUFFER_SIZE` | Optional local stdio read buffer size in bytes. Default: `10485760`. |
| `NODE_EXTRA_CA_CERTS` | Node.js TLS option for adding an internal CA bundle. Useful when Claude launches the bridge outside your shell environment. |

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
  "oauth": false,
  "oauthCallbackPort": 33418,
  "oauthOpenBrowser": true,
  "timeoutMs": 120000,
  "maxBufferSize": 10485760
}
```

Precedence is config file, then environment variables, then CLI flags.

## Security Notes

- HTTPS is required by default.
- stdout is reserved for MCP messages; logs are written to stderr.
- Secrets are redacted from bridge logs.
- OAuth token/client-registration cache files are stored outside the repository in the user config directory with private file permissions where supported by the OS.
- Credentials embedded in endpoint URLs are rejected. Use environment variables or a config file instead.
- Static bearer/API-key auth and OAuth browser auth are mutually exclusive modes.
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
