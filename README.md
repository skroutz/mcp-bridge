# MCP Bridge

`mcp-bridge` is a small local proxy that lets Claude Desktop speak MCP over local stdio while the real MCP server runs behind a secure Streamable-HTTP endpoint.

```text
Claude Desktop <-> local stdio <-> mcp-bridge <-> HTTPS Streamable HTTP <-> remote MCP server
```

The bridge intentionally uses only the official `@modelcontextprotocol/sdk` runtime transports for MCP framing, Streamable-HTTP behavior, and OAuth client flows. The local code validates configuration, attaches authentication headers when configured, handles OAuth browser login when enabled, forwards JSON-RPC messages, and cleans up remote sessions on termination.

## Requirements

- Node.js 24 or newer on macOS, Windows, or Linux.
- A reachable Streamable-HTTP MCP endpoint, for example `https://mcp.example.com/mcp`.
- On Linux, a URL opener for OAuth browser login. The bridge honors the `BROWSER` environment variable and otherwise tries common openers in order.
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

Linux path:

```text
~/.config/Claude/claude_desktop_config.json
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

## Claude MCPB Extension

This repository can also produce a Claude Desktop MCPB extension for organization-wide distribution. The bundle vendors the bridge code and `node_modules` into a single `.mcpb` zip archive, so users do not need to install Node dependencies or edit `claude_desktop_config.json` manually.

The committed MCPB manifest is a public-safe template. Do not commit generated organization-specific `.mcpb` files or manifests with internal endpoints.

Build the bundle from a clean checkout:

```bash
npm ci --omit=dev
npm run build:mcpb
```

The generated file is written to `dist/skroutz-mcp-bridge-<version>.mcpb`.

The MCPB template lives at `mcpb/manifest.template.json`. It configures Claude Desktop to run the bundled bridge with:

- `MCP_BRIDGE_URL` from the extension's Remote MCP URL setting.
- `MCP_BRIDGE_OAUTH=true` so the remote server's OAuth/DCR browser flow is used.
- `MCP_BRIDGE_OAUTH_CALLBACK_PORT` from the extension's OAuth callback port setting.
- Optional `NODE_EXTRA_CA_CERTS` and `MCP_BRIDGE_CA_BUNDLE` from either a bundled CA certificate or the extension's Internal CA certificate file setting.

Build an organization-specific artifact by passing release-time environment variables. The generated artifact remains ignored by git:

```bash
MCPB_NAME="your-org-mcp" \
MCPB_DISPLAY_NAME="Your Org MCP" \
MCPB_REMOTE_MCP_URL="https://mcp.example.com/mcp" \
MCPB_PRIVACY_POLICIES="https://example.com/privacy" \
npm run build:mcpb
```

When `MCPB_REMOTE_MCP_URL` is set, the generated manifest bakes the URL and OAuth callback port directly into the private artifact instead of asking each user to configure them during installation. Override the fixed callback port with `MCPB_OAUTH_CALLBACK_PORT` if needed.

The npm/npx package and MCPB extension require Node.js 24 or newer.

If Claude needs a corporate TLS proxy CA to reach the remote MCP server, keep the PEM file outside git and bundle it only into the generated `.mcpb`:

```bash
MCPB_CA_BUNDLE="./company-ca.pem" \
npm run build:mcpb
```

When `MCPB_CA_BUNDLE` is set, the build copies the PEM to `certs/ca-bundle.pem` inside the ignored `.mcpb` artifact and sets both `NODE_EXTRA_CA_CERTS=${__dirname}/certs/ca-bundle.pem` and `MCP_BRIDGE_CA_BUNDLE=${__dirname}/certs/ca-bundle.pem` in the generated manifest. `MCP_BRIDGE_CA_BUNDLE` is read by the bridge itself, so TLS trust does not depend only on Claude Desktop honoring Node's startup CA environment variable. Do not use this for private keys or client certificates.

For Claude.ai organization settings, upload the generated `.mcpb` as a local MCP extension. Users should then see the configured local MCP server in Claude Desktop without pasting JSON. On first use, the bridge will start the remote OAuth flow and cache the resulting client registration and tokens in the user's OS config directory.

Before uploading a new MCPB release:

```bash
npm run check
npm run pack:dry-run
npm run build:mcpb
unzip -l dist/skroutz-mcp-bridge-$(node -p "require('./package.json').version").mcpb | head -50
```

To debug the exact MCPB launch path from Terminal, run the emulator against either a `.mcpb` file or Claude's already-unpacked extension directory:

```bash
npm run emulate:mcpb -- --mcpb dist/skroutz-mcp-bridge-0.1.0.mcpb --clean-env
```

```bash
npm run emulate:mcpb -- --mcpb "/path/to/unpacked/extension-directory" --clean-env
```

The emulator reads `manifest.json`, resolves `${__dirname}`, starts the configured Node server with the manifest environment, sends a Claude-style `initialize` request, and writes captured output to `dist/mcpb-emulate.stdout` and `dist/mcpb-emulate.stderr`.

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
| `MCP_BRIDGE_CA_BUNDLE` | Optional PEM CA bundle read directly by the bridge HTTP client for MCP and OAuth requests. |
| `MCP_BRIDGE_ALLOW_HTTP` | Set to `true` only for local development endpoints. |
| `MCP_BRIDGE_TIMEOUT_MS` | Optional fetch timeout. Disabled by default because MCP responses may stream. |
| `MCP_BRIDGE_MAX_BUFFER_SIZE` | Optional local stdio read buffer size in bytes. Default: `10485760`. |
| `NODE_EXTRA_CA_CERTS` | Node.js TLS option for adding an internal CA bundle. MCPB builds also set `MCP_BRIDGE_CA_BUNDLE` so the bridge can load the PEM itself. |

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
  "caBundle": "/absolute/path/to/company-ca.pem",
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
npm run build:mcpb
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
   npm run build:mcpb
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
   - The generated `.mcpb` artifact from `dist/`.
   - Supported Node.js version.
   - Configuration changes.
   - Security notes and dependency version.

6. Upload the `.mcpb` artifact to Claude.ai organization settings for managed local-MCP distribution.

7. Smoke-test the release tag on macOS, Windows, and Linux:

   ```bash
   npx -y github:skroutz/mcp-bridge#v0.1.1 --help
   ```

8. Optional npm publication:

   ```bash
   npm publish --provenance
   ```
