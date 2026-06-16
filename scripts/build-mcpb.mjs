import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { platform } from "node:os";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const manifestPath = join(root, "mcpb", "manifest.template.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const version = process.env.MCPB_VERSION || packageJson.version;
applyManifestOverrides(manifest);

const bundledCaPath = resolveOptionalPath(process.env.MCPB_CA_BUNDLE);
if (bundledCaPath) {
  manifest.server.mcp_config.env.NODE_EXTRA_CA_CERTS = "${__dirname}/certs/ca-bundle.pem";
  manifest.server.mcp_config.env.MCP_BRIDGE_CA_BUNDLE = "${__dirname}/certs/ca-bundle.pem";
  delete manifest.user_config.ca_bundle;
}
pruneEmptyUserConfig(manifest);

const bundleName = process.env.MCPB_BUNDLE_FILE || `${manifest.name}-${version}.mcpb`;
const distDir = join(root, "dist");
const stagingDir = join(distDir, "mcpb-stage");
const bundlePath = join(distDir, bundleName);

if (!existsSync(join(root, "node_modules"))) {
  throw new Error("node_modules is missing. Run npm ci --omit=dev before building the MCPB.");
}

manifest.version = version;

await rm(stagingDir, { recursive: true, force: true });
await rm(bundlePath, { force: true });
await mkdir(join(stagingDir, "server"), { recursive: true });
await mkdir(join(stagingDir, "scripts"), { recursive: true });
if (bundledCaPath) {
  await mkdir(join(stagingDir, "certs"), { recursive: true });
}

await writeFile(join(stagingDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
await cp(join(root, "index.js"), join(stagingDir, "server", "index.js"));
await cp(join(root, "scripts", "emulate-mcpb.mjs"), join(stagingDir, "scripts", "emulate-mcpb.mjs"));
await writeFile(join(stagingDir, "package.json"), `${JSON.stringify(packageJsonForBundle(), null, 2)}\n`);
await cp(join(root, "README.md"), join(stagingDir, "README.md"));
if (bundledCaPath) {
  await cp(bundledCaPath, join(stagingDir, "certs", "ca-bundle.pem"));
}
await cp(join(root, "node_modules"), join(stagingDir, "node_modules"), {
  recursive: true,
  dereference: true,
  filter: (source) => !source.split(/[\\/]/).includes(".cache")
});

await zipDirectory(stagingDir, bundlePath);

process.stderr.write(`Created ${bundlePath}\n`);

function zipDirectory(cwd, outputPath) {
  return new Promise((resolveZip, rejectZip) => {
    const [command, args] = archiveCommand(outputPath);
    const child = spawn(command, args, {
      cwd,
      stdio: "inherit"
    });
    child.once("error", rejectZip);
    child.once("exit", (code) => {
      if (code === 0) {
        resolveZip();
        return;
      }
      rejectZip(new Error(`zip exited with code ${code}`));
    });
  });
}

function archiveCommand(outputPath) {
  if (platform() === "win32") {
    return [
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Compress-Archive -Path * -DestinationPath $args[0] -Force",
        outputPath
      ]
    ];
  }

  return ["zip", ["-qr", outputPath, "."]];
}

function applyManifestOverrides(manifest) {
  overrideString(manifest, "name", "MCPB_NAME");
  overrideString(manifest, "display_name", "MCPB_DISPLAY_NAME");
  overrideString(manifest, "description", "MCPB_DESCRIPTION");
  overrideString(manifest, "long_description", "MCPB_LONG_DESCRIPTION");

  const remoteUrl = process.env.MCPB_REMOTE_MCP_URL;
  if (remoteUrl) {
    manifest.server.mcp_config.env.MCP_BRIDGE_URL = remoteUrl;
    delete manifest.user_config.remote_mcp_url;
  }

  const callbackPort = parseNumber(process.env.MCPB_OAUTH_CALLBACK_PORT)
    ?? manifest.user_config.oauth_callback_port.default;
  if (remoteUrl) {
    manifest.server.mcp_config.env.MCP_BRIDGE_OAUTH_CALLBACK_PORT = String(callbackPort);
    delete manifest.user_config.oauth_callback_port;
  } else if (callbackPort) {
    manifest.user_config.oauth_callback_port.default = callbackPort;
  }

  const privacyPolicies = parseList(process.env.MCPB_PRIVACY_POLICIES);
  if (privacyPolicies.length > 0) {
    manifest.privacy_policies = privacyPolicies;
  }

  pruneEmptyUserConfig(manifest);
}

function overrideString(target, field, envName) {
  if (process.env[envName]) {
    target[field] = process.env[envName];
  }
}

function parseNumber(value) {
  if (!value) {
    return undefined;
  }

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${value} is not a valid positive integer`);
  }

  return parsed;
}

function parseList(value) {
  if (!value) {
    return [];
  }

  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function resolveOptionalPath(value) {
  if (!value) {
    return undefined;
  }

  const resolvedPath = resolve(root, value);
  if (!existsSync(resolvedPath)) {
    throw new Error(`MCPB_CA_BUNDLE does not exist: ${resolvedPath}`);
  }

  return resolvedPath;
}

function packageJsonForBundle() {
  return {
    ...packageJson,
    version,
    scripts: {
      start: "node ./server/index.js",
      "emulate:mcpb": "node ./scripts/emulate-mcpb.mjs"
    },
    engines: {
      ...packageJson.engines,
      node: manifest.compatibility.runtimes.node
    }
  };
}

function pruneEmptyUserConfig(manifest) {
  if (manifest.user_config && Object.keys(manifest.user_config).length === 0) {
    delete manifest.user_config;
  }
}
