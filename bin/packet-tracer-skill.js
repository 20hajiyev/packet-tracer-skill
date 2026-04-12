#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawnSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..");

const HOST_PATHS = {
  codex: path.join(os.homedir(), ".codex", "skills", "pkt"),
  claude: path.join(os.homedir(), ".claude", "skills", "pkt"),
  cursor: path.join(os.homedir(), ".cursor", "skills", "pkt"),
  kiro: path.join(os.homedir(), ".kiro", "skills", "pkt"),
  adal: path.join(os.homedir(), ".adal", "skills", "pkt"),
};

const IGNORE_NAMES = new Set([
  ".git",
  ".venv",
  "venv",
  "__pycache__",
  ".pytest_cache",
  "output",
  "node_modules",
]);

const IGNORE_EXTS = new Set([".pyc", ".pyo", ".pkt", ".xml"]);

function printHelp() {
  console.log(`packet-tracer-skill

Install or verify the pkt skill for a local host.

Usage:
  packet-tracer-skill [--codex|--cursor|--claude|--kiro|--adal] [--force]
  packet-tracer-skill --path <dir> [--direct] [--force]
  packet-tracer-skill --verify [--codex|--cursor|--claude|--kiro|--adal]
  packet-tracer-skill --verify --path <dir> [--direct]
  packet-tracer-skill --doctor

Examples:
  packet-tracer-skill
  packet-tracer-skill --cursor
  packet-tracer-skill --claude --force
  packet-tracer-skill --path .agents/skills --force
  packet-tracer-skill --verify --codex
  packet-tracer-skill --verify --path .agents/skills
  packet-tracer-skill --doctor
`);
}

function parseArgs(argv) {
  const args = {
    host: "codex",
    force: false,
    verify: false,
    direct: false,
    doctor: false,
    path: null,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--force") {
      args.force = true;
    } else if (arg === "--verify") {
      args.verify = true;
    } else if (arg === "--direct") {
      args.direct = true;
    } else if (arg === "--doctor") {
      args.doctor = true;
    } else if (arg === "--path") {
      i += 1;
      args.path = argv[i];
    } else if (arg === "--codex") {
      args.host = "codex";
    } else if (arg === "--cursor") {
      args.host = "cursor";
    } else if (arg === "--claude") {
      args.host = "claude";
    } else if (arg === "--kiro") {
      args.host = "kiro";
    } else if (arg === "--adal") {
      args.host = "adal";
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return args;
}

function resolveTarget(args) {
  if (args.path) {
    const base = path.resolve(args.path);
    return args.direct ? base : path.join(base, "pkt");
  }
  return HOST_PATHS[args.host];
}

function shouldIgnore(name) {
  if (IGNORE_NAMES.has(name)) {
    return true;
  }
  return IGNORE_EXTS.has(path.extname(name).toLowerCase());
}

function copyTree(src, dst) {
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (shouldIgnore(entry.name)) {
      continue;
    }
    const srcPath = path.join(src, entry.name);
    const dstPath = path.join(dst, entry.name);
    if (entry.isDirectory()) {
      fs.mkdirSync(dstPath, { recursive: true });
      copyTree(srcPath, dstPath);
    } else {
      fs.mkdirSync(path.dirname(dstPath), { recursive: true });
      fs.copyFileSync(srcPath, dstPath);
    }
  }
}

function verifyInstall(target) {
  const required = [
    "SKILL.md",
    path.join("scripts", "generate_pkt.py"),
    path.join("scripts", "install_skill.py"),
    path.join("scripts", "packet_tracer_env.py"),
  ];
  const missing = required.filter((rel) => !fs.existsSync(path.join(target, rel)));
  return {
    ok: missing.length === 0,
    missing,
    target,
  };
}

function commandExists(command) {
  const probe = process.platform === "win32" ? "where" : "which";
  const result = spawnSync(probe, [command], { stdio: "ignore" });
  return result.status === 0;
}

function envPathStatus(value) {
  if (!value) {
    return { ok: false, message: "not set" };
  }
  if (!fs.existsSync(value)) {
    return { ok: false, message: `set but missing: ${value}` };
  }
  return { ok: true, message: value };
}

function doctor() {
  const checks = [
    ["node", commandExists("node"), commandExists("node") ? "found" : "missing"],
    ["python", commandExists("python"), commandExists("python") ? "found" : "missing"],
  ];

  const root = envPathStatus(process.env.PACKET_TRACER_ROOT);
  const donor = envPathStatus(process.env.PACKET_TRACER_COMPAT_DONOR);
  const twofish = envPathStatus(process.env.PKT_TWOFISH_LIBRARY);

  checks.push(["PACKET_TRACER_ROOT", root.ok, root.message]);
  checks.push(["PACKET_TRACER_COMPAT_DONOR", donor.ok, donor.message]);
  checks.push(["PKT_TWOFISH_LIBRARY", twofish.ok, twofish.message]);

  for (const [name, ok, detail] of checks) {
    console.log(`${ok ? "OK" : "MISSING"}  ${name}  ${detail}`);
  }

  const failed = checks.some(([, ok]) => !ok);
  if (failed) {
    console.error("\nRuntime is not fully ready. Install copies are fine, but Packet Tracer generation still needs the missing items above.");
    process.exit(1);
  }

  console.log("\nRuntime looks ready.");
  process.exit(0);
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
      printHelp();
      process.exit(0);
    }

    if (args.doctor) {
      doctor();
    }

    const target = resolveTarget(args);

    if (args.verify) {
      const result = verifyInstall(target);
      if (!result.ok) {
        console.error(`Install verification failed: ${result.target}`);
        for (const missing of result.missing) {
          console.error(`  missing: ${missing}`);
        }
        process.exit(1);
      }
      console.log(`Install verified: ${result.target}`);
      process.exit(0);
    }

    if (fs.existsSync(target)) {
      if (!args.force) {
        throw new Error(`Target already exists: ${target}. Use --force to replace it.`);
      }
      fs.rmSync(target, { recursive: true, force: true });
    }

    fs.mkdirSync(target, { recursive: true });
    copyTree(REPO_ROOT, target);

    const result = verifyInstall(target);
    if (!result.ok) {
      throw new Error(`Install completed but verification failed: ${result.missing.join(", ")}`);
    }

    console.log(`Installed: ${target}`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

main();
