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
  packet-tracer-skill --bootstrap [--dev] [--codex|--cursor|--claude|--kiro|--adal]
  packet-tracer-skill --bootstrap [--dev] --path <dir> [--direct]
  packet-tracer-skill --doctor

Examples:
  packet-tracer-skill
  packet-tracer-skill --cursor
  packet-tracer-skill --claude --force
  packet-tracer-skill --path .agents/skills --force
  packet-tracer-skill --verify --codex
  packet-tracer-skill --verify --path .agents/skills
  packet-tracer-skill --bootstrap --cursor
  packet-tracer-skill --bootstrap --dev --path .agents/skills
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
    bootstrap: false,
    dev: false,
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
    } else if (arg === "--bootstrap") {
      args.bootstrap = true;
    } else if (arg === "--dev") {
      args.dev = true;
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
    path.join("scripts", "donor_diagnostics.py"),
    path.join("scripts", "install_skill.py"),
    path.join("scripts", "packet_tracer_env.py"),
    path.join("scripts", "runtime_doctor.py"),
    path.join("scripts", "twofish_diagnostics.py"),
  ];
  const missing = required.filter((rel) => !fs.existsSync(path.join(target, rel)));
  return {
    ok: missing.length === 0,
    missing,
    target,
  };
}

function commandExists(command) {
  if (path.isAbsolute(command) || command.includes(path.sep)) {
    return fs.existsSync(command);
  }
  const probe = process.platform === "win32" ? "where" : "which";
  const result = spawnSync(probe, [command], { stdio: "ignore" });
  return result.status === 0;
}

function preferredPythonCommand() {
  const candidates = [
    process.env.PACKET_TRACER_SKILL_PYTHON,
    process.env.PYTHON,
    process.platform === "win32" ? path.join("C:\\", "Python314", "python.exe") : "",
    "python",
    "py",
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (commandExists(candidate)) {
      return candidate;
    }
  }
  return null;
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

function packetTracerVersionDiagnostics() {
  const pythonCommand = preferredPythonCommand();
  if (!pythonCommand) {
    return {
      targetVersion: process.env.PACKET_TRACER_TARGET_VERSION || "9.0.0.0810",
      donorPath: process.env.PACKET_TRACER_COMPAT_DONOR || "",
      donorVersion: "",
      donorSource: "",
      status: "python_missing",
      message: "python was not found in PATH",
      blockingReason: "python was not found in PATH",
      candidatePaths: [],
    };
  }

  const diagnosticsScript = path.join(REPO_ROOT, "scripts", "donor_diagnostics.py");
  const args = pythonCommand === "py" ? ["-3", diagnosticsScript] : [diagnosticsScript];
  const result = runCaptured(pythonCommand, args);
  if (result.error) {
    const donorPath = process.env.PACKET_TRACER_COMPAT_DONOR || "";
    if (!donorPath) {
      return {
        targetVersion: process.env.PACKET_TRACER_TARGET_VERSION || "9.0.0.0810",
        donorPath: "",
        donorVersion: "",
        donorSource: "",
        status: "not_set",
        message: "not set",
        blockingReason: "not set",
        candidatePaths: [],
      };
    }
    if (!fs.existsSync(donorPath)) {
      return {
        targetVersion: process.env.PACKET_TRACER_TARGET_VERSION || "9.0.0.0810",
        donorPath,
        donorVersion: "",
        donorSource: "env",
        status: "missing",
        message: `set but missing: ${donorPath}`,
        blockingReason: `set but missing: ${donorPath}`,
        candidatePaths: [],
      };
    }
    return {
      targetVersion: process.env.PACKET_TRACER_TARGET_VERSION || "9.0.0.0810",
      donorPath,
      donorVersion: "",
      donorSource: "env",
      status: "inspection_blocked",
      message: `set, but donor version inspection is blocked in this host wrapper: ${result.error.message}`,
      blockingReason: `set, but donor version inspection is blocked in this host wrapper: ${result.error.message}`,
      candidatePaths: [],
    };
  }
  if (result.status !== 0) {
    const detail =
      (result.stderr || result.stdout || "").trim().split(/\r?\n/).filter(Boolean).pop() ||
      `exit code ${result.status}`;
    return {
      targetVersion: process.env.PACKET_TRACER_TARGET_VERSION || "9.0.0.0810",
      donorPath: process.env.PACKET_TRACER_COMPAT_DONOR || "",
      donorVersion: "",
      donorSource: process.env.PACKET_TRACER_COMPAT_DONOR ? "env" : "",
      status: "decode_error",
      message: detail,
      blockingReason: detail,
      candidatePaths: [],
    };
  }

  try {
    const parsed = JSON.parse((result.stdout || "").trim() || "{}");
    return {
      targetVersion: parsed.target_version || process.env.PACKET_TRACER_TARGET_VERSION || "9.0.0.0810",
      donorPath: parsed.resolved_donor_path || parsed.donor_path || process.env.PACKET_TRACER_COMPAT_DONOR || "",
      donorVersion: parsed.donor_version || "",
      donorSource: parsed.donor_source || "",
      status: parsed.status || "decode_error",
      message: parsed.message || "unknown error",
      blockingReason: parsed.blocking_reason || parsed.message || "unknown error",
      candidatePaths: parsed.candidate_paths || [],
    };
  } catch (error) {
    return {
      targetVersion: process.env.PACKET_TRACER_TARGET_VERSION || "9.0.0.0810",
      donorPath: process.env.PACKET_TRACER_COMPAT_DONOR || "",
      donorVersion: "",
      donorSource: process.env.PACKET_TRACER_COMPAT_DONOR ? "env" : "",
      status: "decode_error",
      message: error.message,
      blockingReason: error.message,
      candidatePaths: [],
    };
  }
}

function twofishDiagnostics() {
  const pythonCommand = preferredPythonCommand();
  if (!pythonCommand) {
    return {
      pythonVersion: "",
      pythonSupportStatus: "missing",
      pythonSupportMessage: "python was not found in PATH",
      expectedTwofishPatterns: [],
      twofishSearchRoots: [],
      resolvedTwofishPath: "",
      twofishSource: "",
      twofishLoadStatus: "python_missing",
      twofishMessage: "python was not found in PATH",
      twofishSha256: "",
    };
  }

  const diagnosticsScript = path.join(REPO_ROOT, "scripts", "twofish_diagnostics.py");
  const args = pythonCommand === "py" ? ["-3", diagnosticsScript] : [diagnosticsScript];
  const result = runCaptured(pythonCommand, args);
  if (result.error) {
    const envPath = process.env.PKT_TWOFISH_LIBRARY || "";
    const envExists = envPath !== "" && fs.existsSync(envPath);
    return {
      pythonVersion: "",
      pythonSupportStatus: "unknown",
      pythonSupportMessage: `inspection blocked in this host wrapper: ${result.error.message}`,
      expectedTwofishPatterns: [],
      twofishSearchRoots: [],
      resolvedTwofishPath: envPath,
      twofishSource: envPath ? "env" : "",
      twofishLoadStatus: envExists ? "inspection_blocked" : "missing",
      twofishMessage: envExists
        ? `set, but load inspection is blocked in this host wrapper: ${result.error.message}`
        : envPath
          ? `set but missing: ${envPath}`
          : "not set and sibling inspection is blocked in this host wrapper",
      twofishSha256: "",
    };
  }
  if (result.status !== 0) {
    const detail =
      (result.stderr || result.stdout || "").trim().split(/\r?\n/).filter(Boolean).pop() ||
      `exit code ${result.status}`;
    return {
      pythonVersion: "",
      pythonSupportStatus: "unknown",
      pythonSupportMessage: detail,
      expectedTwofishPatterns: [],
      twofishSearchRoots: [],
      resolvedTwofishPath: process.env.PKT_TWOFISH_LIBRARY || "",
      twofishSource: process.env.PKT_TWOFISH_LIBRARY ? "env" : "",
      twofishLoadStatus: "load_error",
      twofishMessage: detail,
      twofishSha256: "",
    };
  }

  try {
    const parsed = JSON.parse((result.stdout || "").trim() || "{}");
    return {
      pythonVersion: parsed.python_version || "",
      pythonSupportStatus: parsed.python_support_status || "unknown",
      pythonSupportMessage: parsed.python_support_message || "unknown",
      expectedTwofishPatterns: parsed.expected_twofish_patterns || [],
      twofishSearchRoots: parsed.twofish_search_roots || [],
      resolvedTwofishPath: parsed.resolved_twofish_path || "",
      twofishSource: parsed.twofish_source || "",
      twofishLoadStatus: parsed.twofish_load_status || "unknown",
      twofishMessage: parsed.twofish_message || "unknown",
      twofishSha256: parsed.twofish_sha256 || "",
    };
  } catch (error) {
    return {
      pythonVersion: "",
      pythonSupportStatus: "unknown",
      pythonSupportMessage: error.message,
      expectedTwofishPatterns: [],
      twofishSearchRoots: [],
      resolvedTwofishPath: process.env.PKT_TWOFISH_LIBRARY || "",
      twofishSource: process.env.PKT_TWOFISH_LIBRARY ? "env" : "",
      twofishLoadStatus: "load_error",
      twofishMessage: error.message,
      twofishSha256: "",
    };
  }
}

function runtimeDoctorDiagnostics() {
  const pythonCommand = preferredPythonCommand();
  if (!pythonCommand) {
    return {
      available: false,
      error: "python_missing",
      hostOs: process.platform,
      installerSupport: { status: "supported", message: "supported" },
      realPktRuntimeSupport: {
        status: "windows_first",
        message: "python was not found in PATH",
      },
      envExamples: [],
      detectedLayoutType: "missing",
      recommendedPacketTracerRoot: "",
      recommendedPacketTracerSavesRoot: "",
      pythonVersion: "",
      pythonSupportStatus: "missing",
      pythonSupportMessage: "python was not found in PATH",
      expectedTwofishPatterns: [],
      twofishSearchRoots: [],
      packetTracerRoot: process.env.PACKET_TRACER_ROOT || "",
      packetTracerSavesRoot: "",
      packetTracerExe: "",
      resolvedTwofishPath: process.env.PKT_TWOFISH_LIBRARY || "",
      twofishSource: process.env.PKT_TWOFISH_LIBRARY ? "env" : "",
      twofishLoadStatus: "python_missing",
      twofishMessage: "python was not found in PATH",
      twofishSha256: "",
      targetVersion: process.env.PACKET_TRACER_TARGET_VERSION || "9.0.0.0810",
      resolvedDonorPath: process.env.PACKET_TRACER_COMPAT_DONOR || "",
      donorVersion: "",
      donorSource: process.env.PACKET_TRACER_COMPAT_DONOR ? "env" : "",
      donorStatus: process.env.PACKET_TRACER_COMPAT_DONOR ? "unknown" : "missing",
      donorMessage: process.env.PACKET_TRACER_COMPAT_DONOR ? "python missing" : "not set",
      donorBlockingReason: "python was not found in PATH",
      donorCandidates: [],
      blockingReason: "python was not found in PATH",
    };
  }

  const diagnosticsScript = path.join(REPO_ROOT, "scripts", "runtime_doctor.py");
  const args = pythonCommand === "py" ? ["-3", diagnosticsScript] : [diagnosticsScript];
  const result = runCaptured(pythonCommand, args);
  if (result.error || result.status !== 0) {
    return {
      available: false,
      error: result.error ? result.error.message : `exit code ${result.status}`,
    };
  }

  try {
    const parsed = JSON.parse((result.stdout || "").trim() || "{}");
    return {
      available: true,
      hostOs: parsed.host_os || process.platform,
      installerSupport: parsed.installer_support || { status: "unknown", message: "unknown" },
      realPktRuntimeSupport: parsed.real_pkt_runtime_support || { status: "unknown", message: "unknown" },
      envExamples: parsed.env_examples || [],
      detectedLayoutType: parsed.detected_layout_type || "unknown",
      recommendedPacketTracerRoot: parsed.recommended_packet_tracer_root || "",
      recommendedPacketTracerSavesRoot: parsed.recommended_packet_tracer_saves_root || "",
      recommendedNextSteps: parsed.recommended_next_steps || [],
      packetTracerRoot: parsed.packet_tracer_root || process.env.PACKET_TRACER_ROOT || "",
      packetTracerSavesRoot: parsed.packet_tracer_saves_root || "",
      packetTracerExe: parsed.packet_tracer_exe || "",
      pythonVersion: parsed.python_version || "",
      pythonSupportStatus: parsed.python_support_status || "unknown",
      pythonSupportMessage: parsed.python_support_message || "unknown",
      expectedTwofishPatterns: parsed.expected_twofish_patterns || [],
      twofishSearchRoots: parsed.twofish_search_roots || [],
      resolvedTwofishPath: parsed.resolved_twofish_path || "",
      twofishSource: parsed.twofish_source || "",
      twofishLoadStatus: parsed.twofish_load_status || "unknown",
      twofishMessage: parsed.twofish_message || "unknown",
      twofishSha256: parsed.twofish_sha256 || "",
      targetVersion: parsed.target_version || process.env.PACKET_TRACER_TARGET_VERSION || "9.0.0.0810",
      resolvedDonorPath: parsed.resolved_donor_path || process.env.PACKET_TRACER_COMPAT_DONOR || "",
      donorVersion: parsed.donor_version || "",
      donorSource: parsed.donor_source || "",
      donorStatus: parsed.donor_status || "unknown",
      donorMessage: parsed.donor_message || "unknown",
      donorBlockingReason: parsed.donor_blocking_reason || "",
      donorCandidates: parsed.donor_candidates || [],
      blockingReason: parsed.blocking_reason || "",
    };
  } catch (error) {
    return {
      available: false,
      error: error.message,
    };
  }
}

function requirementLines(requirementsPath) {
  if (!fs.existsSync(requirementsPath)) {
    return [];
  }
  return fs
    .readFileSync(requirementsPath, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}

function runOrThrow(command, args, options = {}) {
  const result = spawnSync(command, args, {
    stdio: "inherit",
    shell: false,
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}`);
  }
}

function runCaptured(command, args, options = {}) {
  return spawnSync(command, args, {
    stdio: "pipe",
    encoding: "utf8",
    shell: false,
    ...options,
  });
}

function firstAvailableCommand(candidates) {
  for (const candidate of candidates) {
    if (commandExists(candidate)) {
      return candidate;
    }
  }
  return null;
}

function bootstrapEnvironment(target, includeDev) {
  const pythonCommand = preferredPythonCommand();
  if (!pythonCommand) {
    return {
      ok: false,
      message: "python was not found in PATH",
      venvDir: path.join(target, ".venv"),
      runtimeRequirements: [],
      devRequirements: [],
    };
  }

  const venvDir = path.join(target, ".venv");
  const pythonExe =
    process.platform === "win32"
      ? path.join(venvDir, "Scripts", "python.exe")
      : path.join(venvDir, "bin", "python");

  const runtimeRequirements = requirementLines(path.join(target, "requirements.txt"));
  const devRequirements = requirementLines(path.join(target, "requirements-dev.txt"));
  try {
    const venvArgs = pythonCommand === "py" ? ["-3", "-m", "venv", venvDir] : ["-m", "venv", venvDir];
    const venvResult = runCaptured(pythonCommand, venvArgs);
    if (venvResult.status !== 0) {
      const detail = (venvResult.stderr || venvResult.stdout || "").trim().split(/\r?\n/).filter(Boolean).pop() || `exit code ${venvResult.status}`;
      throw new Error(`${pythonCommand} ${venvArgs.join(" ")} failed: ${detail}`);
    }

    if (runtimeRequirements.length > 0) {
      const runtimeResult = runCaptured(pythonExe, ["-m", "pip", "install", "-r", path.join(target, "requirements.txt")]);
      if (runtimeResult.status !== 0) {
        const detail = (runtimeResult.stderr || runtimeResult.stdout || "").trim().split(/\r?\n/).filter(Boolean).pop() || `exit code ${runtimeResult.status}`;
        throw new Error(`${pythonExe} -m pip install -r requirements.txt failed: ${detail}`);
      }
    }

    if (includeDev && devRequirements.length > 0) {
      const devResult = runCaptured(pythonExe, ["-m", "pip", "install", "-r", path.join(target, "requirements-dev.txt")]);
      if (devResult.status !== 0) {
        const detail = (devResult.stderr || devResult.stdout || "").trim().split(/\r?\n/).filter(Boolean).pop() || `exit code ${devResult.status}`;
        throw new Error(`${pythonExe} -m pip install -r requirements-dev.txt failed: ${detail}`);
      }
    }
  } catch (error) {
    return {
      ok: false,
      message: error.message,
      venvDir,
      runtimeRequirements,
      devRequirements,
    };
  }

  return {
    ok: true,
    message: "venv created",
    venvDir,
    runtimeRequirements,
    devRequirements,
  };
}

function doctorChecks() {
  const nodeOk = commandExists("node");
  const pythonOk = commandExists("python");
  const checks = [
    ["node", nodeOk, nodeOk ? "found" : "missing"],
    ["python", pythonOk, pythonOk ? "found" : "missing"],
  ];
  const runtimeDoctor = runtimeDoctorDiagnostics();
  const donorDiagnostics = runtimeDoctor.available
    ? {
        targetVersion: runtimeDoctor.targetVersion,
        donorPath: runtimeDoctor.resolvedDonorPath,
        donorVersion: runtimeDoctor.donorVersion,
        donorSource: runtimeDoctor.donorSource,
        status: runtimeDoctor.donorStatus,
        message: runtimeDoctor.donorMessage,
        blockingReason: runtimeDoctor.donorBlockingReason,
        candidatePaths: runtimeDoctor.donorCandidates,
      }
    : packetTracerVersionDiagnostics();
  const twofish = runtimeDoctor.available
    ? {
        pythonVersion: runtimeDoctor.pythonVersion,
      pythonSupportStatus: runtimeDoctor.pythonSupportStatus,
      pythonSupportMessage: runtimeDoctor.pythonSupportMessage,
      expectedTwofishPatterns: runtimeDoctor.expectedTwofishPatterns,
      twofishSearchRoots: runtimeDoctor.twofishSearchRoots,
      resolvedTwofishPath: runtimeDoctor.resolvedTwofishPath,
        twofishSource: runtimeDoctor.twofishSource,
        twofishLoadStatus: runtimeDoctor.twofishLoadStatus,
        twofishMessage: runtimeDoctor.twofishMessage,
        twofishSha256: runtimeDoctor.twofishSha256,
      }
    : twofishDiagnostics();
  const hostOs = runtimeDoctor.available ? runtimeDoctor.hostOs : process.platform;
  const detectedLayoutType = runtimeDoctor.available ? runtimeDoctor.detectedLayoutType : "fallback_unknown";
  const recommendedPacketTracerRoot = runtimeDoctor.available
    ? runtimeDoctor.recommendedPacketTracerRoot
    : fallbackRecommendedPacketTracerRoot(process.platform);
  const recommendedPacketTracerSavesRoot = runtimeDoctor.available
    ? runtimeDoctor.recommendedPacketTracerSavesRoot
    : fallbackRecommendedPacketTracerSavesRoot(process.platform);
  const installerSupported = runtimeDoctor.available
    ? runtimeDoctor.installerSupport.status === "supported"
    : ["win32", "darwin", "linux"].includes(process.platform);
  const runtimeSupported = runtimeDoctor.available
    ? runtimeDoctor.realPktRuntimeSupport.status === "validated"
    : process.platform === "win32";
  const runtimeMessage = runtimeDoctor.available
    ? runtimeDoctor.realPktRuntimeSupport.message
    : runtimeSupported
      ? "validated Windows Packet Tracer 9.0 runtime path"
      : twofish.resolvedTwofishPath
        ? "custom native runtime may work, but bundled validation is still Windows-first"
        : "needs custom Packet Tracer paths and a non-Windows native Twofish bridge";
  const packetTracerRoot = runtimeDoctor.available
    ? runtimeDoctor.packetTracerRoot
    : process.env.PACKET_TRACER_ROOT || "";
  const root = runtimeDoctor.available
    ? {
        ok: packetTracerRoot !== "",
        message: packetTracerRoot || "not set",
      }
    : envPathStatus(process.env.PACKET_TRACER_ROOT);

  const strictTargetVersion = "9.0.0.0810";
  checks.push(["HOST_OS", true, hostOs]);
  checks.push([
    "INSTALLER_SUPPORT",
    installerSupported,
    runtimeDoctor.available ? runtimeDoctor.installerSupport.message : installerSupported ? "supported" : "unknown host platform",
  ]);
  checks.push([
    "DETECTED_LAYOUT_TYPE",
    true,
    detectedLayoutType || "unknown",
  ]);
  checks.push([
    "RECOMMENDED_PACKET_TRACER_ROOT",
    recommendedPacketTracerRoot !== "",
    recommendedPacketTracerRoot || "not available",
  ]);
  checks.push([
    "RECOMMENDED_PACKET_TRACER_SAVES_ROOT",
    recommendedPacketTracerSavesRoot !== "",
    recommendedPacketTracerSavesRoot || "not available",
  ]);
  checks.push([
    "REAL_PKT_RUNTIME_SUPPORT",
    runtimeSupported,
    runtimeMessage,
  ]);
  checks.push(["PACKET_TRACER_ROOT", root.ok, root.message]);
  if (runtimeDoctor.available) {
    checks.push([
      "PACKET_TRACER_SAVES_ROOT",
      runtimeDoctor.packetTracerSavesRoot !== "",
      runtimeDoctor.packetTracerSavesRoot || "not resolved",
    ]);
    checks.push([
      "PACKET_TRACER_EXE",
      runtimeDoctor.packetTracerExe !== "",
      runtimeDoctor.packetTracerExe || "not resolved",
    ]);
  }
  checks.push([
    "PYTHON_VERSION",
    twofish.pythonVersion !== "",
    twofish.pythonVersion || "unknown",
  ]);
  checks.push([
    "PYTHON_SUPPORT_STATUS",
    twofish.pythonSupportStatus === "ok",
    twofish.pythonSupportStatus === "ok"
      ? `supported (${twofish.pythonSupportMessage})`
      : `${twofish.pythonSupportStatus} (${twofish.pythonSupportMessage})`,
  ]);
  checks.push([
    "PACKET_TRACER_TARGET_VERSION",
    donorDiagnostics.targetVersion === strictTargetVersion,
    donorDiagnostics.targetVersion === strictTargetVersion
      ? donorDiagnostics.targetVersion
      : `${donorDiagnostics.targetVersion} (expected ${strictTargetVersion})`,
  ]);
  checks.push([
    "PACKET_TRACER_COMPAT_DONOR",
    donorDiagnostics.status === "ok",
    donorDiagnostics.message,
  ]);
  checks.push([
    "PACKET_TRACER_COMPAT_DONOR_VERSION",
    donorDiagnostics.status === "ok",
    donorDiagnostics.donorVersion || donorDiagnostics.status,
  ]);
  checks.push([
    "RESOLVED_DONOR_PATH",
    donorDiagnostics.donorPath !== "",
    donorDiagnostics.donorPath || "not resolved",
  ]);
  checks.push([
    "DONOR_SOURCE",
    donorDiagnostics.status === "ok",
    donorDiagnostics.donorSource || "not resolved",
  ]);
  checks.push([
    "BLOCKING_REASON",
    donorDiagnostics.status === "ok",
    donorDiagnostics.status === "ok" ? "none" : donorDiagnostics.blockingReason || donorDiagnostics.message,
  ]);
  const candidateSummary = (donorDiagnostics.candidatePaths || [])
    .slice(0, 5)
    .map((entry) => `${entry.source}: ${entry.path}`)
    .join(" | ");
  checks.push([
    "DONOR_CANDIDATES",
    (donorDiagnostics.candidatePaths || []).length > 0,
    candidateSummary || "none discovered",
  ]);
  checks.push([
    "RESOLVED_TWOFISH_PATH",
    twofish.resolvedTwofishPath !== "",
    twofish.resolvedTwofishPath || "not found",
  ]);
  checks.push([
    "TWOFISH_LOAD_STATUS",
    twofish.twofishLoadStatus === "ok",
    `${twofish.twofishLoadStatus} (${twofish.twofishMessage})`,
  ]);
  checks.push([
    "TWOFISH_SHA256",
    twofish.twofishSha256 !== "",
    twofish.twofishSha256 || "not available",
  ]);
  checks.push([
    "TWOFISH_EXPECTED_PATTERNS",
    (twofish.expectedTwofishPatterns || []).length > 0,
    (twofish.expectedTwofishPatterns || []).join(" | ") || "not available",
  ]);
  checks.push([
    "TWOFISH_SEARCH_ROOTS",
    (twofish.twofishSearchRoots || []).length > 0,
    (twofish.twofishSearchRoots || []).join(" | ") || "not available",
  ]);

  return checks;
}

function printDoctorChecks(checks) {
  for (const [name, ok, detail] of checks) {
    console.log(`${ok ? "OK" : "MISSING"}  ${name}  ${detail}`);
  }
}

function checkMap(checks) {
  return new Map(checks.map(([name, ok, detail]) => [name, { ok, detail }]));
}

function doctorGuidance(checks) {
  const map = checkMap(checks);
  const guidance = [];
  const pythonSupport = map.get("PYTHON_SUPPORT_STATUS");
  const root = map.get("PACKET_TRACER_ROOT");
  const donor = map.get("PACKET_TRACER_COMPAT_DONOR");
  const donorCandidates = map.get("DONOR_CANDIDATES");
  const savesRoot = map.get("RECOMMENDED_PACKET_TRACER_SAVES_ROOT");
  const twofish = map.get("TWOFISH_LOAD_STATUS");
  const patterns = map.get("TWOFISH_EXPECTED_PATTERNS");
  const searchRoots = map.get("TWOFISH_SEARCH_ROOTS");
  const runtimeSupport = map.get("REAL_PKT_RUNTIME_SUPPORT");

  if (runtimeSupport && !runtimeSupport.ok) {
    guidance.push(`Real runtime is still Windows-first: ${runtimeSupport.detail}`);
  }
  if (pythonSupport && !pythonSupport.ok) {
    guidance.push("Use Python 3.14.x for Packet Tracer 9.0 encode/decode.");
  }
  if (root && !root.ok) {
    const suffix =
      map.get("RECOMMENDED_PACKET_TRACER_ROOT")?.detail &&
      map.get("RECOMMENDED_PACKET_TRACER_ROOT")?.detail !== "not available"
        ? ` Suggested root: ${map.get("RECOMMENDED_PACKET_TRACER_ROOT").detail}.`
        : "";
    guidance.push(`Set PACKET_TRACER_ROOT to your local Cisco Packet Tracer 9.0 install directory.${suffix}`);
  }
  if (donor && !donor.ok) {
    const savesHint =
      savesRoot && savesRoot.detail && savesRoot.detail !== "not available"
        ? ` Packet Tracer saves are typically under ${savesRoot.detail}.`
        : "";
    if (donorCandidates && donorCandidates.ok) {
      guidance.push(`Pick one discovered donor or export PACKET_TRACER_COMPAT_DONOR explicitly: ${donorCandidates.detail}.${savesHint}`);
    } else {
      guidance.push(`Provide a working 9.0 donor lab with PACKET_TRACER_COMPAT_DONOR or place one in Downloads/Documents/Desktop/Packet Tracer saves.${savesHint}`);
    }
  }
  if (twofish && !twofish.ok) {
    const parts = ["Provide a local Twofish bridge"];
    if (patterns && patterns.detail && patterns.detail !== "not available") {
      parts.push(`matching one of: ${patterns.detail}`);
    }
    if (searchRoots && searchRoots.detail && searchRoots.detail !== "not available") {
      parts.push(`in one of these roots: ${searchRoots.detail}`);
    }
    parts.push("or set PKT_TWOFISH_LIBRARY / PKT_TWOFISH_SEARCH_ROOTS.");
    guidance.push(parts.join(" "));
  }
  return guidance;
}

function fallbackEnvExamples(platformName) {
  if (platformName === "win32") {
    return [
      "$env:PACKET_TRACER_ROOT='C:\\Program Files\\Cisco Packet Tracer 9.0.0'",
      "$env:PACKET_TRACER_COMPAT_DONOR='C:\\path\\to\\your-working-9.0-donor.pkt'",
      '$env:PKT_TWOFISH_LIBRARY="$env:USERPROFILE\\.codex\\skills\\pkt\\scripts\\vendor\\_twofish.cp314-win_amd64.pyd"',
    ];
  }
  if (platformName === "darwin") {
    return [
      "export PACKET_TRACER_ROOT='/Applications/Cisco Packet Tracer.app/Contents/Resources'",
      "export PACKET_TRACER_COMPAT_DONOR=\"$HOME/path/to/your-working-9.0-donor.pkt\"",
      "export PKT_TWOFISH_SEARCH_ROOTS=\"$HOME/.codex/skills/pkt/scripts/vendor:$HOME/pkt-bridges\"",
    ];
  }
  if (platformName === "linux") {
    return [
      "export PACKET_TRACER_ROOT='/opt/pt'",
      "export PACKET_TRACER_COMPAT_DONOR=\"$HOME/path/to/your-working-9.0-donor.pkt\"",
      "export PKT_TWOFISH_SEARCH_ROOTS=\"$HOME/.codex/skills/pkt/scripts/vendor:$HOME/pkt-bridges\"",
    ];
  }
  return [];
}

function fallbackRecommendedPacketTracerRoot(platformName) {
  if (platformName === "win32") {
    return "C:\\Program Files\\Cisco Packet Tracer 9.0.0";
  }
  if (platformName === "darwin") {
    return "/Applications/Cisco Packet Tracer.app/Contents/Resources";
  }
  if (platformName === "linux") {
    return "/opt/pt";
  }
  return "";
}

function fallbackRecommendedPacketTracerSavesRoot(platformName) {
  if (platformName === "win32") {
    return "C:\\Program Files\\Cisco Packet Tracer 9.0.0\\saves";
  }
  if (platformName === "darwin") {
    return "/Applications/Cisco Packet Tracer.app/Contents/Resources/saves";
  }
  if (platformName === "linux") {
    return "/opt/pt/saves";
  }
  return "";
}

function printEnvExamples(runtimeDoctor) {
  const examples =
    runtimeDoctor && runtimeDoctor.available && (runtimeDoctor.envExamples || []).length
      ? runtimeDoctor.envExamples
      : fallbackEnvExamples(process.platform);
  if (!examples.length) {
    return;
  }
  console.log("\nSuggested environment setup:");
  for (const line of examples) {
    console.log(`- ${line}`);
  }
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
      printHelp();
      process.exit(0);
    }

    if (args.doctor) {
      const runtimeDoctor = runtimeDoctorDiagnostics();
      const checks = doctorChecks();
      printDoctorChecks(checks);
      const guidance = doctorGuidance(checks);
      if (guidance.length > 0) {
        console.log("\nRecommended next steps:");
        for (const line of guidance) {
          console.log(`- ${line}`);
        }
      }
      printEnvExamples(runtimeDoctor);
      const failed = checks.some(([, ok]) => !ok);
      if (failed) {
        console.error("\nRuntime is not fully ready. Install copies are fine, but Packet Tracer generation still needs the missing items above.");
        process.exit(1);
      }
      console.log("\nRuntime looks ready.");
      process.exit(0);
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

    if (args.bootstrap) {
      const bootstrapResult = bootstrapEnvironment(target, args.dev);
      console.log(`Installed: ${target}`);

      if (bootstrapResult.ok) {
        console.log(`Bootstrap venv: ${bootstrapResult.venvDir}`);
        if (bootstrapResult.runtimeRequirements.length === 0) {
          console.log("Runtime requirements: none declared");
        }
        if (args.dev) {
          if (bootstrapResult.devRequirements.length === 0) {
            console.log("Dev requirements: none declared");
          } else {
            console.log(`Dev requirements installed: ${bootstrapResult.devRequirements.length}`);
          }
        }
      } else {
        console.log(`Bootstrap venv: not completed`);
        console.log(`Bootstrap note: ${bootstrapResult.message}`);
      }

      const checks = doctorChecks();
      const runtimeDoctor = runtimeDoctorDiagnostics();
      console.log("\nRemaining manual runtime checks:");
      printDoctorChecks(checks);
      const guidance = doctorGuidance(checks);
      if (guidance.length > 0) {
        console.log("\nRecommended next steps:");
        for (const line of guidance) {
          console.log(`- ${line}`);
        }
      }
      printEnvExamples(runtimeDoctor);
      const missing = checks.filter(([, ok]) => !ok).map(([name]) => name);
      const donorCandidates = checks.find(([name]) => name === "DONOR_CANDIDATES");
      if (donorCandidates && donorCandidates[2] && donorCandidates[2] !== "none discovered") {
        console.log(`\nDiscovered donor candidates: ${donorCandidates[2]}`);
      }
      if (missing.length > 0) {
        console.log("\nBootstrap finished. Packet Tracer itself and any missing runtime paths still need to be provided manually.");
      } else {
        console.log("\nBootstrap finished. Runtime looks ready.");
      }
      process.exit(0);
    }

    console.log(`Installed: ${target}`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

main();
