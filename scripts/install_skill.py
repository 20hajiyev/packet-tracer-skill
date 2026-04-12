from __future__ import annotations

import argparse
import shutil
from pathlib import Path


HOST_PATHS = {
    "codex": Path.home() / ".codex" / "skills" / "pkt",
    "claude": Path.home() / ".claude" / "skills" / "pkt",
    "cursor": Path.home() / ".cursor" / "skills" / "pkt",
    "kiro": Path.home() / ".kiro" / "skills" / "pkt",
    "adal": Path.home() / ".adal" / "skills" / "pkt",
}

IGNORE_NAMES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "output",
}


def _copytree(src: Path, dst: Path) -> None:
    for item in src.iterdir():
        if item.name in IGNORE_NAMES:
            continue
        if item.suffix.lower() in {".pyc", ".pyo", ".pkt", ".xml"}:
            continue
        target = dst / item.name
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            _copytree(item, target)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def main() -> int:
    parser = argparse.ArgumentParser(description="Install pkt skill into a local host skill directory.")
    parser.add_argument("--host", choices=sorted(HOST_PATHS), help="Known host name.")
    parser.add_argument("--path", help="Custom destination directory. Final skill folder will be <path>/pkt unless --direct is used.")
    parser.add_argument("--direct", action="store_true", help="Treat --path as the final skill directory instead of the parent skills folder.")
    parser.add_argument("--force", action="store_true", help="Replace the target directory if it already exists.")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]

    if args.host:
        destination = HOST_PATHS[args.host]
    elif args.path:
        base = Path(args.path).expanduser()
        destination = base if args.direct else base / "pkt"
    else:
        parser.error("Provide --host or --path.")

    if destination.exists():
        if not args.force:
            raise SystemExit(f"Target already exists: {destination}. Use --force to replace it.")
        shutil.rmtree(destination)

    destination.mkdir(parents=True, exist_ok=True)
    _copytree(repo_root, destination)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
