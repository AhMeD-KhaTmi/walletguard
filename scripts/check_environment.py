"""Record the professor's Linux VM, kernel and BTF prerequisites."""

import argparse
import json
from pathlib import Path
import platform
import re
import sys


def check():
    release = platform.freedesktop_os_release()
    kernel = platform.release()
    version = re.match(r"(\d+)\.(\d+)", kernel)
    checks = {
        "ubuntu_lts": release.get("ID") == "ubuntu" and release.get("VERSION_ID") in {"22.04", "24.04"},
        "kernel_5_15_or_newer": bool(version and tuple(map(int, version.groups())) >= (5, 15)),
        "btf_available": Path("/sys/kernel/btf/vmlinux").is_file(),
    }
    return {"os": release.get("PRETTY_NAME"), "kernel": kernel,
            "btf_path": "/sys/kernel/btf/vmlinux", "checks": checks, "ready": all(checks.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check()
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    print(text, end="")
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
