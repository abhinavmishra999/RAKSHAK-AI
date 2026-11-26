"""Tiny isolated child: set rlimits, then exec the reviewed argv."""
import os
import resource
import sys


def main():
    if len(sys.argv) < 6 or sys.argv[4] != "--":
        return 125
    cpu_s, mem_mb, fsize_mb = (int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
    argv = sys.argv[5:]
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_s + 1, cpu_s + 2))
    resource.setrlimit(resource.RLIMIT_AS, (mem_mb << 20, mem_mb << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_mb << 20, fsize_mb << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (512, 512))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.execv(argv[0], argv)
    return 127


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"launcher failure: {exc}", file=sys.stderr)
        raise SystemExit(127)
