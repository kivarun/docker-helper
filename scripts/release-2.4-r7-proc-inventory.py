"""Capture OCI hardening paths and metadata in the R7 guest."""

import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


PATH_FIELDS = ("readonlyPaths", "maskedPaths")
SOURCE_TYPE = "docker_helper_buildkitd_t"
MAX_SPEC = 256 * 1024
DIR_FLAGS = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW


def read_spec(config, state):
    op, _, _, _, bundle, _ = config.relative_to(state / "ops").parts
    if not re.fullmatch(r"op_[a-f0-9]{32}", op) or not re.fullmatch(r"[a-z0-9]{25}", bundle):
        return None
    try:
        fd = os.open(config, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return None
            raw = stream.read(MAX_SPEC + 1)
        if len(raw) > MAX_SPEC:
            return None
        spec = json.loads(raw)
        # Match the runtime-facing spec after the prepared /dev rewrite.
        if not any(
            mount.get("destination") == "/dev"
            and mount.get("type") == "bind"
            and mount.get("source") == f"/var/lib/docker-helper/dev-prep/{op}"
            for mount in spec["mounts"]
        ):
            return None
        paths = {field: spec["linux"].get(field, []) for field in PATH_FIELDS}
        if any(
            not isinstance(entries, list)
            or len(entries) > 64
            or any(not isinstance(path, str) for path in entries)
            for entries in paths.values()
        ):
            return None
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    return {"op": op, "bundle": bundle, "sha256": hashlib.sha256(raw).hexdigest(), "paths": paths}


def inspect_path(root, path):
    parts = path.split("/")
    if (
        len(parts) < 3 or parts[:2] not in (["", "proc"], ["", "sys"], ["", "dev"])
        or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) or part in (".", "..") for part in parts[1:])
    ):
        return {"status": "gap", "reason": "path outside the inventory scope"}
    directory = os.dup(root)
    try:
        for part in parts[1:-1]:
            child = os.open(part, DIR_FLAGS, dir_fd=directory)
            os.close(directory)
            directory = child
        leaf = parts[-1]
        inode = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISCHR(inode.st_mode):
            if (os.major(inode.st_rdev), os.minor(inode.st_rdev)) == (1, 3):
                return {"status": "null-device", "ino": inode.st_ino}
        kind = {stat.S_IFDIR: "dir", stat.S_IFREG: "file"}.get(stat.S_IFMT(inode.st_mode))
        if kind is None:
            return {"status": "gap", "reason": "target is neither a regular file nor a directory"}
        try:
            label = os.getxattr(
                f"/proc/self/fd/{directory}/{leaf}", "security.selinux", follow_symlinks=False
            ).rstrip(b"\0").decode("ascii")
        except (OSError, UnicodeError) as exc:
            return {"status": "present", "class": kind, "ino": inode.st_ino, "label_error": str(exc)}
        return {"status": "present", "class": kind, "ino": inode.st_ino, "label": label}
    except OSError as exc:
        return {"status": "absent" if exc.errno == errno.ENOENT else "gap", "errno": exc.errno}
    finally:
        os.close(directory)


def inspect_init(process, state, specs):
    try:
        if not (process / "comm").read_text().startswith("runc:[2:INIT]"):
            return None
        mountinfo = [line.split() for line in (process / "mountinfo").read_text().splitlines()]
        roots = [row for row in mountinfo if row[4] == "/"]
        if len(roots) != 1:
            return None
        root_mount = roots[0]
        candidates = [
            spec for spec in specs.values()
            if root_mount[3].startswith(f"{state}/ops/{spec['op']}/root/runc-native/")
        ]
        if len(candidates) != 1:
            return None
        # Pin the runc namespace and post-pivot root during the short
        # metadata walk. Release both before reporting or querying policy.
        ns = os.open(process / "ns/mnt", os.O_RDONLY)
        try:
            with_root = os.open(process / "root", os.O_PATH | os.O_DIRECTORY)
            try:
                spec = candidates[0]
                targets = dict.fromkeys(path for entries in spec["paths"].values() for path in entries)
                rows = {path: inspect_path(with_root, path) for path in targets}
                target_mounts = {row[4]: row for row in mountinfo if row[4] in rows}
                for path, mount in target_mounts.items():
                    rows[path]["mountinfo"] = mount
                return {"pid": int(process.name), "root_mount": root_mount, "spec": spec, "rows": rows}
            finally:
                os.close(with_root)
        finally:
            os.close(ns)
    except (OSError, UnicodeError):
        return None


def emit(event, value):
    print(json.dumps({"event": event, **value}, ensure_ascii=True), flush=True)


def capture(state, stop):
    specs, seen = {}, set()
    emit("ready", {})
    deadline = time.monotonic() + 125
    while not stop.exists() and time.monotonic() < deadline:
        for config in state.glob("ops/op_*/root/runc-native/executor/*/config.json"):
            if config not in specs and (spec := read_spec(config, state)):
                specs[config] = spec
                emit("spec", spec)
        if specs:
            for process in Path("/proc").iterdir():
                if not process.name.isdecimal() or process.name in seen:
                    continue
                if snapshot := inspect_init(process, state, specs):
                    seen.add(process.name)
                    emit("post-pivot", snapshot)
        time.sleep(0.002)


def report(op, capture_log):
    if not capture_log.exists():
        emit("gap", {"reason": "inventory capture log missing"})
        return
    events = [json.loads(line) for line in capture_log.read_text().splitlines() if line.strip()]
    specs = [event for event in events if event["event"] == "spec" and event["op"] == op]
    if not specs:
        emit("gap", {"reason": "no runtime-facing OCI spec captured", "op": op})
        return
    candidates = set()
    for spec in specs:
        emit("spec", {key: spec[key] for key in ("op", "bundle", "sha256", "paths")})
        matching = [
            event for event in events
            if event["event"] == "post-pivot"
            and event["spec"]["op"] == op
            and event["spec"]["bundle"] == spec["bundle"]
            and event["spec"]["sha256"] == spec["sha256"]
        ]
        if not matching:
            emit("gap", {"reason": "post-pivot view not captured", "bundle": spec["bundle"]})
            continue
        for snapshot in matching:
            for field, targets in spec["paths"].items():
                for path in targets:
                    row = snapshot["rows"][path]
                    emit("target", {"pid": snapshot["pid"], "list": field, "path": path, **row})
                    label = row.get("label", "").split(":")
                    if len(label) >= 4 and re.fullmatch(r"[A-Za-z0-9_]+", label[2]):
                        candidates.add((label[2], row["class"]))
    # This is a type-enforcement inventory, including attribute rules.
    # Runtime checks and MCS constraints are resolved by the trace and AVCs.
    for target_type, object_class in sorted(candidates):
        identity = {"type": target_type, "class": object_class, "source": SOURCE_TYPE}
        try:
            query = subprocess.run(
                ["sesearch", "-A", "-s", SOURCE_TYPE, "-t", target_type, "-c", object_class],
                check=False, capture_output=True, text=True, timeout=5,
            )
            emit("policy", {**identity, "rc": query.returncode, "allow": query.stdout, "stderr": query.stderr})
        except (OSError, subprocess.TimeoutExpired) as exc:
            emit("gap", {**identity, "reason": str(exc)})


if __name__ == "__main__":
    command, first, second = sys.argv[1:]
    if command == "capture":
        capture(Path(first), Path(second))
    elif command == "report":
        report(first, Path(second))
    else:
        raise SystemExit("expected capture or report")
