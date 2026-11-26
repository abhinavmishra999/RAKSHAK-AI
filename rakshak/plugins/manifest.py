"""plugin.yml manifest: a plugin is only DATA until an administrator reviews and enables it.

    id: nmap-ports                  # lowercase letters, digits, dashes; must equal the folder name
    name: Open port check (Nmap)
    version: "1.0"
    description: What it does, in plain words.
    source: https://nmap.org        # where the tool came from (shown to the reviewer)
    kind: active                    # passive = only reads local data; active = sends traffic to a target
    approval: admin                 # active only: self = requester confirms, admin = an admin must approve
    interpreter: python             # optional: run a script in this folder with Rakshak's own Python
    executable: nmap                # bare name (looked up on the system path), absolute path, or file in this folder
    sha256: ""                      # optional: pin the exact file hash; enabling fails if it differs
    target_type: host               # host | url | none (passive plugins that need no target)
    args: ["-Pn", "-sT", "--top-ports", "100", "--open", "-oX", "-", "{target}"]
    timeout_s: 120
    max_output_kb: 512
    parser: nmap_xml                # nmap_xml | json_findings | text
    validator: tcp_open             # tcp_open | http_recheck | none (how findings are independently re-checked)

Plugins never run inside Rakshak's process and never get a shell. The only substitution
allowed in `args` is {target}, which has already been validated and scope-checked.
"""
import hashlib
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,40}$")
KINDS = ("passive", "active")
TARGET_TYPES = ("host", "url", "none")
PARSERS = ("nmap_xml", "json_findings", "text")
VALIDATORS = ("tcp_open", "http_recheck", "none")
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
KNOWN_KEYS = {"id", "name", "version", "description", "source", "kind", "approval", "interpreter",
              "executable", "sha256", "target_type", "args", "timeout_s", "max_output_kb", "parser", "validator"}
PUBLIC = ("id", "name", "version", "description", "source", "kind", "approval", "interpreter", "executable",
          "sha256", "target_type", "args", "timeout_s", "max_output_kb", "parser", "validator", "builtin",
          "manifest_sha256", "problems")


@dataclass
class Plugin:
    id: str
    name: str = ""
    version: str = ""
    description: str = ""
    source: str = ""
    kind: str = "active"
    approval: str = "admin"
    interpreter: str = ""
    executable: str = ""
    sha256: str = ""
    target_type: str = "host"
    args: list = field(default_factory=list)
    timeout_s: int = 120
    max_output_kb: int = 512
    parser: str = "text"
    validator: str = "none"
    folder: Path = None
    builtin: bool = False
    manifest_sha256: str = ""
    problems: list = field(default_factory=list)

    def public(self):
        return {k: getattr(self, k) for k in PUBLIC}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(folder: Path, builtin: bool) -> Plugin:
    raw = (folder / "plugin.yml").read_bytes()
    p = Plugin(id=folder.name, folder=folder, builtin=builtin, manifest_sha256=hashlib.sha256(raw).hexdigest())
    try:
        d = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        p.problems.append(f"plugin.yml is not valid YAML: {exc}")
        return p
    if not isinstance(d, dict):
        p.problems.append("plugin.yml must contain a YAML mapping.")
        return p
    for k in d:
        if k not in KNOWN_KEYS:
            p.problems.append(f"Unknown field '{k}' (not allowed).")
    p.id = str(d.get("id", ""))
    if not ID_RE.match(p.id):
        p.problems.append("id must be 2-41 characters: lowercase letters, digits and dashes.")
    if p.id and folder.name != p.id:
        p.problems.append(f"Folder name '{folder.name}' must equal the plugin id '{p.id}'.")
    p.name = str(d.get("name") or p.id)[:80]
    p.version = str(d.get("version", ""))[:20]
    p.description = str(d.get("description", ""))[:600]
    p.source = str(d.get("source", ""))[:200]
    p.kind = str(d.get("kind", "active"))
    p.approval = str(d.get("approval", "admin"))
    p.interpreter = str(d.get("interpreter", "") or "")
    p.executable = str(d.get("executable", "") or "")
    p.sha256 = str(d.get("sha256", "") or "").lower()
    p.target_type = str(d.get("target_type", "host"))
    p.args = d.get("args", [])
    p.parser = str(d.get("parser", "text"))
    p.validator = str(d.get("validator", "none"))
    try:
        p.timeout_s = int(d.get("timeout_s", 120))
        p.max_output_kb = int(d.get("max_output_kb", 512))
    except (TypeError, ValueError):
        p.problems.append("timeout_s and max_output_kb must be whole numbers.")
    if p.kind not in KINDS:
        p.problems.append("kind must be 'passive' or 'active'.")
    if p.approval not in ("self", "admin"):
        p.problems.append("approval must be 'self' or 'admin'.")
    if p.target_type not in TARGET_TYPES:
        p.problems.append("target_type must be host, url or none.")
    if p.kind == "active" and p.target_type == "none":
        p.problems.append("An active plugin must have a target (host or url).")
    if p.parser not in PARSERS:
        p.problems.append(f"parser must be one of: {', '.join(PARSERS)}.")
    if p.validator not in VALIDATORS:
        p.problems.append(f"validator must be one of: {', '.join(VALIDATORS)}.")
    if p.interpreter not in ("", "python"):
        p.problems.append("interpreter may only be empty or 'python'.")
    if not p.executable:
        p.problems.append("executable is required.")
    if p.sha256 and not re.fullmatch(r"[0-9a-f]{64}", p.sha256):
        p.problems.append("sha256 must be 64 hexadecimal characters.")
    if not 1 <= p.timeout_s <= 3600:
        p.problems.append("timeout_s must be between 1 and 3600.")
    if not 1 <= p.max_output_kb <= 8192:
        p.problems.append("max_output_kb must be between 1 and 8192.")
    if not isinstance(p.args, list) or not all(isinstance(a, str) for a in p.args):
        p.problems.append("args must be a list of strings.")
        p.args = []
    for a in p.args:
        for tok in re.findall(r"\{[^}]*\}", a):
            if tok != "{target}":
                p.problems.append(f"Only {{target}} may be used inside args (found {tok}).")
    if p.target_type != "none" and not any("{target}" in a for a in p.args):
        p.problems.append("args must contain {target} for plugins that have a target.")
    if p.target_type == "none" and any("{target}" in a for a in p.args):
        p.problems.append("target_type is none but args uses {target}.")
    return p


def resolve_executable(p: Plugin):
    """Find the real file to run. Returns (command_prefix, path_to_hash, error_text)."""
    ex = p.executable
    if p.interpreter == "python":
        script = (p.folder / ex).resolve()
        if p.folder.resolve() not in script.parents:
            return None, None, "The script must be inside the plugin's own folder."
        if not script.is_file():
            return None, None, f"Script not found: {ex}"
        return [sys.executable, "-I", str(script)], script, ""
    if "/" in ex:
        path = Path(ex)
        if not path.is_absolute():
            path = (p.folder / ex).resolve()
            if p.folder.resolve() not in path.parents:
                return None, None, "A relative executable must be inside the plugin's own folder."
    else:
        found = shutil.which(ex, path=SYSTEM_PATH)
        if not found:
            return None, None, f"'{ex}' is not installed on this computer (not found on the system path)."
        path = Path(found)
    path = path.resolve()
    if not path.is_file():
        return None, None, f"Executable not found: {path}"
    return [str(path)], path, ""
