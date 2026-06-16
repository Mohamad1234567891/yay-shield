#!/usr/bin/env python3

#===============================================================================
# yay-shield
# Copyright (C) 2026 Muhammed Bekiroğlu
# Copyright (C) 2026 Alshajara Computer Science Institute
#
# Author: Muhammed Bekiroğlu
# Institution: Alshajara Computer Science Institute
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, version 3 of the License.
#
# Additional attribution notice under GPLv3 section 7(b):
# Redistributed copies and modified versions of this software must preserve
# the following reasonable author attribution in the source code,
# documentation, and other reasonable legal notices accompanying the work:
#
#   yay-shield was originally created by Muhammed Bekiroğlu.
#   Original repository: https://github.com/Mohamad1234567891/yay-shield
#   Author channel: https://www.youtube.com/channel/UCn5v_KxsVgdbba4vk1CxjAA?sub_confirmation=1
#
# This attribution requirement does not limit, restrict, or otherwise
# modify the rights granted under the GNU General Public License v3.0.
#===============================================================================

from __future__ import annotations

import base64
import configparser
import concurrent.futures
import dataclasses
import hashlib
import io
import json
import math
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None  # type: ignore[assignment]
from collections import Counter, defaultdict
from contextlib import redirect_stdout
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

ENV = os.environ

YSHIELD_FORCE                      = ENV.get("YSHIELD_FORCE", "0") == "1"
YSHIELD_ALLOW_OFFICIAL             = ENV.get("YSHIELD_ALLOW_OFFICIAL", "1") == "1"
YSHIELD_MIN_SEVERITY               = ENV.get("YSHIELD_MIN_SEVERITY", "MEDIUM").upper()
YSHIELD_BLOCK_MIN_SEVERITY         = ENV.get("YSHIELD_BLOCK_MIN_SEVERITY", "HIGH").upper()
YSHIELD_CLONE_DEPTH                = int(ENV.get("YSHIELD_CLONE_DEPTH", "5"))
YSHIELD_MAX_TEXT_BYTES             = int(ENV.get("YSHIELD_MAX_TEXT_BYTES", "2000000"))
YSHIELD_CACHE_DIR                  = Path(ENV.get("YSHIELD_CACHE_DIR", str(Path.home() / ".cache" / "yay-shield")))
YSHIELD_REPORT_JSON                = ENV.get("YSHIELD_REPORT_JSON", "0") == "1"
YSHIELD_REPORT_PATH                = Path(ENV.get("YSHIELD_REPORT_PATH", "/tmp/yay-shield-report.json"))
YSHIELD_ALLOWLIST                  = Path(ENV.get("YSHIELD_ALLOWLIST", str(Path.home() / ".config" / "yay-shield" / "allowlist")))
YSHIELD_TRUSTED_MAINTAINERS        = [x for x in ENV.get("YSHIELD_TRUSTED_MAINTAINERS", "").split(":") if x]
YSHIELD_PARALLEL                   = ENV.get("YSHIELD_PARALLEL", "1") == "1"
YSHIELD_DIFF_COMMITS               = int(ENV.get("YSHIELD_DIFF_COMMITS", "3"))
YSHIELD_ENTROPY_THRESHOLD          = float(ENV.get("YSHIELD_ENTROPY_THRESHOLD", "4.9"))
YSHIELD_MIN_ENTROPY_LEN            = int(ENV.get("YSHIELD_MIN_ENTROPY_LEN", "48"))
YSHIELD_DEBUG                      = ENV.get("YSHIELD_DEBUG", "0") == "1"
YSHIELD_GLOBAL_SCOPE_ESCALATION    = ENV.get("YSHIELD_GLOBAL_SCOPE_ESCALATION", "1") == "1"
YSHIELD_INSTALL_SCRIPT_ESCALATION  = ENV.get("YSHIELD_INSTALL_SCRIPT_ESCALATION", "1") == "1"
YSHIELD_CHECK_TYPOSQUAT            = ENV.get("YSHIELD_CHECK_TYPOSQUAT", "1") == "1"
YSHIELD_TYPOSQUAT_MAX_DISTANCE     = int(ENV.get("YSHIELD_TYPOSQUAT_MAX_DISTANCE", "2"))
YSHIELD_CHECK_BINARY_FILES         = ENV.get("YSHIELD_CHECK_BINARY_FILES", "1") == "1"
YSHIELD_CHECK_SRCINFO              = ENV.get("YSHIELD_CHECK_SRCINFO", "1") == "1"
YSHIELD_NEW_PACKAGE_DAYS           = int(ENV.get("YSHIELD_NEW_PACKAGE_DAYS", "3"))
YSHIELD_MAX_SIMILAR_SHOWN          = int(ENV.get("YSHIELD_MAX_SIMILAR_SHOWN", "3"))
YSHIELD_DEEP_SOURCE_SCAN           = ENV.get("YSHIELD_DEEP_SOURCE_SCAN", "0") == "1"
YSHIELD_TOCTOU_CHECK               = ENV.get("YSHIELD_TOCTOU_CHECK", "1") == "1"
YSHIELD_SCAN_VCS_SOURCES           = ENV.get("YSHIELD_SCAN_VCS_SOURCES", "0") == "1"
YSHIELD_SCAN_AUR_DEPS              = ENV.get("YSHIELD_SCAN_AUR_DEPS", "0") == "1"
YSHIELD_AUR_DEP_DEPTH              = int(ENV.get("YSHIELD_AUR_DEP_DEPTH", "1"))
YSHIELD_SHELLCHECK                 = ENV.get("YSHIELD_SHELLCHECK", "1") == "1"
YSHIELD_POPULAR_CACHE_TTL          = int(ENV.get("YSHIELD_POPULAR_CACHE_TTL", str(7 * 86400)))
YSHIELD_AUR_TOP_N                  = int(ENV.get("YSHIELD_AUR_TOP_N", "2000"))
YSHIELD_CORRELATION_WINDOW         = int(ENV.get("YSHIELD_CORRELATION_WINDOW", "8"))
YSHIELD_MAINTAINER_REP             = ENV.get("YSHIELD_MAINTAINER_REP", "1") == "1"
YSHIELD_MAX_VCS_SOURCES            = int(ENV.get("YSHIELD_MAX_VCS_SOURCES", "2"))
YSHIELD_DATA_FLOW                  = ENV.get("YSHIELD_DATA_FLOW", "1") == "1"
YSHIELD_SANDBOX                    = ENV.get("YSHIELD_SANDBOX", "0") == "1"
YSHIELD_SANDBOX_TIMEOUT            = int(ENV.get("YSHIELD_SANDBOX_TIMEOUT", "60"))
YSHIELD_BINARY_STRINGS             = ENV.get("YSHIELD_BINARY_STRINGS", "1") == "1"
YSHIELD_HOMOGLYPH                  = ENV.get("YSHIELD_HOMOGLYPH", "1") == "1"
YSHIELD_CALL_GRAPH                 = ENV.get("YSHIELD_CALL_GRAPH", "1") == "1"
YSHIELD_STEGANOGRAPHY              = ENV.get("YSHIELD_STEGANOGRAPHY", "0") == "1"
YSHIELD_ANTI_ANALYSIS              = ENV.get("YSHIELD_ANTI_ANALYSIS", "1") == "1"
YSHIELD_STRING_RECONSTRUCT         = ENV.get("YSHIELD_STRING_RECONSTRUCT", "1") == "1"
YSHIELD_SCOPE_WEIGHT_GLOBAL        = float(ENV.get("YSHIELD_SCOPE_WEIGHT_GLOBAL", "1.2"))
YSHIELD_SCOPE_WEIGHT_PACKAGE       = float(ENV.get("YSHIELD_SCOPE_WEIGHT_PACKAGE", "1.0"))
YSHIELD_SCOPE_WEIGHT_BUILD         = float(ENV.get("YSHIELD_SCOPE_WEIGHT_BUILD", "0.9"))
YSHIELD_SCOPE_WEIGHT_PREPARE       = float(ENV.get("YSHIELD_SCOPE_WEIGHT_PREPARE", "0.7"))
YSHIELD_SCOPE_WEIGHT_CHECK         = float(ENV.get("YSHIELD_SCOPE_WEIGHT_CHECK", "0.3"))
YSHIELD_SEMANTIC_VARS              = ENV.get("YSHIELD_SEMANTIC_VARS", "1") == "1"
YSHIELD_HEREDOC_SCAN               = ENV.get("YSHIELD_HEREDOC_SCAN", "1") == "1"
YSHIELD_DIFF_AWARE                 = ENV.get("YSHIELD_DIFF_AWARE", "1") == "1"
YSHIELD_GPG_VERIFY                 = ENV.get("YSHIELD_GPG_VERIFY", "1") == "1"
YSHIELD_FILE_WORKERS               = int(ENV.get("YSHIELD_FILE_WORKERS", str(min(8, os.cpu_count() or 4))))
YSHIELD_ARRAY_CTX                  = ENV.get("YSHIELD_ARRAY_CTX", "1") == "1"
YSHIELD_SRC_CROSSREF               = ENV.get("YSHIELD_SRC_CROSSREF", "1") == "1"
YSHIELD_SERVICE_SCAN               = ENV.get("YSHIELD_SERVICE_SCAN", "1") == "1"
YSHIELD_ACTIVE_B64_DECODE          = ENV.get("YSHIELD_ACTIVE_B64_DECODE", "1") == "1"
YSHIELD_DEP_CONFUSION              = ENV.get("YSHIELD_DEP_CONFUSION", "1") == "1"
YSHIELD_MAINTAINER_MATURITY_DECAY  = ENV.get("YSHIELD_MAINTAINER_MATURITY_DECAY", "1") == "1"
YSHIELD_TYPOSQUAT_FARM_MIN_CONF    = float(ENV.get("YSHIELD_TYPOSQUAT_FARM_MIN_CONF", "0.40"))
# v8 new
YSHIELD_TRAP_ANALYSIS              = ENV.get("YSHIELD_TRAP_ANALYSIS", "1") == "1"
YSHIELD_GLOB_OBFUSC                = ENV.get("YSHIELD_GLOB_OBFUSC", "1") == "1"
YSHIELD_INDIRECT_VAR               = ENV.get("YSHIELD_INDIRECT_VAR", "1") == "1"
YSHIELD_BUILD_SYSTEM_DEEP          = ENV.get("YSHIELD_BUILD_SYSTEM_DEEP", "1") == "1"
YSHIELD_GIT_HOOK_SCAN              = ENV.get("YSHIELD_GIT_HOOK_SCAN", "1") == "1"
YSHIELD_ARITH_CHARCODE             = ENV.get("YSHIELD_ARITH_CHARCODE", "1") == "1"
YSHIELD_PROC_SUB_NET               = ENV.get("YSHIELD_PROC_SUB_NET", "1") == "1"
YSHIELD_SHELL_OPT_ANALYSIS         = ENV.get("YSHIELD_SHELL_OPT_ANALYSIS", "1") == "1"
YSHIELD_KEYBOARD_TYPOSQUAT         = ENV.get("YSHIELD_KEYBOARD_TYPOSQUAT", "1") == "1"
# v9 new
YSHIELD_STRIP_INLINE_COMMENTS      = ENV.get("YSHIELD_STRIP_INLINE_COMMENTS", "1") == "1"
YSHIELD_DROPPER_PATH_TRACKING      = ENV.get("YSHIELD_DROPPER_PATH_TRACKING", "1") == "1"
YSHIELD_VERIFY_YAY_BINARY          = ENV.get("YSHIELD_VERIFY_YAY_BINARY", "1") == "1"
YSHIELD_SANITIZE_ENV               = ENV.get("YSHIELD_SANITIZE_ENV", "1") == "1"
YSHIELD_MANIFEST_DEEP              = ENV.get("YSHIELD_MANIFEST_DEEP", "1") == "1"
# v10 new
YSHIELD_FAIL_CLOSED_MANIFESTS      = ENV.get("YSHIELD_FAIL_CLOSED_MANIFESTS", "1") == "1"
YSHIELD_SOURCE_INTEGRITY_DEEP      = ENV.get("YSHIELD_SOURCE_INTEGRITY_DEEP", "1") == "1"
YSHIELD_SYMLINK_SCAN               = ENV.get("YSHIELD_SYMLINK_SCAN", "1") == "1"
YSHIELD_ARCHIVE_RISK_SCAN          = ENV.get("YSHIELD_ARCHIVE_RISK_SCAN", "1") == "1"
YSHIELD_LOCKFILE_SCAN              = ENV.get("YSHIELD_LOCKFILE_SCAN", "1") == "1"
YSHIELD_HANDOFF_ARG_GUARD          = ENV.get("YSHIELD_HANDOFF_ARG_GUARD", "1") == "1"
YSHIELD_MAX_MANIFEST_BYTES         = int(ENV.get("YSHIELD_MAX_MANIFEST_BYTES", "1000000"))
# v11 new
YSHIELD_BASH_EAGER_DECODE          = ENV.get("YSHIELD_BASH_EAGER_DECODE", "1") == "1"
YSHIELD_PARAM_TRANSFORM_TRACK      = ENV.get("YSHIELD_PARAM_TRANSFORM_TRACK", "1") == "1"
YSHIELD_ARRAY_INDEX_TRACK          = ENV.get("YSHIELD_ARRAY_INDEX_TRACK", "1") == "1"
YSHIELD_FILE_TAINT_TRACK           = ENV.get("YSHIELD_FILE_TAINT_TRACK", "1") == "1"
YSHIELD_DOWNSTREAM_SCRIPT_CRAWL    = ENV.get("YSHIELD_DOWNSTREAM_SCRIPT_CRAWL", "1") == "1"
YSHIELD_INSTALL_UNIFORM_SCAN       = ENV.get("YSHIELD_INSTALL_UNIFORM_SCAN", "1") == "1"
# signal/noise tuning
YSHIELD_OFFICIAL_ALT_PROMPT        = ENV.get("YSHIELD_OFFICIAL_ALT_PROMPT", "1") == "1"
YSHIELD_WEAK_ADVISORIES            = ENV.get("YSHIELD_WEAK_ADVISORIES", "0") == "1"

AUR_RPC    = "https://aur.archlinux.org/rpc/v5/info"
AUR_SEARCH = "https://aur.archlinux.org/rpc/v5/search"
AUR_GIT    = "https://aur.archlinux.org"

REQ_CMDS      = ["git", "curl", "pacman", "file", "sha256sum"]
OPTIONAL_CMDS = ["python3", "shellcheck", "bsdtar", "bwrap",
                 "strace", "strings", "binwalk", "unshare", "gpg"]

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ESCALATE_MAP  = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}

SCOPE_WEIGHT_TABLE: Dict[str, float] = {
    "global":   YSHIELD_SCOPE_WEIGHT_GLOBAL,
    "check":    YSHIELD_SCOPE_WEIGHT_CHECK,
    "prepare":  YSHIELD_SCOPE_WEIGHT_PREPARE,
    "build":    YSHIELD_SCOPE_WEIGHT_BUILD,
    "pkgver":   YSHIELD_SCOPE_WEIGHT_BUILD,
    "package":  YSHIELD_SCOPE_WEIGHT_PACKAGE,
    "external": YSHIELD_SCOPE_WEIGHT_PACKAGE,
    "diff":     1.5,
}

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK mapping (extended for v8)
# ─────────────────────────────────────────────────────────────────────────────

MITRE: Dict[str, str] = {
    "pipe_to_shell":          "T1059.004",
    "eval":                   "T1059.004",
    "decode_pattern":         "T1140",
    "shell_dash_c":           "T1059.004",
    "root_delete":            "T1485",
    "disk_destructive":       "T1485",
    "hex_obfuscation":        "T1140",
    "ifs_obfuscation":        "T1140",
    "interpreter_exec":       "T1059",
    "path_traversal":         "T1083",
    "paste_site":             "T1102",
    "ebpf":                   "T1014",
    "proc_read":              "T1057",
    "fd_exec":                "T1055",
    "reverse_shell":          "T1059.004",
    "crypto_miner":           "T1496",
    "sudoers_tamper":         "T1548.003",
    "env_exfil":              "T1552.007",
    "secret_dir":             "T1552",
    "token_ref":              "T1552.001",
    "browser_profile":        "T1539",
    "ssh_tool":               "T1021.004",
    "admin_command":          "T1136",
    "sudo_invocation":        "T1548.003",
    "suid_bit":               "T1548.001",
    "setcap":                 "T1548",
    "kernel_module":          "T1215",
    "pacman_conf_tamper":     "T1562.001",
    "shell_rc_persistence":   "T1546.004",
    "profile_d_persistence":  "T1546.004",
    "cron_persistence":       "T1053.003",
    "http_exfil":             "T1048.003",
    "service_control":        "T1543",
    "gpg_keyimport":          "T1553",
    "xdg_autostart":          "T1547.013",
    "systemd_user_unit":      "T1543.002",
    "history_tamper":         "T1070.003",
    "ld_preload_rootkit":     "T1574.006",
    "namespace_escape":       "T1611",
    "var_slice_obfuscation":  "T1140",
    "ansi_c_obfuscation":     "T1140",
    "array_obfuscation":      "T1140",
    "process_sub_obfuscation":"T1140",
    "indirect_exec":          "T1059",
    "correlation_dl_exec":    "T1059",
    "strace_scraping":        "T1056",
    "dbus_desktop_access":    "T1106",
    "at_batch_schedule":      "T1053",
    "etc_ld_so_preload":      "T1574.006",
    "taint_flow":             "T1140",
    "string_reconstruct":     "T1140",
    "anti_analysis":          "T1497",
    "polyglot":               "T1027",
    "homoglyph":              "T1036.008",
    "dynamic_sandbox":        "T1059",
    "binary_strings":         "T1027",
    "steganography":          "T1027.003",
    "call_graph":             "T1059",
    "time_payload":           "T1497.003",
    "env_probe":              "T1497",
    "dep_confusion":          "T1195.001",
    "heredoc_exec":           "T1059.004",
    "var_concat_obfusc":      "T1140",
    "rlo_attack":             "T1036",
    "flag_injection":         "T1059",
    "permission_escalation":  "T1548",
    "diff_introduced":        "T1059",
    "supply_chain":           "T1195",
    "insecure_tls":           "T1573",
    "network_fetch":          "T1071",
    "brace_expand_obfusc":    "T1140",
    "printf_obfusc":          "T1140",
    "tr_obfusc":              "T1140",
    "fifo_exec":              "T1059",
    "here_string_exec":       "T1059.004",
    "active_b64":             "T1140",
    "service_exec":           "T1543",
    "dep_confusion_provides": "T1195.001",
    "src_crossref":           "T1195",
    "git_submodules":         "T1195.001",
    "suspicious_commit_msg":  "T1195",
    "pkgbuild_changed":       "T1195",
    "shellcheck":             "T1059",
    "high_entropy":           "T1140",
    "committed_binary":       "T1027",
    "syntax":                 "T1059",
    "orphaned":               "T1195",
    "low_votes":              "T1195",
    "new_package":            "T1195",
    "typosquat":              "T1036.008",
    "new_maintainer":         "T1195",
    "maintainer_neglect":     "T1195",
    "suspicious_helper_func": "T1059",
    "missing_checksums":      "T1195",
    "skip_checksum":          "T1195",
    "no_check":               "T1195",
    "insecure_source":        "T1195",
    "ip_source":              "T1071",
    "suspicious_tld":         "T1071",
    "high_epoch":             "T1195",
    "missing_install_file":   "T1195",
    "unpinned_vcs_source":    "T1195",
    "no_pgp_validation":      "T1195",
    "integrity_disabled":     "T1195",
    "srcinfo_missing":        "T1195",
    "srcinfo_mismatch":       "T1195",
    "aur_dependency":         "T1195",
    "newish_domain":          "T1195",
    "domain_typosquat":       "T1036.008",
    "eco_install":            "T1059",
    "local_pkg_install":      "T1195",
    "system_path_write":      "T1485",
    "source_temp":            "T1059",
    "git_clone":              "T1195",
    "download_script":        "T1105",
    "dns_exfil":              "T1048.001",
    "etc_hosts":              "T1565.001",
    "proc_hide":              "T1014",
    # v8 new
    "proc_sub_net_exec":      "T1059.004",
    "glob_obfusc":            "T1140",
    "indirect_var_exec":      "T1059",
    "trap_payload":           "T1059.004",
    "exec_fd_trick":          "T1055",
    "arith_charcode":         "T1140",
    "mapfile_exec":           "T1059",
    "shell_opt_disable":      "T1070",
    "git_hook_inject":        "T1546.003",
    "cmake_external":         "T1195",
    "meson_wrap":             "T1195",
    "npm_registry_tamper":    "T1195.001",
    "cargo_registry_tamper":  "T1195.001",
    "self_modify":            "T1195",
    "makepkg_recursive":      "T1195",
    "configure_inject":       "T1059",
    "makefile_inject":        "T1059",
    "char_concat_obfusc":     "T1140",
    "associate_array_exec":   "T1140",
    # v9 new
    "dropper_path":           "T1105",
    "yay_binary_tamper":      "T1574.007",
    "env_injection":          "T1574.006",
    "manifest_script":        "T1195.001",
    "cargo_build_script":     "T1195.001",
    "go_replace":             "T1195.001",
    "vendored_executable":    "T1027",
    # v10 new
    "manifest_parse":         "T1195.001",
    "source_integrity":       "T1195",
    "source_command_subst":   "T1059.004",
    "symlink_escape":         "T1083",
    "archive_traversal":      "T1083",
    "lockfile_script":        "T1195.001",
    "lockfile_integrity":     "T1195.001",
    "package_manager_hook":   "T1195.001",
    "handoff_arg_injection":  "T1574.007",
    "repo_shadowing":         "T1574.007",
    # v11 new
    "param_transform":        "T1140",
    "printf_v_assignment":    "T1140",
    "file_taint_launder":     "T1140",
    "dynamic_array_index":    "T1140",
    "downstream_build_hook":  "T1195.001",
    "install_scriptlet":      "T1543",
    "official_alternative":   "T1195",
    "trusted_tool_shadow":    "T1574.007",
}

RESET = "\033[0m" if sys.stdout.isatty() else ""
C = {k: v if sys.stdout.isatty() else "" for k, v in {
    "red":     "\033[1;31m",
    "green":   "\033[1;32m",
    "yellow":  "\033[1;33m",
    "blue":    "\033[1;34m",
    "magenta": "\033[1;35m",
    "cyan":    "\033[1;36m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "nc":      RESET,
}.items()}

NO_GLOBAL_ESCALATION_CATEGORIES: FrozenSet[str] = frozenset({
    "archive_traversal", "cargo_build_script", "cargo_registry_tamper",
    "cmake_external", "eco_install", "go_replace", "lockfile_integrity",
    "lockfile_script", "manifest_parse", "meson_wrap", "missing_checksums",
    "newish_domain", "no_check", "no_pgp_validation", "official_alternative",
    "package_manager_hook", "source_integrity", "skip_checksum",
    "src_crossref", "symlink_escape", "unpinned_vcs_source",
})

WEAK_ADVISORY_CATEGORIES: FrozenSet[str] = frozenset({
    "archive_traversal", "cargo_build_script", "cargo_registry_tamper",
    "downstream_build_hook", "go_replace", "install_scriptlet",
    "lockfile_integrity", "lockfile_script", "low_votes",
    "package_manager_hook", "skip_checksum", "source_integrity",
    "symlink_escape", "unpinned_vcs_source",
})

TEMP_DIR    = Path(tempfile.mkdtemp(prefix="yay-shield-"))
CACHE_DIR   = YSHIELD_CACHE_DIR
OUTPUT_LOCK = threading.Lock()
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)

def info(msg: str) -> None:
    print(f"{C['cyan']}[INFO]{C['nc']}  {msg}")

def warn(msg: str) -> None:
    print(f"{C['yellow']}[WARN]{C['nc']}  {msg}")

def error(msg: str) -> None:
    print(f"{C['red']}[ERROR]{C['nc']} {msg}", file=sys.stderr)

def debug(msg: str) -> None:
    if YSHIELD_DEBUG:
        print(f"{C['blue']}[DBG]{C['nc']}   {msg}", file=sys.stderr)

def run(cmd: List[str], *, check: bool = False, capture_output: bool = False,
        text: bool = True, cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, check=check, capture_output=capture_output, text=text,
        cwd=str(cwd) if cwd else None, env=env, timeout=timeout,
    )

def command_exists(name: str) -> bool:
    return shutil.which(name) is not None

def ensure_required_commands() -> None:
    missing = [cmd for cmd in REQ_CMDS if not command_exists(cmd)]
    if missing:
        raise SystemExit(f"{C['red']}[FATAL]{C['nc']} Missing required: {', '.join(missing)}")

def severity_rank(sev: str) -> int:
    return SEVERITY_RANK.get(sev.upper(), 0)

def escalate_severity(sev: str) -> str:
    return ESCALATE_MAP.get(sev.upper(), sev.upper())

def meets_threshold(sev: str, threshold: str) -> bool:
    return severity_rank(sev) >= severity_rank(threshold)

def is_text_file(path: Path) -> bool:
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size > YSHIELD_MAX_TEXT_BYTES:
        return False
    try:
        cp = run(["file", "-b", "--mime-type", "--", str(path)], capture_output=True, check=False)
    except Exception:
        return False
    mime = (cp.stdout or "").strip()
    return mime.startswith("text/") or mime in {
        "application/json", "application/xml", "application/javascript",
        "application/x-shellscript", "application/x-sh", "application/x-perl",
        "application/x-python", "application/x-ruby", "application/x-php",
        "inode/x-empty",
    }

def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")

def read_manifest_text(scan: "PackageScan", rel: str, path: Path) -> Optional[str]:
    """Read a security-relevant manifest, failing closed on size/read errors."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        if YSHIELD_FAIL_CLOSED_MANIFESTS:
            scan.add("HIGH", rel, 0,
                     f"Cannot stat manifest for security scan: {exc}",
                     category="manifest_parse", confidence=0.85)
        return None
    if size > YSHIELD_MAX_MANIFEST_BYTES:
        if YSHIELD_FAIL_CLOSED_MANIFESTS:
            scan.add("HIGH", rel, 0,
                     f"Manifest too large to parse safely ({size} bytes > {YSHIELD_MAX_MANIFEST_BYTES})",
                     category="manifest_parse", confidence=0.85)
        return None
    try:
        return read_text(path)
    except Exception as exc:
        if YSHIELD_FAIL_CLOSED_MANIFESTS:
            scan.add("HIGH", rel, 0,
                     f"Cannot read manifest for security scan: {exc}",
                     category="manifest_parse", confidence=0.85)
        return None

def load_json_manifest(scan: "PackageScan", rel: str, path: Path) -> Optional[object]:
    text = read_manifest_text(scan, rel, path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        if YSHIELD_FAIL_CLOSED_MANIFESTS:
            scan.add("HIGH", rel, exc.lineno,
                     f"Malformed JSON manifest; lifecycle/dependency checks could be bypassed: {exc.msg}",
                     evidence=safe_join_preview(text.splitlines()[exc.lineno - 1] if text.splitlines() else ""),
                     category="manifest_parse", confidence=0.90)
        return None

def load_toml_manifest(scan: "PackageScan", rel: str, path: Path) -> Optional[dict]:
    text = read_manifest_text(scan, rel, path)
    if text is None:
        return None
    if tomllib is None:
        if YSHIELD_FAIL_CLOSED_MANIFESTS:
            scan.add("MEDIUM", rel, 0,
                     "TOML manifest present but this Python lacks tomllib; deep checks skipped",
                     category="manifest_parse", confidence=0.70)
        return None
    try:
        parsed = tomllib.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except tomllib.TOMLDecodeError as exc:  # type: ignore[union-attr]
        if YSHIELD_FAIL_CLOSED_MANIFESTS:
            scan.add("HIGH", rel, 0,
                     f"Malformed TOML manifest; dependency/source checks could be bypassed: {exc}",
                     category="manifest_parse", confidence=0.90)
        return None

def load_ini_manifest(scan: "PackageScan", rel: str, path: Path) -> Optional[configparser.ConfigParser]:
    text = read_manifest_text(scan, rel, path)
    if text is None:
        return None
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
        return parser
    except configparser.Error as exc:
        if YSHIELD_FAIL_CLOSED_MANIFESTS:
            scan.add("MEDIUM", rel, 0,
                     f"Malformed INI-style manifest; checks may be incomplete: {exc}",
                     category="manifest_parse", confidence=0.75)
        return None

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if not a:  return len(b)
    if not b:  return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]

def prompt_yes_no(question: str) -> bool:
    try:
        while True:
            ans = input(question).strip()
            if ans.lower() == "y": return True
            if ans.lower() in {"", "n", "no"}: return False
            print("Please enter y or n.")
    except EOFError:
        print()
        return False
    except KeyboardInterrupt:
        print()
        return False

def colorize_sev(sev: str, text: str) -> str:
    color = {"CRITICAL": C["red"], "HIGH": C["magenta"],
             "MEDIUM": C["yellow"], "LOW": C["blue"]}.get(sev.upper(), "")
    return f"{color}{text}{C['nc']}"

def safe_join_preview(line: str, limit: int = 160) -> str:
    line = line.rstrip("\n")
    return line if len(line) <= limit else line[:limit - 1] + "…"

def strip_shell_inline_comment(line: str) -> str:
    """
    Remove shell comments while preserving quoted # characters.
    Bash treats # as a comment only at the start of a word, so require either
    beginning-of-line or preceding shell whitespace.
    """
    if not YSHIELD_STRIP_INLINE_COMMENTS or "#" not in line:
        return line
    in_single = False
    in_double = False
    escaped   = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and not in_single:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1] in " \t":
                return line[:i].rstrip()
    return line

def effective_shell_line(line: str) -> str:
    return strip_shell_inline_comment(line).strip()

def shell_unquote(value: str) -> str:
    value = value.strip()
    if not value:
        return value
    try:
        parts = shlex.split(value, posix=True)
        if len(parts) == 1:
            return parts[0]
    except ValueError:
        pass
    if ((value.startswith("'") and value.endswith("'"))
            or (value.startswith('"') and value.endswith('"'))):
        return value[1:-1]
    return value

def shell_words(line: str) -> List[str]:
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return re.findall(r"""[^\s'"<>|;&]+""", line)

def is_allowlisted_package(pkg: str) -> bool:
    try:
        return YSHIELD_ALLOWLIST.exists() and pkg in {
            x.strip()
            for x in YSHIELD_ALLOWLIST.read_text(encoding="utf-8", errors="ignore").splitlines()
            if x.strip() and not x.lstrip().startswith("#")
        }
    except Exception:
        return False

def is_trusted_maintainer(name: str) -> bool:
    return bool(name) and name in YSHIELD_TRUSTED_MAINTAINERS

@lru_cache(maxsize=512)
def is_official_repo_package(pkg: str) -> bool:
    pkg_clean = re.split(r"[><=!]", pkg)[0].strip()
    cp = run(["pacman", "-Si", "--", pkg_clean], capture_output=True, check=False)
    return cp.returncode == 0

OFFICIAL_ALT_SUFFIXES: Tuple[str, ...] = (
    "-bin", "-git", "-svn", "-hg", "-bzr", "-cvs",
    "-appimage", "-portable", "-nightly", "-devel", "-dev",
    "-beta", "-alpha", "-rc", "-latest", "-stable", "-full",
)

def package_atom_name(atom: str) -> str:
    atom = atom.strip()
    if "/" in atom:
        atom = atom.rsplit("/", 1)[-1]
    return re.split(r"[<>=]", atom, 1)[0].strip()

@lru_cache(maxsize=512)
def official_repo_name(pkg: str) -> Optional[str]:
    pkg_clean = package_atom_name(pkg)
    if not pkg_clean:
        return None
    cp = run(["pacman", "-Si", "--", pkg_clean], capture_output=True, check=False)
    if cp.returncode != 0:
        return None
    m = re.search(r"(?m)^\s*Name\s*:\s*(\S+)", cp.stdout or "")
    return m.group(1) if m else pkg_clean

def official_alternative_for(pkg: str) -> Optional[str]:
    if not YSHIELD_OFFICIAL_ALT_PROMPT:
        return None
    name = package_atom_name(pkg)
    if not name or is_official_repo_package(name):
        return None
    candidates: List[str] = []
    for suffix in OFFICIAL_ALT_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix) + 1:
            candidates.append(name[:-len(suffix)])
    if name.endswith("-bin") and "-bin-" in name:
        candidates.append(name.replace("-bin-", "-", 1))
    for candidate in candidates:
        if candidate and candidate != name and is_official_repo_package(candidate):
            return official_repo_name(candidate) or candidate
    return None

def fetch_aur_info(pkg: str) -> dict:
    params = urllib.parse.urlencode([("arg[]", pkg)])
    url = f"{AUR_RPC}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "yay-shield/10"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    if data.get("resultcount", 0) <= 0:
        raise ValueError(f"{pkg!r} not found in AUR")
    return data

def fetch_aur_info_batch(pkgs: List[str]) -> List[dict]:
    if not pkgs:
        return []
    params = "&".join(f"arg[]={urllib.parse.quote(p)}" for p in pkgs[:250])
    url = f"{AUR_RPC}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "yay-shield/10"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        return data.get("results", [])
    except Exception:
        return []

def git(*args: str, cwd: Optional[Path] = None,
        check: bool = False, capture_output: bool = False) -> subprocess.CompletedProcess:
    return run(["git", "--no-pager", *args], cwd=cwd, check=check,
               capture_output=capture_output)

def clone_aur_repo(pkgbase: str, repo_dir: Path, depth: int = None) -> bool:
    if repo_dir.exists():
        shutil.rmtree(repo_dir, ignore_errors=True)
    d = depth if depth is not None else YSHIELD_CLONE_DEPTH
    cmd = ["git", "clone", "--depth", str(d), "--quiet",
           f"{AUR_GIT}/{pkgbase}.git", str(repo_dir)]
    cp = run(cmd, capture_output=True, check=False)
    return cp.returncode == 0

def cache_file_for_pkg(pkg: str) -> Path:
    return CACHE_DIR / f"{pkg}.pkgbuild.sha256"

def normalize_severity_label(pkg: "PackageScan") -> str:
    if pkg.critical: return "CRITICAL"
    if pkg.high:     return "HIGH"
    if pkg.medium:   return "MEDIUM"
    if pkg.low:      return "LOW"
    return "CLEAN"

def scope_weight(scope: str) -> float:
    s = scope.lower()
    for key in SCOPE_WEIGHT_TABLE:
        if s.startswith(key):
            return SCOPE_WEIGHT_TABLE[key]
    return SCOPE_WEIGHT_TABLE["package"]

def _sigmoid(x: float) -> float:
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0

# ─────────────────────────────────────────────────────────────────────────────
# v7 Array Context + SRCINFO isolation (retained, improved)
# ─────────────────────────────────────────────────────────────────────────────

_DECLARATIVE_ARRAY_FIELDS: FrozenSet[str] = frozenset({
    'depends', 'makedepends', 'checkdepends', 'optdepends',
    'provides', 'conflicts', 'replaces', 'groups',
    'arch', 'license', 'options', 'backup', 'noextract',
    'validpgpkeys',
    'sha256sums', 'sha512sums', 'md5sums', 'b2sums', 'sha1sums',
    'cksums', 'sha224sums', 'sha384sums',
})
_SOURCE_ARRAY_FIELDS: FrozenSet[str] = frozenset({'source'})

ACTX_EXECUTABLE  = "executable"
ACTX_DECLARATIVE = "declarative"
ACTX_SOURCE      = "source_array"

_ARRAY_OPEN_RE = re.compile(r'^[ \t]*([A-Za-z_]\w*)(?:_[A-Za-z0-9]+)?\+?=[ \t]*\(')

def compute_array_contexts(lines: List[str]) -> List[str]:
    if not YSHIELD_ARRAY_CTX:
        return [ACTX_EXECUTABLE] * len(lines)
    contexts: List[str] = []
    in_array = False
    actx     = ACTX_EXECUTABLE
    depth    = 0
    for raw in lines:
        stripped = raw.strip()
        if not in_array:
            m = _ARRAY_OPEN_RE.match(raw)
            if m:
                field = m.group(1).lower()
                base_field = re.sub(
                    r'_(?:x86_64|i686|aarch64|armv7h|armv6h|riscv64|pentium4)$', '', field)
                if base_field in _DECLARATIVE_ARRAY_FIELDS:
                    actx = ACTX_DECLARATIVE
                elif base_field in _SOURCE_ARRAY_FIELDS:
                    actx = ACTX_SOURCE
                else:
                    contexts.append(ACTX_EXECUTABLE)
                    continue
                depth = stripped.count('(') - stripped.count(')')
                contexts.append(actx)
                if depth <= 0:
                    in_array = False
                    actx = ACTX_EXECUTABLE
                else:
                    in_array = True
                continue
            contexts.append(ACTX_EXECUTABLE)
        else:
            contexts.append(actx)
            depth += stripped.count('(') - stripped.count(')')
            if depth <= 0:
                in_array = False
                depth    = 0
                actx     = ACTX_EXECUTABLE
    return contexts

def is_srcinfo_file(rel: str) -> bool:
    return rel == ".SRCINFO" or rel.endswith("/.SRCINFO")

# ─────────────────────────────────────────────────────────────────────────────
# v8 Keyboard adjacency map for typosquat detection
# ─────────────────────────────────────────────────────────────────────────────

_KEYBOARD_ADJACENT: Dict[str, Set[str]] = {
    'q': set('was'), 'w': set('qeasd'), 'e': set('wrsd'),
    'r': set('etdf'), 't': set('ryfg'), 'y': set('tugh'),
    'u': set('yihj'), 'i': set('uojk'), 'o': set('ipkl'),
    'p': set('ol'), 'a': set('qwsz'), 's': set('waedxz'),
    'd': set('serfcx'), 'f': set('drtgvc'), 'g': set('ftyhbv'),
    'h': set('gyujnb'), 'j': set('huikmn'), 'k': set('jiolm'),
    'l': set('kop'), 'z': set('asx'), 'x': set('zsdc'),
    'c': set('xdfv'), 'v': set('cfgb'), 'b': set('vghn'),
    'n': set('bhjm'), 'm': set('njk'),
}

def keyboard_distance(a: str, b: str) -> int:
    """Return number of character substitutions that are keyboard-adjacent."""
    if len(a) != len(b):
        return levenshtein(a, b)
    return sum(
        0 if ca == cb else (1 if cb in _KEYBOARD_ADJACENT.get(ca, set()) else 2)
        for ca, cb in zip(a, b)
    )

# ─────────────────────────────────────────────────────────────────────────────
# Pre-compiled patterns (all compiled at import, never re-compiled)
# ─────────────────────────────────────────────────────────────────────────────

class _P:
    """Namespace for all pre-compiled patterns. Compiled once at module load."""

    # ── Core network / exec ─────────────────────────────────────────────────
    URL                  = re.compile(r"https?://[^\s\"'<>`\)]+")
    COMMENT              = re.compile(r"^\s*#")
    BLANK                = re.compile(r"^\s*$")
    SAFE_PKGDIR          = re.compile(r"(?i)(\$\{?pkgdir\}?|DESTDIR=|--destdir\b|--prefix[= ]\S*\$\{?pkgdir\}?)")
    SAFE_INSTALL         = re.compile(r"(?i)\b(install|cp|mv|mkdir|chmod|ln)\b.*\$\{?pkgdir\}?")
    SAFE_PACKAGING       = re.compile(r"(?i)\b(cmake\s+--install\b|meson\s+install\b|ninja\s+install\b|make\s+.*DESTDIR|install\s+-D[m]?\b|DESTDIR=\$\{?pkgdir\}?)")
    WRITE_SYS            = re.compile(r"(?i)(>|tee|cp|mv|install|ln|mkdir|chmod)\b.*/(?:etc|usr/bin|usr/sbin|usr/lib|bin|sbin|lib)/")
    SYSTEM_PATH          = re.compile(r"(?i)/(etc/|usr/bin/|usr/sbin/|usr/lib/|bin/|sbin/|lib/)")
    DANGEROUS_PIPE       = re.compile(r"(?i)(curl|wget|fetch|aria2c)[^#\n]*\|[ \t]*(su[d]o[ \t]+)?(ba)?sh(\b|[;|]|$)")
    EVAL                 = re.compile(r'(?i)(^|[^A-Za-z0-9_])eval[ \t]*[\(\$"\']')
    SHELL_C              = re.compile(r"(?i)\b(bash|sh|zsh|dash|ksh|csh|tcsh|fish)[ \t]+-c[ \t]")
    DECODE               = re.compile(r"(?i)\b(base64[ \t]+(--decode|-d)|uudecode|xxd[ \t]+-r\b|openssl[ \t]+enc[ \t]+-d)")
    ROOT_DELETE          = re.compile(r"(?i)\brm[ \t]+-([rf]{1,2})[ \t]+/(?:[ \t;]|$)")
    FORMAT_UTIL          = re.compile(r"(?i)(^|[ \t;|&])(mkfs(\.[A-Za-z0-9_+-]+)?|mke2fs|mkswap|dd[ \t]+if=|shred|wipe)[ \t]")
    HEX_CMD              = re.compile(r"(?:printf|echo)[ \t]+(?:\\\\x[0-9A-Fa-f]{2}){4,}")
    IFS_MANIP            = re.compile(
        r"^[ \t]*(?:(?:export|local|declare|typeset)[ \t]+)?IFS(?:\+?=|[ \t]+)"
    )
    INTERP               = re.compile(r"(?i)\b(python3?|perl|ruby|php|node|deno)[ \t]+-[cme][ \t]")
    TRAVERSAL            = re.compile(r"(\.\./\.\.|%2e%2e|\\x2e\\x2e).*(passwd|shadow|/proc/self)")
    PASTE_SITE           = re.compile(
        r"(?i)(curl|wget|fetch)[^#\n]*"
        r"(pastebin\.com|paste\.ee|pastecode|hastebin|ghostbin|controlc\.com|"
        r"ix\.io|termbin|dpaste|sprunge|clbin|0x0\.st|rentry\.co|paste\.rs|"
        r"pastes\.io|paste\.mozilla\.org|privatebin|justpaste|toptal\.com/developers/hastebin|"
        r"codeshare\.io|bpaste\.net|snippets\.glot\.io)"
    )
    EBPF                 = re.compile(r"(?i)(bpf_prog_load|bpf\(\s*BPF_PROG_LOAD|libbpf|bpftool|bpf_object__open|BTF_KIND)")
    PROC_PRIV            = re.compile(r"(?i)(cat|read|head|tail|less|more)[ \t]+/proc/(net|self|[0-9]+/mem|kcore)")
    PROC_MEM             = re.compile(r"(?i)/proc/[0-9]+/mem\b")
    FD_EXEC              = re.compile(r"(?i)(/dev/fd/[0-9]|/proc/self/fd).*?(exec|source|[.])")
    SECRET_DIR           = re.compile(r"(/\.ssh|/\.gnupg|/\.aws|/\.azure|/\.config/gcloud|/\.kube|/\.docker|/\.netrc|/\.npmrc|/\.pypirc|/\.cargo/credentials|/\.password-store|/\.bitwarden|/\.vault-token|/\.terraform\.d)")
    TOKEN                = re.compile(
        r"(?i)\b(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|GITLAB_TOKEN|PYPI_TOKEN|"
        r"CARGO_REGISTRY_TOKEN|AWS_SECRET|AWS_ACCESS_KEY|SLACK_TOKEN|DISCORD_TOKEN|"
        r"ANTHROPIC_API_KEY|OPENAI_API_KEY|STRIPE_SECRET|CI_JOB_TOKEN|CODECOV_TOKEN|"
        r"HUGGINGFACE_TOKEN|CLOUDFLARE_API_KEY|VAULT_TOKEN|DOPPLER_TOKEN|VERCEL_TOKEN|"
        r"NETLIFY_AUTH_TOKEN|HEROKU_API_KEY|DIGITALOCEAN_ACCESS_TOKEN)\b"
    )
    BROWSER              = re.compile(r"(?i)(\.config/(google-chrome|chromium|firefox|brave-browser|microsoft-edge)|Library/Application Support/(Google|Firefox))")
    SSH_TOOL             = re.compile(r"(?i)(^|[ \t;|&])(ssh|scp|sftp|rsync)[ \t]")
    ADMIN_CMD            = re.compile(r"(?i)(^|[ \t;|&])(useradd|usermod|groupadd|groupmod|visudo|sudoedit|chpasswd|passwd)[ \t]")
    SUDO                 = re.compile(r"(?i)(^|[ \t;|&])sudo[ \t]")
    SUID                 = re.compile(r"(?i)chmod[ \t].*[u+]s|chmod[ \t].*4[0-7]{3}|chmod[ \t].*2[0-7]{3}")
    CRON                 = re.compile(r"(?i)(crontab[ \t]+-[el]|/etc/cron\.|/var/spool/cron)")
    FETCH                = re.compile(r"(?i)(^|[ \t;|&])(curl|wget|fetch|aria2c)[ \t]")
    TRUSTED_TOOL_SHADOW  = re.compile(
        r"(?i)^\s*(?:alias\s+|function\s+)?"
        r"(curl|wget|fetch|aria2c|git|gpg|makepkg|pacman|sudo)\b"
        r"(?:\s*\(\)|=)"
    )
    SERVICE              = re.compile(r"(?i)(systemctl|service)[ \t].*(enable|start|restart|stop|mask|daemon-reload|daemon-reexec)")
    PKG_INSTALL          = re.compile(r"(?i)(^|[ \t;|&])(pip3?|npm|yarn|bun|pnpm|cargo|go)[ \t]+(install|add|update|publish|get|build|run|compile|fetch)[ \t]")
    GIT_CLONE            = re.compile(r"(?i)(^|[ \t;|&])git[ \t]+clone[ \t]")
    DOWNLOAD_SCRIPT      = re.compile(r"(?i)(curl|wget|fetch)[^#\n]*(https?://[^\s\"']*\.(sh|bash|py|pl|rb|ps1|cmd|bat|exe|elf|bin))")
    LOCAL_PKG            = re.compile(r"(?i)(makepkg|pacman)[ \t]+-U([ \t]|$)")
    CHMOD_CRITICAL       = re.compile(r"(?i)chmod[ \t]+[0-7]{3,4}[ \t]+(/etc|/usr|/bin|/sbin|/lib)")
    SOURCE_TEMP          = re.compile(r"(?i)(source|\.|bash|sh|zsh)[ \t]+(/tmp/|/dev/shm/)")
    FIREWALL             = re.compile(r"(?i)(iptables|nftables|ufw|firewall-cmd)[ \t]")
    ETC_HOSTS            = re.compile(r"(?i)(>|>>)[ \t]*/etc/hosts")
    PROC_HIDE            = re.compile(r"(?i)(hidepid|remount[^#]*/proc|mount[^#]*proc)")
    ECO_INSTALL          = re.compile(r"(?i)(^|[ \t;|&])(npm|pnpm|yarn|bun|pip3?|cargo|go|gradle|mvn|ant)[ \t]+(install|build|run|compile|fetch)")
    RECENT_COMMIT        = re.compile(r"(?i)(hotfix|urgent|temp|test|revert|remove.check|disable.verify|bypass|skip.hash|no.verify|remove.sig|skip.sign)")
    BAD_DOMAIN           = re.compile(r"(?i)(githib|githubb|gthub|giithub|github\.co[^m]|bitbuckett|sourceforgee|pyp1|npmjs\.co[^m]|pypl\.org|pyhton|goggle)")
    NEWISH_DOMAIN        = re.compile(r"(?i)https?://[a-z0-9]{3,8}[0-9]{2,}\.")
    NON_HTTPS_SRC        = re.compile(r"(?i)source=.*\"?(http://|ftp://|git\+http://)")
    IP_SOURCE            = re.compile(r"(?i)source=.*\"?https?://[0-9]{1,3}(?:\.[0-9]{1,3}){3}")
    SUSPICIOUS_TLD       = re.compile(r"(?i)source=.*\"?https?://[^/]*\.(tk|ml|ga|cf|gq|xyz|top|click|download|zip)/")
    SKIP_CHECKSUM        = re.compile(r"(?im)^[ \t]*(sha256sums|sha512sums|b2sums|md5sums|sha1sums)=\(['\"]?SKIP")
    NO_CHECK             = re.compile(r"(?im)^[ \t]*options=.*!check")
    INSTALL_NO_FILE      = re.compile(r"(?im)^[ \t]*install=['\"]?[^'\" \t]+['\"]?")
    SOURCE_LINE          = re.compile(r"(?im)^[ \t]*source[ \t]*=")
    CHECKSUM_LINE        = re.compile(r"(?im)^[ \t]*(sha256sums|sha512sums|b2sums|md5sums|sha1sums|cksums|sha224sums|sha384sums)[ \t]*=")
    DEV_TCP              = re.compile(r"(?i)/dev/(tcp|udp)/")
    NC_EXEC              = re.compile(r"(?i)\b(nc|ncat|netcat)\b[^#\n]*(-e\b|--exec\b|--sh-exec\b|-c[ \t])")
    SOCAT_EXEC           = re.compile(r"(?i)\bsocat\b[^#\n]*\bexec\b")
    MINER                = re.compile(
        r"(?i)(xmrig|stratum\+tcp|stratum\+ssl|cpuminer|cryptonight|ethminer|"
        r"nicehash|minerd|nbminer|randomx|monero|xmr-stak|lolminer|teamredminer|"
        r"gminer|t-rex-miner|phoenixminer|claymore|ccminer|bfgminer|cgminer)"
    )
    PACMAN_CONF          = re.compile(r"(?i)(>|>>|tee|cp|mv|sed[ \t].*-i)[^#\n]*(/etc/pacman\.conf|/etc/pacman\.d/)")
    GPG_KEY              = re.compile(r"(?i)gpg[ \t][^#\n]*(--recv-keys|--keyserver)")
    SUDOERS              = re.compile(r"(?i)(/etc/sudoers(\.d)?\b|visudo)")
    SETCAP               = re.compile(r"(?i)(^|[ \t;|&])setcap[ \t]")
    SHELL_RC             = re.compile(r"(?i)(>>|>)[ \t]*\"?\$?\{?(HOME|home)\}?\"?/?\.(bashrc|zshrc|profile|bash_profile|zprofile|bash_login|kshrc)\b")
    PROFILE_D            = re.compile(r"(?i)(>|>>|tee|cp|mv|install)[^#\n]*/etc/profile\.d/")
    AUTOSTART            = re.compile(r"(?i)(\.config/autostart|/etc/xdg/autostart)")
    CRONTAB_INSTALL      = re.compile(r"(?i)(^|[ \t;|&])crontab[ \t]+(?!-[el])\S")
    SYSTEMD_USER         = re.compile(r"(?i)(systemctl[ \t]+--user|/usr/lib/systemd/user/|\.config/systemd/user)")
    ENV_EXFIL            = re.compile(r"(?i)\b(printenv|env)\b[^#\n]*\|[ \t]*(curl|wget|nc|ncat|socat)")
    DNS_EXFIL            = re.compile(r"(?i)\b(nslookup|dig|host)\b[^#\n]*\$\(")
    HTTP_POST_EXFIL      = re.compile(r"(?i)(curl[^#\n]*(-d\b|--data\b|--data-binary\b|--data-raw\b|--upload-file\b|-T[ \t])|wget[^#\n]*--post-(data|file))")
    HISTORY_TAMPER       = re.compile(r"(?i)(HISTSIZE=0\b|unset[ \t]+HISTFILE\b|export[ \t]+HISTFILE=/dev/null|history[ \t]+-c\b)")
    KERNEL_MODULE        = re.compile(r"(?i)(^|[ \t;|&])(insmod|modprobe|rmmod)[ \t]")
    VAR_SLICE            = re.compile(r"\$\{[A-Za-z_]\w*:[0-9]+:[0-9]+\}.*\$\{[A-Za-z_]\w*:[0-9]+:[0-9]+\}")
    ANSI_C_QUOTE         = re.compile(r"\$'(?:[^'\\]|\\(?:x[0-9A-Fa-f]{2}|[0-9]{3}|.))+['\s]")
    ARRAY_CMD            = re.compile(r'(?i)(?:^|[;|&({\s])["\']?\$\{[A-Za-z_]\w*\[@\*\]\}["\']?(?:\s|;|$)')
    INDIRECT_EXEC        = re.compile(r"(?i)\b(declare|typeset)\b[^#\n]*(-n|-f)[ \t]")
    PROC_SUB_EXEC        = re.compile(r"(?i)\b(source|\.|bash|sh|zsh|python3?|perl|ruby)\b[^#\n]*[<>]\(")
    TILDE_PRIV           = re.compile(r"~(root|postgres|mysql|redis|www-data|daemon|nobody)/")
    PRINTF_EXEC          = re.compile(r"(?i)(printf|echo)\s+['\"](?:\\x[0-9A-Fa-f]{2}|\\[0-7]{3}|[^'\"\\]){4,}['\"]\s*\|?\s*(bash|sh|zsh|dash|eval|source)")
    GIT_BYPASS           = re.compile(r"(?i)\bgit\b[^#\n]*(--no-verify\b|--force\b)")
    GPG_BATCH            = re.compile(r"(?i)\bgpg\b[^#\n]*(--batch\b|--yes\b).*?(--recv|--import|--keyserver)")
    PACMAN_U_NOCONFIRM   = re.compile(r"(?i)\bpacman\b[^#\n]*-U[^#\n]*--noconfirm")
    NAMESPACE            = re.compile(r"(?i)(^|[ \t;|&])(nsenter|unshare|chroot|pivot_root)[ \t]")
    LD_SO_PRELOAD        = re.compile(r"(?i)(>|>>|tee|cp|mv|install)[^#\n]*/etc/ld\.so\.(preload|conf)")
    DBUS                 = re.compile(r"(?i)(^|[ \t;|&])(dbus-send|gdbus|qdbus)[ \t]")
    AT_SCHEDULE          = re.compile(r"(?i)(^|[ \t;|&])(at|batch)[ \t]")
    TRACER               = re.compile(r"(?i)(^|[ \t;|&])(strace|ltrace|gdb|perf)[ \t][^#\n]*(-p\b|--pid\b|pid)")
    SYSTEM_SHELLRC       = re.compile(r"(?i)(>|>>|tee|cp|mv|install)[^#\n]*(/etc/environment|/etc/bash\.bashrc|/etc/zsh/zshrc|/etc/profile(?!\.d))")
    SAFE_CDN             = re.compile(
        r"(?i)https://(releases\.github\.com|objects\.githubusercontent\.com|"
        r"github\.com/[^/]+/[^/]+/releases/|gitlab\.com/[^/]+/[^/]+/-/releases/|"
        r"download\.kde\.org|download\.gnome\.org|ftp\.gnu\.org|dl\.google\.com|"
        r"storage\.googleapis\.com|downloads\.sourceforge\.net|prdownloads\.sourceforge\.net|"
        r"pypi\.org/packages/|files\.pythonhosted\.org|registry\.npmjs\.org|"
        r"cdn\.npmjs\.com|static\.crates\.io|dl\.rs|rubygems\.org|gems\.ruby-lang\.org|"
        r"dl\.fedoraproject\.org|launchpad\.net|sourceware\.org|kernel\.org/pub|"
        r"freedesktop\.org/releases|gnupg\.org/ftp|nodejs\.org/dist|"
        r"electronjs\.org/releases|github\.com/electron/|"
        r"dl\.winehq\.org|repo\.msys2\.org|download\.qt\.io)"
    )
    ANTI_ANALYSIS        = re.compile(
        r"(?i)(\[[ \t]*-[fde][ \t]+[/\"]?\.dockerenv|\bsystemd-detect-virt\b|"
        r"cat[ \t]+/proc/1/cgroup|cat[ \t]+/proc/self/status|\$PPID[ \t]*-[eg][qt][ \t]*[0-9]|"
        r"grep[ \t]+TracerPid[ \t]+/proc|cat[ \t]+/proc/self/maps|"
        r"\[[ \t]*\"\$UID\"[ \t]*[!=-][^]]*\]|\[[ \t]*\$UID[ \t]*-[en][qe][ \t]*[0-9]|"
        r"hostname.*sandbox|hostname.*analysis|\$TERM.*=.*dumb|NO_COLOR=|CI=true|"
        r"\[\[.*SANDBOX.*\]\]|\$\(who.*am.*i\).*!=.*root|/proc/self/exe.*readlink|"
        r"dmidecode.*-s|virt-what\b|/sys/class/dmi/id)"
    )
    TIME_PAYLOAD         = re.compile(r"(?i)(date.*\+%[YmdH].*\|\s*(grep|test|if)|epoch=\$\(date.*\+%s\)|\bif\b.*\$\(date.*\).*\b(then|&&))")
    STRING_CONCAT        = re.compile(r"\$[A-Za-z_]\w*\$[A-Za-z_]\w*")
    SHM_EXEC             = re.compile(r"(?i)(/dev/shm/|/run/shm/)[A-Za-z0-9_.-]+\.(sh|py|pl|bash|elf|bin)")
    NO_TLS_VERIFY        = re.compile(r"(?i)(curl[^#\n]*--insecure\b|curl[^#\n][ \t]-k\b|wget[^#\n]*--no-check-certificate)")
    FUNC_DEF             = re.compile(r"^\s*(?:function[ \t]+)?([A-Za-z_]\w*)[ \t]*\(\)[ \t]*(?:\{|$)")
    FUNC_CALL_MATCH      = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*)(?:[ \t]|$)")
    RLO_ATTACK           = re.compile(r"[\u202e\u202d\u202c\u202b\u202a\u200f\u200e]")
    NULL_BYTE            = re.compile(r"\x00")
    FLAG_INJECTION       = re.compile(r"\$\{?[A-Za-z_]\w*\}?[ \t]+[^#\n]*(--exec|--command|--shell|-e[ \t]|--eval)")
    HEREDOC_EXEC         = re.compile(r"(?i)\b(bash|sh|zsh|python3?|perl|ruby|eval)\b[^#\n]*<<[-]?['\"]?(EOF|HEREDOC|END|SCRIPT|CMD|PAYLOAD|DATA)['\"]?")
    JUNK_VAR_PATTERN     = re.compile(r"^[ \t]*[A-Za-z_][A-Za-z0-9_]{0,2}=['\"]?[a-zA-Z0-9/.-]{1,3}['\"]?\s*$")
    DOUBLE_EXT_DISGUISE  = re.compile(r"\.(png|jpg|gif|ico|txt|conf)\.sh\b|\.(sh|bash)\.png\b")
    POLYGLOT_PY          = re.compile(r"(?ms)^import\s+(?:os|sys|subprocess|socket|base64)$")
    POLYGLOT_PHP         = re.compile(r"<\?php\s")
    CURL_SILENT_OUT      = re.compile(r"(?i)curl[^#\n]*-[soO]\s+/(?:tmp|dev/shm)/[A-Za-z0-9_.-]+")
    WGET_QUIET_OUT       = re.compile(r"(?i)wget[^#\n]*-q[^#\n]+-O\s+/(?:tmp|dev/shm)/[A-Za-z0-9_.-]+")
    SRC_URL_FRAGMENT     = re.compile(r"(?i)source=.*\"?https?://[^#\"'\s]+")
    VALIDPGP_EMPTY       = re.compile(r"(?m)^\s*validpgpkeys=\(\s*\)")
    INTEGRITY_DISABLED   = re.compile(r"(?m)^\s*options=.*(!strip|!debug).*(!check)", re.I)
    EPOCH_HIGH           = re.compile(r"(?m)^epoch=([0-9]+)")
    UNPINNED_VCS         = re.compile(r"(?m)^\s*source=.*git\+")
    VCS_PINNED           = re.compile(r"(?m)^\s*source=.*#(commit|tag|branch)=")
    OPTIONS_STRIP        = re.compile(r"(?m)^\s*options=.*!strip", re.I)
    BRACE_EXPAND_OBFUSC  = re.compile(r"\{[a-z],[a-z],[a-z](,[a-z])*\}")
    TR_OBFUSC            = re.compile(r"(?i)\|[ \t]*tr[ \t]+['\"][A-Za-z-]+['\"][ \t]+['\"][A-Za-z-]+['\"][ \t]*\|[ \t]*(bash|sh|eval|python)")
    FIFO_EXEC            = re.compile(r"(?i)(mkfifo|mknod[^#]*p)[ \t]+(['\"]?/[^'\"\s]+)['\"]?")
    HERE_STRING_EXEC     = re.compile(r"(?i)\b(bash|sh|zsh|python3?|perl|ruby|eval)\b[^#\n]*<<<[ \t]*['\"]?\$\(")
    B64_BLOB_RE          = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
    SERVICE_EXECSTART_RE = re.compile(r"(?i)^[ \t]*Exec(?:Start|Stop|Pre|Post|Reload|StartPre|StartPost)[= ]\s*(.+)$")
    DESKTOP_EXEC_RE      = re.compile(r"(?i)^[ \t]*Exec[ \t]*=[ \t]*(.+)$")
    URL_FIELD_RE         = re.compile(r"(?m)^[ \t]*url=['\"]?(https?://[^'\"\s]+)['\"]?")
    SOURCE_URL_FIELD_RE  = re.compile(r"(?i)['\"]?(?:[^:]+::)?(https?://([^/'\"\s#]+))")
    ROT13_PIPE           = re.compile(r"(?i)\|[ \t]*tr[ \t]+['\"]A-Za-z['\"][ \t]+['\"]N-ZA-Mn-za-m['\"]")
    PROVIDES_FIELD_RE    = re.compile(r"(?ms)^[ \t]*provides[ \t]*=[ \t]*\(([^)]*)\)")
    PKGNAME_FIELD_RE     = re.compile(r"(?m)^[ \t]*pkgname=[ \t]*['\"]?([A-Za-z0-9._+@\-]+)['\"]?")

    # ── v8 new patterns ──────────────────────────────────────────────────────

    # Process substitution with network (CRITICAL bypass in v7)
    PROC_SUB_NET         = re.compile(
        r"(?i)(source|\.|bash|sh|zsh|dash|ksh)\s+<\s*\(\s*(curl|wget|fetch|aria2c)"
    )
    # Also: eval "$(curl ...)" — slightly different form
    EVAL_NET_SUBSHELL    = re.compile(
        r"(?i)eval\s+['\"]?\$\(\s*(curl|wget|fetch|aria2c)\b"
    )
    # Glob-based command name obfuscation: c?rl, cu*l, ba?h, py*on
    GLOB_CMD_OBFUSC      = re.compile(
        r"(?i)\b([a-z]{1,2}[?*][a-z?*]{1,6})\b[^#\n]*(\||\$\(|;|&&)"
    )
    # Indirect variable reference exec: ${!var} where var might resolve to a command
    INDIRECT_VAR_REF     = re.compile(r"\$\{![A-Za-z_]\w*\}|\$\{!([0-9]+)\}")
    # Trap with suspicious payload
    TRAP_SUSPICIOUS      = re.compile(
        r"(?i)trap\s+['\"]?[^'\";\n]*(?:curl|wget|eval|bash|sh|base64|python)[^'\";\n]*['\"]?\s+"
        r"(?:EXIT|ERR|SIGTERM|SIGINT|0|1|2|15|RETURN)\b"
    )
    # exec with file descriptor to open TCP: exec {fd}<>/dev/tcp/
    EXEC_FD_TCP          = re.compile(r"(?i)exec\s+\{?[A-Za-z0-9_]+\}?[<>]{1,2}&?\s*/dev/(tcp|udp)/")
    EXEC_FD_PROC         = re.compile(r"(?i)exec\s+[0-9]+[<>]\s*/proc/self/fd/")
    # Arithmetic char-code reconstruction: $((0x63)) etc.
    ARITH_CHARCODE       = re.compile(r"\$\(\([^)]*0x[0-9A-Fa-f]{2}[^)]*\)\)")
    ARITH_DECIMAL_CHAR   = re.compile(
        r"printf\s+['\"]?\\\\?([0-9]{3})['\"]?.*printf\s+['\"]?\\\\?([0-9]{3})['\"]?"
    )
    # mapfile / readarray piped into eval
    MAPFILE_EVAL         = re.compile(
        r"(?i)(mapfile|readarray)\b[^#\n]*(?:\|[^#\n]*(eval|bash|sh|exec)|"
        r"< <\([^)]*\)[^#\n]*(eval|bash))"
    )
    # associative array used as command: "${cmd[@]}" or "${cmd[*]}"
    ASSOC_ARRAY_CMD      = re.compile(r'"\$\{[A-Za-z_]\w*\[@\]\}"|\$\{[A-Za-z_]\w*\[\*\]\}')
    # Shell option tampering before suspicious code
    SHELL_OPT_DISABLE    = re.compile(r"(?i)^[ \t]*set\s+(\+e|\+x|\+v|\-\-)\b|^[ \t]*shopt\s+-u\s+")
    # printf building commands char by char
    PRINTF_CHARBYCHAR    = re.compile(
        r"(?i)(?:printf|echo)\s+['\"][^'\"]{1,4}['\"]\s*(?:printf|echo)\s+['\"][^'\"]{1,4}['\"]"
        r"[^#\n]*(?:printf|echo)\s+['\"][^'\"]{1,4}['\"]"
    )
    # git hook-like scripts committed to repo root
    GIT_HOOK_NAMES       = re.compile(
        r"(?i)^(pre-commit|post-commit|pre-push|pre-receive|post-receive|"
        r"pre-rebase|post-checkout|post-merge|commit-msg|prepare-commit-msg|"
        r"update|post-update|pre-applypatch|applypatch-msg)$"
    )
    # CMake ExternalProject_Add with URL fetch
    CMAKE_EXTERNAL       = re.compile(
        r"(?i)ExternalProject_Add\s*\([^)]*URL\s+https?://"
    )
    # Meson wrap files
    MESON_WRAP           = re.compile(r"(?i)\[(wrap-git|wrap-file|wrap-redirect|wrap-db)\]")
    # npm/pip registry override in config files
    NPM_REGISTRY_TAMPER  = re.compile(
        r"(?i)(npm\s+config\s+set\s+registry|registry\s*=\s*https?://(?!registry\.npmjs\.org))"
    )
    CARGO_REGISTRY       = re.compile(r"(?i)(\[registries\]|\[source\.[^]]+\])")
    PIP_CONF_TAMPER      = re.compile(
        r"(?i)(pip\s+config\s+set.*index-url|index-url\s*=\s*https?://(?!pypi\.org|files\.pythonhosted))"
    )
    # PKGBUILD self-modification
    PKGBUILD_SELF_MOD    = re.compile(r"(?i)(>|>>|tee|cp|mv)[^#\n]*PKGBUILD\b")
    MAKEPKG_RECURSIVE    = re.compile(r"(?i)(^|[ \t;|&])makepkg\b[^#\n]*(--skipinteg|--nosign|--noprogressbar)")
    # configure / Makefile injection
    CONFIGURE_NET        = re.compile(r"(?i)^\s*\./configure\b.*\|\s*(bash|sh|curl|wget)")
    MAKEFILE_NET         = re.compile(r"(?i)^\s*(curl|wget|fetch)\b.*\|\s*(bash|sh|eval)")
    # Backtick command substitution (legacy, harder to see)
    BACKTICK_CMD         = re.compile(r"`[^`]{5,100}`")
    # read line from network into eval
    READ_EVAL            = re.compile(r"(?i)read\b[^#\n]*\|[^#\n]*(eval|bash|sh|exec)")
    # /dev/stdin exec
    STDIN_EXEC           = re.compile(r"(?i)(bash|sh|zsh)[ \t]+/dev/stdin")
    # Char concatenation obfuscation: c=cu; d=rl; $c$d → curl
    CHAR_CONCAT_EXEC     = re.compile(r"\$[A-Za-z_]\w*\$[A-Za-z_]\w*\$[A-Za-z_]\w*")
    # set +e before a download/exec sequence
    SET_E_BEFORE_DL      = re.compile(r"(?i)set\s+\+e[^#\n]*\n[^#\n]*(curl|wget|eval|bash)")
    # Suspicious Python one-liner in shell
    PYTHON_ONE_LINER     = re.compile(
        r"(?i)python3?\s+-c\s+['\"](?:import\s+(?:os|subprocess|socket|urllib|base64|pty)|"
        r"exec\s*\(|eval\s*\(|__import__|open\s*\(['\"])"
    )
    # Source from URL via /dev/stdin
    SOURCE_DEV_STDIN     = re.compile(r"(?i)(curl|wget)[^|#\n]*\|\s*(bash|sh|zsh|dash)\s*/dev/stdin")
    # xargs exec
    XARGS_EXEC           = re.compile(r"(?i)\bxargs\b[^#\n]*\b(bash|sh|eval|python3?|perl|ruby)\b")
    # tee to /etc/* while also executing
    TEE_EXEC             = re.compile(r"(?i)\btee\b[^#\n]*/etc/[^#\n]*&&[^#\n]*(bash|sh|chmod|exec)")
    # Suspicious use of /proc/self/exe
    PROC_SELF_EXE        = re.compile(r"(?i)/proc/self/exe\b")
    # dd for disk write / binary injection
    DD_WRITE             = re.compile(r"(?i)\bdd\b[^#\n]*of=(/dev/[sh]d[a-z]|/dev/nvm|/dev/vd)")
    # curl with --output to a path then chmod+exec
    CURL_CHMOD_EXEC_RE   = re.compile(
        r"(?i)(curl|wget)[^#\n]*(?:-o|-O|--output)\s+(\S+)[^#\n]*\n"
        r"[^#\n]*(chmod[^#\n]*\+x[^#\n]*\2|bash[^#\n]*\2|sh[^#\n]*\2)"
    )
    # Suspicious comment injection: RLO/null inside comments
    COMMENT_INJECTION    = re.compile(r"#[^#\n]*[\x00\u202e\u200b\u200c\u200d]")
    # UID/GID check bypass
    UGID_CHECK           = re.compile(r'(?i)\[\[?\s*\$(?:EUID|UID|ID)\s*(?:!=|-ne)\s*0\s*\]?\]')
    # Double evaluation: eval "$(eval ...)"
    DOUBLE_EVAL          = re.compile(r"(?i)eval\s+['\"]?\$\(\s*eval\b")
    # Base64 decode to file then execute
    B64_TO_FILE_EXEC     = re.compile(
        r"(?i)(base64\s+(--decode|-d)|echo\s+['\"][A-Za-z0-9+/]{20})|"
        r"xxd\s+-r\s+-p\b[^#\n]*>\s*/tmp/"
    )
    # Suspicious file extension masquerading
    MASQUERADE_EXT       = re.compile(r"\b\w+\.(png|jpg|gif|pdf|txt|conf|log|dat)\s*&&|\|\s*\b\w+\.(png|jpg|gif|pdf|txt|conf|log|dat)")
    # v9: precise staged dropper and manifest patterns
    FETCH_OUT_CURL       = re.compile(r"(?i)\b(?:curl|fetch)\b[^#\n]*(?:-o|--output)[ \t=]+(['\"]?)([^'\"\s;&|]+)\1")
    FETCH_OUT_WGET       = re.compile(r"(?i)\bwget\b[^#\n]*(?:-O|--output-document=)[ \t=]*(['\"]?)([^'\"\s;&|]+)\1")
    FETCH_REDIRECT       = re.compile(r"(?i)\b(?:curl|wget|fetch|aria2c)\b[^#\n]*(?:>|1>)[ \t]*(['\"]?)([^'\"\s;&|]+)\1")
    CHMOD_EXEC_PATH      = re.compile(r"(?i)\bchmod\b[^#\n]*(?:\+x|[0-7]*[157][0-7][0-7])[^#\n]*(['\"]?)([^'\"\s;&|]+)\1")
    SHELL_EXEC_PATH      = re.compile(r"(?i)(?:^|[;&|({\s])(?:bash|sh|zsh|dash|exec|source|\.)[ \t]+(['\"]?)([^'\"\s;&|]+)\1")
    DIRECT_EXEC_PATH     = re.compile(r"(?i)(?:^|[;&|({\s])(['\"]?)(\./[^'\"\s;&|]+|/tmp/[^'\"\s;&|]+|/dev/shm/[^'\"\s;&|]+|/var/tmp/[^'\"\s;&|]+|\$[A-Za-z_]\w*|\$\{[A-Za-z_]\w*\})\1(?:[ \t;&|]|$)")
    SIMPLE_PATH_ASSIGN   = re.compile(r"^[ \t]*(?:local[ \t]+)?([A-Za-z_]\w*)=(['\"]?)([^'\"\s;&|]+)\2[ \t]*$")
    NPM_SCRIPT_FIELD     = re.compile(r'"(?:preinstall|install|postinstall|prepare|prepublish|postpack)"\s*:\s*"([^"]+)"')
    CARGO_BUILD_RS       = re.compile(r'(?m)^\s*build\s*=\s*["\']build\.rs["\']')
    GO_REPLACE_REMOTE    = re.compile(r"(?m)^\s*replace\s+\S+\s+=>\s+(?:https?://|git@|ssh://)")
    PY_ALT_INDEX         = re.compile(r"(?i)(index-url|extra-index-url|tool\.poetry\.source|pypi-token|trusted-host)\s*[=:]")
    SOURCE_CMD_SUBST     = re.compile(r"(?i)(`|\$\(|<\(|\$\{[^}]*:[^}]*\})")
    CHECKSUM_ANY_LINE    = re.compile(r"(?im)^[ \t]*(sha(?:1|224|256|384|512)sums|b2sums|md5sums|cksums)(?:_[A-Za-z0-9_]+)?[ \t]*=")
    WEAK_CHECKSUM_LINE   = re.compile(r"(?im)^[ \t]*(md5sums|sha1sums|cksums)(?:_[A-Za-z0-9_]+)?[ \t]*=")
    ARCHIVE_EXT          = re.compile(r"(?i)\.(tar\.(gz|bz2|xz|zst|lz|lzma)|t[bgx]z|zip|7z|rar|jar|war|crate|gem|whl|egg|appimage)$")
    SHELL_META_FILENAME  = re.compile(r"[`$;&|<>]|\s")
    LOCKFILE_INTEGRITY   = re.compile(r"(?i)(integrity|checksum|sha512|sha1|resolved)")
    LOCKFILE_HTTP        = re.compile(r"(?i)(resolved|url|source)[\"'=:\s]+http://")
    LOCKFILE_SCRIPT_HINT = re.compile(r"(?i)(preinstall|postinstall|install script|hasInstallScript|requiresBuild)")
    NPM_HOOK_CONFIG      = re.compile(r"(?i)(ignore-scripts\s*=\s*false|script-shell\s*=|unsafe-perm\s*=\s*true|node-options\s*=)")
    GEM_SOURCE_REMOTE    = re.compile(r"(?im)^\s*source\s+['\"](?!https://rubygems\.org/?['\"])(https?://[^'\"]+)")
    GRADLE_REPO_REMOTE   = re.compile(r"(?i)\b(maven|ivy)\s*\{[^}]*url\s+['\"]http://")
    MAVEN_REPO_REMOTE    = re.compile(r"(?is)<repository>.*?<url>http://")
    CARGO_PATCH_REMOTE   = re.compile(
        r"(?is)(\[patch[^\]]+\][\s\S]{0,1200}?\bgit\s*=\s*['\"]"
        r"(?!https://github\.com/|https://gitlab\.com/)(?:https?://|ssh://|git@)|"
        r"\b(?:git|registry)\s*=\s*['\"](?!https://github\.com/|https://gitlab\.com/|https://crates\.io)"
        r"(?:https?://|ssh://|git@))"
    )
    GO_EXCLUDE_REPLACE   = re.compile(r"(?im)^\s*(replace|exclude)\s+")
    # v11: Bash grammar/state evasions
    ANSI_C_QUOTED        = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
    PRINTF_V_ASSIGN      = re.compile(
        r"(?i)^[ \t]*(?:builtin[ \t]+|command[ \t]+)?printf[ \t]+(?:-[A-Za-z]*v[A-Za-z]*|-[A-Za-z]*[ \t]+-v)[ \t]+([A-Za-z_]\w*)[ \t]+(.+)$"
    )
    PARAM_TRANSFORM      = re.compile(
        r"\$\{[A-Za-z_]\w*(?::[-+?=]?|/[^\}]*|#[^\}]*|%[^\}]*|\^\^?|,,?)[^}]*\}"
    )
    MUTATED_UNKNOWN      = re.compile(r"__YSHIELD_MUTATED_UNKNOWN__")
    UNKNOWN_EXEC_SINK    = re.compile(
        r"(?i)(?:^|[;|&({\s])(?:eval|source|\.|exec|bash|sh|zsh|dash|python3?|perl|ruby)\b|"
        r"^\s*__YSHIELD_MUTATED_UNKNOWN__\b|\|\s*__YSHIELD_MUTATED_UNKNOWN__\b"
    )
    ARRAY_INDEX_REF      = re.compile(r"\$\{([A-Za-z_]\w*)\[([^]\}]+)\]\}")
    DYNAMIC_ARRAY_INDEX  = re.compile(r"\$\{[A-Za-z_]\w*\[(?:\$|\$\{|`|\$\(|[^0-9@*'\"][^]\}]*)")
    FILE_TAINT_WRITE     = re.compile(r"(?:>|>>|1>)[ \t]*(['\"]?)([^'\"\s;&|]+)\1|\btee(?:[ \t]+-a)?[ \t]+(['\"]?)([^'\"\s;&|]+)\3")
    FILE_TAINT_READ      = re.compile(r"(?i)\b(?:cat|source|\.)[ \t]+(['\"]?)([^'\"\s;&|]+)\1|<[ \t]*(['\"]?)([^'\"\s;&|]+)\3")
    INSTALL_ASSIGN       = re.compile(r"(?m)^[ \t]*install[ \t]*=[ \t]*(['\"]?)([^'\"\s#]+)\1")
    BUILD_RS_FILE        = re.compile(r"(?i)(^|/)build\.rs$")
    SETUP_PY_FILE        = re.compile(r"(?i)(^|/)setup\.py$")
    MAKEFILE_FILE        = re.compile(r"(?i)(^|/)(Makefile|makefile|GNUmakefile)$")
    DOWNSTREAM_HOOK_FILE = re.compile(
        r"(?i)(^|/)(build\.rs|setup\.py|setup\.cfg|pyproject\.toml|package\.json|"
        r"CMakeLists\.txt|meson\.build|Makefile|makefile|GNUmakefile|Rakefile|build\.gradle|pom\.xml)$"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Homoglyph / Unicode detection
# ─────────────────────────────────────────────────────────────────────────────

HOMOGLYPH_MAP: Dict[str, str] = {
    'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y','і':'i','ї':'i',
    'А':'A','В':'B','Е':'E','К':'K','М':'M','Н':'H','О':'O','Р':'P','С':'C',
    'Т':'T','У':'Y','Х':'X','Ь':'b','Ѕ':'S','ѕ':'s',
    'ο':'o','ρ':'p','υ':'u','ν':'v','η':'n','α':'a','ε':'e','ι':'i','κ':'k',
    'μ':'u','τ':'t','ω':'w',
    'ℓ':'l','Ι':'I','Ο':'O',
    '⁰':'0','¹':'1','²':'2','³':'3',
    '\u200b':'','\u200c':'','\u200d':'','\ufeff':'',
    '\u2060':'','\u2061':'','\u2062':'','\u2063':'',
}

def normalize_homoglyphs(text: str) -> str:
    text = unicodedata.normalize('NFKC', text)
    return ''.join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)

def has_homoglyphs(text: str) -> bool:
    for ch in text:
        if ch in HOMOGLYPH_MAP:
            return True
        if unicodedata.category(ch) in ('Cf', 'Mn') and ch not in ' \t\n':
            return True
    return False

def has_punycode_domain(url: str) -> bool:
    try:
        return 'xn--' in urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return False

def check_url_homoglyphs(url: str) -> Optional[str]:
    try:
        host = urllib.parse.urlparse(url).netloc
    except Exception:
        return None
    if not host:
        return None
    if has_homoglyphs(host):
        normalized = normalize_homoglyphs(host)
        if normalized != host:
            return f"URL host '{host}' contains homoglyph/confusable chars → '{normalized}'"
    if has_punycode_domain(url):
        return f"URL contains punycode domain (xn--) — possible homoglyph attack: {url[:80]}"
    return None

def check_rlo_attack(text: str) -> Optional[str]:
    if _P.RLO_ATTACK.search(text):
        offending = [hex(ord(c)) for c in text if unicodedata.category(c) in ('Cf',) and ord(c) in
                     (0x202e, 0x202d, 0x202c, 0x202b, 0x202a, 0x200f, 0x200e)]
        return f"Bidirectional text override characters detected ({offending}) — filename/URL disguise attack"
    return None

# ─────────────────────────────────────────────────────────────────────────────
# v8 Arithmetic char-code decoder
# ─────────────────────────────────────────────────────────────────────────────

def try_arith_charcode_decode(line: str) -> Optional[str]:
    """
    Attempt to decode arithmetic char-code patterns like:
    printf "\\x$(printf '%x' $((0x63)))..." → "c..."
    Returns reconstructed string if suspicious, else None.
    """
    if not YSHIELD_ARITH_CHARCODE:
        return None
    # Find sequences of $((N)) where N is 32..126 (printable ASCII)
    hits = re.findall(r'\$\(\(([^)]+)\)\)', line)
    chars = []
    for expr in hits:
        expr = expr.strip()
        try:
            val = int(expr, 0)  # handles 0x hex and decimal
            if 32 <= val <= 126:
                chars.append(chr(val))
        except ValueError:
            pass
    if len(chars) >= 3:
        reconstructed = ''.join(chars)
        return reconstructed
    return None

# ─────────────────────────────────────────────────────────────────────────────
# v11 Bash eager decoder / deterministic expansion helpers
# ─────────────────────────────────────────────────────────────────────────────

_ANSI_SIMPLE_ESCAPES = {
    "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
    "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\",
    "'": "'", '"': '"', "?": "?",
}

def decode_bash_ansi_c_body(body: str) -> str:
    """
    Decode the escape forms Bash accepts in $'...'. This is intentionally
    bounded and non-executing; unsupported escapes are kept literal.
    """
    out: List[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\" or i + 1 >= len(body):
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in _ANSI_SIMPLE_ESCAPES:
            out.append(_ANSI_SIMPLE_ESCAPES[nxt])
            i += 2
            continue
        if nxt == "x":
            m = re.match(r"x([0-9A-Fa-f]{1,2})", body[i + 1:])
            if m:
                out.append(chr(int(m.group(1), 16)))
                i += 1 + len(m.group(0))
                continue
        if nxt == "u":
            m = re.match(r"u([0-9A-Fa-f]{1,4})", body[i + 1:])
            if m:
                out.append(chr(int(m.group(1), 16)))
                i += 1 + len(m.group(0))
                continue
        if nxt == "U":
            m = re.match(r"U([0-9A-Fa-f]{1,8})", body[i + 1:])
            if m:
                try:
                    out.append(chr(int(m.group(1), 16)))
                except ValueError:
                    out.append("\\" + m.group(0))
                i += 1 + len(m.group(0))
                continue
        if nxt in "01234567":
            m = re.match(r"([0-7]{1,3})", body[i + 1:])
            if m:
                out.append(chr(int(m.group(1), 8)))
                i += 1 + len(m.group(1))
                continue
        if nxt == "c" and i + 2 < len(body):
            out.append(chr(ord(body[i + 2].upper()) & 0x1F))
            i += 3
            continue
        out.append(nxt)
        i += 2
    return "".join(out)

def decode_bash_ansi_c_quotes(line: str) -> Tuple[str, bool]:
    if not YSHIELD_BASH_EAGER_DECODE:
        return line, False
    changed = False

    def _sub(m: re.Match) -> str:
        nonlocal changed
        changed = True
        return shlex.quote(decode_bash_ansi_c_body(m.group(1)))

    return _P.ANSI_C_QUOTED.sub(_sub, line), changed

def decode_printf_format_string(fmt: str) -> str:
    text = shell_unquote(fmt.strip())
    return decode_bash_ansi_c_body(text)

def _resolve_param_expr(expr: str, var_map: Dict[str, str]) -> str:
    inner = expr[2:-1]
    name_match = re.match(r"([A-Za-z_]\w*)", inner)
    if not name_match:
        return "__YSHIELD_MUTATED_UNKNOWN__"
    name = name_match.group(1)
    value = var_map.get(name)
    if value is None:
        return "__YSHIELD_MUTATED_UNKNOWN__"
    op = inner[len(name):]
    try:
        if op == "":
            return value
        if op in ("^^", "^"):
            return value.upper()
        if op in (",,", ","):
            return value.lower()
        if op.startswith(":"):
            parts = op[1:].split(":")
            if not parts or not re.fullmatch(r"-?\d+", parts[0]):
                return "__YSHIELD_MUTATED_UNKNOWN__"
            start = int(parts[0])
            if len(parts) == 1 or parts[1] == "":
                return value[start:]
            if not re.fullmatch(r"-?\d+", parts[1]):
                return "__YSHIELD_MUTATED_UNKNOWN__"
            length = int(parts[1])
            return value[start:start + length]
        if op.startswith("/"):
            glob = op.startswith("//")
            rest = op[2:] if glob else op[1:]
            if "/" not in rest:
                return "__YSHIELD_MUTATED_UNKNOWN__"
            needle, repl = rest.split("/", 1)
            if any(x in needle for x in ("*", "?", "[", "]", "$", "`", "\\")):
                return "__YSHIELD_MUTATED_UNKNOWN__"
            repl = repl.replace(r"\/", "/")
            return value.replace(needle, repl) if glob else value.replace(needle, repl, 1)
    except Exception:
        return "__YSHIELD_MUTATED_UNKNOWN__"
    return "__YSHIELD_MUTATED_UNKNOWN__"

def resolve_shell_expansions_in_line(line: str, var_map: Dict[str, str]) -> str:
    if not var_map:
        return line

    def _array_sub(m: re.Match) -> str:
        arr, idx = m.group(1), shell_unquote(m.group(2).strip())
        if idx in ("@", "*"):
            return var_map.get(arr, m.group(0))
        if idx.isdigit():
            return var_map.get(f"{arr}[{idx}]", "__YSHIELD_MUTATED_UNKNOWN__")
        return "__YSHIELD_MUTATED_UNKNOWN__"

    line = _P.ARRAY_INDEX_REF.sub(_array_sub, line)
    if YSHIELD_PARAM_TRANSFORM_TRACK:
        line = _P.PARAM_TRANSFORM.sub(lambda m: _resolve_param_expr(m.group(0), var_map), line)
    return resolve_vars_in_line(line, var_map)

# ─────────────────────────────────────────────────────────────────────────────
# Semantic PKGBUILD variable resolver
# ─────────────────────────────────────────────────────────────────────────────

_SIMPLE_VAR_RE  = re.compile(
    r"^[ \t]*(?:(?:export|local|declare|typeset|readonly)(?:[ \t]+-[A-Za-z]+)*[ \t]+)?"
    r"([A-Za-z_]\w*)=([^\n]*)$"
)
_APPEND_VAR_RE  = re.compile(
    r"^[ \t]*(?:(?:export|local|declare|typeset)(?:[ \t]+-[A-Za-z]+)*[ \t]+)?"
    r"([A-Za-z_]\w*)\+=([^\n]*)$"
)
_ARRAY_VAR_RE   = re.compile(
    r"^[ \t]*(?:(?:declare|typeset|local)(?:[ \t]+-[A-Za-z]+)*[ \t]+)?"
    r"([A-Za-z_]\w*)=\(([^)]*)\)[ \t]*$"
)
_VAR_REF_RE     = re.compile(r"\$\{?([A-Za-z_]\w*)\}?")
_COMMAND_SUB_RE = re.compile(r"`|\$\(")

def extract_pkgbuild_vars(text: str) -> Dict[str, str]:
    raw: Dict[str, str] = {}
    for line in text.splitlines():
        line = effective_shell_line(line)
        line, _ = decode_bash_ansi_c_quotes(line)
        if not line or _P.COMMENT.match(line):
            continue
        pm = _P.PRINTF_V_ASSIGN.match(line)
        if pm:
            name = pm.group(1)
            words = shell_words(pm.group(2))
            if words:
                fmt = words[0]
                args = words[1:]
                decoded = decode_printf_format_string(fmt)
                if "%s" in decoded and args:
                    try:
                        decoded = decoded % tuple(args)
                    except Exception:
                        pass
                if not _COMMAND_SUB_RE.search(decoded) and len(decoded) <= 512:
                    raw[name] = decoded
            continue
        am = _ARRAY_VAR_RE.match(line)
        if am:
            name, body = am.group(1), am.group(2)
            if not _COMMAND_SUB_RE.search(body):
                words = shell_words(body)
                if words and sum(len(w) for w in words) <= 256:
                    raw[name] = " ".join(words)
                    if YSHIELD_ARRAY_INDEX_TRACK:
                        for idx, word in enumerate(words):
                            raw[f"{name}[{idx}]"] = word
            continue
        m = _SIMPLE_VAR_RE.match(line)
        if m:
            name, value = m.group(1), shell_unquote(m.group(2))
            if not _COMMAND_SUB_RE.search(value) and len(value) <= 512:
                raw[name] = value
            continue
        m = _APPEND_VAR_RE.match(line)
        if m:
            name, value = m.group(1), shell_unquote(m.group(2))
            if not _COMMAND_SUB_RE.search(value) and len(value) <= 512:
                raw[name] = raw.get(name, "") + value
    for _ in range(3):
        for k, v in list(raw.items()):
            def _sub(mo: re.Match) -> str:
                return raw.get(mo.group(1), mo.group(0))
            raw[k] = _VAR_REF_RE.sub(_sub, v)
    return raw

def resolve_vars_in_line(line: str, var_map: Dict[str, str]) -> str:
    def _sub(mo: re.Match) -> str:
        return var_map.get(mo.group(1), mo.group(0))
    return _VAR_REF_RE.sub(_sub, line)

@dataclass
class ShellArrayBlock:
    name:    str
    line:    int
    body:    str
    values:  List[str]
    closed:  bool = True

def _strip_assignment_prefix(line: str) -> str:
    return re.sub(r"^[ \t]*[A-Za-z_]\w*(?:_[A-Za-z0-9_]+)?\+?=[ \t]*\(", "", line, count=1)

def extract_shell_array_blocks(text: str, base_names: Set[str]) -> List[ShellArrayBlock]:
    """
    Statically extract simple Bash array assignment bodies without executing
    PKGBUILD code. This is intentionally conservative; malformed arrays are
    returned as closed=False so callers can fail closed.
    """
    blocks: List[ShellArrayBlock] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = effective_shell_line(lines[i])
        m = re.match(r"^[ \t]*([A-Za-z_]\w*)(?:_[A-Za-z0-9_]+)?\+?=[ \t]*\(", raw)
        if not m:
            i += 1
            continue
        base = re.sub(
            r"_(?:x86_64|i686|aarch64|armv7h|armv6h|riscv64|pentium4|loongarch)$",
            "", m.group(1).lower(),
        )
        if base not in base_names:
            i += 1
            continue

        start = i + 1
        parts = [_strip_assignment_prefix(raw)]
        depth = raw.count("(") - raw.count(")")
        closed = depth <= 0
        i += 1
        while i < len(lines) and not closed:
            line = effective_shell_line(lines[i])
            parts.append(line)
            depth += line.count("(") - line.count(")")
            if depth <= 0:
                closed = True
                break
            i += 1

        body = "\n".join(parts)
        if closed:
            body = re.sub(r"\)[ \t]*$", "", body.strip(), count=1)
        try:
            values = shell_words(body)
        except Exception:
            values = []
        blocks.append(ShellArrayBlock(base, start, body, values, closed))
        i += 1
    return blocks

def _is_remote_source(value: str) -> bool:
    value = value.split("::", 1)[-1]
    return bool(re.match(r"(?i)^(https?|ftp|git|hg|svn|bzr)\+|^(https?|ftp|git|ssh)://|^git@", value))

def _source_without_fragment(value: str) -> str:
    return value.split("::", 1)[-1].split("#", 1)[0]

def _is_vcs_source(value: str) -> bool:
    value = value.split("::", 1)[-1].lower()
    return value.startswith(("git+", "hg+", "svn+", "bzr+")) or value.endswith((".git",))

def _is_checksum_skip(value: str) -> bool:
    return value.strip().strip("'\"").upper() == "SKIP"

# ─────────────────────────────────────────────────────────────────────────────
# Popular package corpus (typosquat detection)
# ─────────────────────────────────────────────────────────────────────────────

_POPULAR_CACHE_FILE_OFFICIAL = CACHE_DIR / "popular_official.txt"
_POPULAR_CACHE_FILE_AUR      = CACHE_DIR / "popular_aur.txt"
_popular_lock = threading.Lock()
_official_names_cache: Optional[FrozenSet[str]] = None
_popular_names_cache:  Optional[FrozenSet[str]] = None

def _cache_stale(path: Path) -> bool:
    try:
        return (time.time() - path.stat().st_mtime) > YSHIELD_POPULAR_CACHE_TTL
    except OSError:
        return True

def _load_official_packages() -> FrozenSet[str]:
    global _official_names_cache
    with _popular_lock:
        if _official_names_cache is not None:
            return _official_names_cache
        if not _cache_stale(_POPULAR_CACHE_FILE_OFFICIAL):
            try:
                names = frozenset(
                    ln.strip() for ln in _POPULAR_CACHE_FILE_OFFICIAL
                        .read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()
                )
                _official_names_cache = names
                return names
            except Exception:
                pass
        debug("Refreshing official package list via pacman -Slq …")
        cp = run(["pacman", "-Slq"], capture_output=True, check=False, timeout=30)
        if cp.returncode != 0 or not cp.stdout:
            _official_names_cache = frozenset()
            return _official_names_cache
        names = frozenset(ln.strip() for ln in cp.stdout.splitlines() if ln.strip())
        try:
            _POPULAR_CACHE_FILE_OFFICIAL.write_text("\n".join(sorted(names)) + "\n", encoding="utf-8")
        except Exception:
            pass
        _official_names_cache = names
        return names

def _load_popular_aur_packages() -> FrozenSet[str]:
    global _popular_names_cache
    with _popular_lock:
        if _popular_names_cache is not None:
            return _popular_names_cache
        if not _cache_stale(_POPULAR_CACHE_FILE_AUR):
            try:
                names = frozenset(
                    ln.strip() for ln in _POPULAR_CACHE_FILE_AUR
                        .read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()
                )
                _popular_names_cache = names
                return names
            except Exception:
                pass
        popular: FrozenSet[str] = _BUILTIN_POPULAR_AUR
        _popular_names_cache = popular
        try:
            _POPULAR_CACHE_FILE_AUR.write_text("\n".join(sorted(popular)) + "\n", encoding="utf-8")
        except Exception:
            pass
        return popular

def get_typosquat_corpus() -> FrozenSet[str]:
    return _load_official_packages() | _load_popular_aur_packages()

_BUILTIN_POPULAR_AUR: FrozenSet[str] = frozenset({
    "firefox", "chromium", "google-chrome", "brave", "vivaldi", "opera",
    "discord", "slack-desktop", "telegram-desktop", "signal-desktop",
    "spotify", "zoom", "teams-for-linux", "skypeforlinux",
    "visual-studio-code-bin", "code", "sublime-text", "atom",
    "vim", "neovim", "emacs", "gimp", "inkscape", "blender", "vlc", "mpv",
    "obs-studio", "steam", "lutris", "wine", "docker", "docker-compose",
    "virtualbox", "qemu", "git", "nodejs", "npm", "python", "python3",
    "gcc", "clang", "rustup", "go", "jdk-openjdk", "postgresql", "mysql",
    "mariadb", "redis", "mongodb", "nginx", "apache", "openssh", "openssl",
    "curl", "wget", "htop", "tmux", "zsh", "bash", "fish", "fzf", "ripgrep",
    "fd", "bat", "exa", "neofetch", "ufw", "networkmanager", "bluez",
    "pulseaudio", "pipewire", "alsa-utils", "xorg-server", "wayland",
    "sway", "i3-wm", "hyprland", "gnome-shell", "plasma-desktop", "dolphin",
    "nautilus", "thunar", "gparted", "timeshift", "grub", "systemd",
    "openvpn", "wireguard-tools", "syncthing", "nextcloud-client",
    "dropbox", "transmission-cli", "qbittorrent", "deluge", "audacity",
    "kdenlive", "handbrake", "ffmpeg", "imagemagick", "libreoffice-fresh",
    "libreoffice-still", "thunderbird", "evolution", "keepassxc",
    "bitwarden", "protonvpn", "tor-browser", "anydesk", "teamviewer",
    "ngrok", "balena-etcher", "postman-bin", "insomnia", "jetbrains-toolbox",
    "android-studio", "flutter", "dotnet-sdk", "mono", "lazygit",
    "github-cli", "lf", "ranger", "mc", "yay", "paru", "pamac",
    "nvm", "pyenv", "rbenv", "sdkman", "asdf", "direnv",
    "vesktop", "webcord", "element-desktop",
    "1password", "bitwarden-desktop", "enpass", "dashlane",
    "linux", "linux-zen", "linux-lts", "linux-hardened",
    "mesa", "vulkan-radeon", "nvidia", "nvidia-dkms",
    "spotify-adblock", "spotify-launcher",
    "python-pip", "python-setuptools", "python-wheel",
    "nerd-fonts-complete", "ttf-ms-fonts",
    "brave-bin", "google-chrome-beta", "firefox-nightly",
    "mullvad-vpn", "expressvpn", "nordvpn-bin",
    "discord-ptb", "discord-canary", "betterdiscord-installer",
    "whatsapp-nativefier", "whatsdesk",
    "cursor-bin", "zed", "lapce", "helix",
    "wezterm", "alacritty", "kitty", "foot",
    "picom", "dunst", "rofi", "wofi", "eww",
    "polybar", "waybar", "ags",
    "timeshift-autosnap", "snapper",
    "supergfxctl", "asusctl",
    "steam-native-runtime",
    "proton-ge-custom-bin", "wine-staging", "wine-ge-custom",
    "mangohud", "goverlay",
    "gamemode",
    "lutris-git", "heroic-games-launcher-bin",
    "xdman", "motrix-appimage",
    "btrfs-assistant",
    "mission-center", "resources",
})

LEGITIMATE_VARIANT_SUFFIXES = (
    "-git", "-bin", "-svn", "-hg", "-bzr", "-nightly", "-beta", "-dev",
    "-debug", "-stable", "-libre", "-patched", "-fix", "-old", "-legacy",
    "-appimage", "-electron", "-wayland", "-x11", "-minimal", "-full",
    "-gtk", "-qt", "-cli", "-gui", "-server", "-client", "-lts", "-zen",
    "-adblock", "-native", "-runtime", "-launcher", "-installer",
)

def looks_like_legitimate_variant(pkg: str, popular: str) -> bool:
    if pkg == popular: return True
    for suf in LEGITIMATE_VARIANT_SUFFIXES:
        if pkg == popular + suf or popular == pkg + suf:
            return True
    if pkg.startswith(popular + "-") or popular.startswith(pkg + "-"):
        return True
    return False

def _typosquat_variations(pkg: str) -> bool:
    """Return True if pkg looks like a typosquat of any popular package via multiple methods."""
    pkg_l    = pkg.lower()
    pkg_norm = normalize_homoglyphs(pkg_l)
    corpus   = get_typosquat_corpus()

    for popular in corpus:
        if pkg_l == popular:
            return False  # exact match = not a typosquat
        if looks_like_legitimate_variant(pkg_l, popular):
            continue
        if abs(len(pkg_norm) - len(popular)) > YSHIELD_TYPOSQUAT_MAX_DISTANCE + 1:
            continue

        # Standard Levenshtein
        ld = levenshtein(pkg_norm, popular)
        if 0 < ld <= YSHIELD_TYPOSQUAT_MAX_DISTANCE:
            return True

        # Keyboard adjacency check (only for same-length strings)
        if YSHIELD_KEYBOARD_TYPOSQUAT and len(pkg_norm) == len(popular):
            kd = keyboard_distance(pkg_norm, popular)
            if 0 < kd <= 1:
                return True

    return False

def check_typosquat(pkg: str) -> List[Tuple[str, int, str]]:
    """Return list of (popular_name, distance, method) tuples."""
    pkg_l    = pkg.lower()
    pkg_norm = normalize_homoglyphs(pkg_l)
    corpus   = get_typosquat_corpus()
    hits: List[Tuple[str, int, str]] = []

    for popular in corpus:
        if pkg_l == popular:
            continue
        if looks_like_legitimate_variant(pkg_l, popular):
            continue
        if abs(len(pkg_norm) - len(popular)) > YSHIELD_TYPOSQUAT_MAX_DISTANCE + 1:
            continue

        ld = levenshtein(pkg_norm, popular)
        if 0 < ld <= YSHIELD_TYPOSQUAT_MAX_DISTANCE:
            hits.append((popular, ld, "levenshtein"))
            continue

        # Keyboard adjacency
        if YSHIELD_KEYBOARD_TYPOSQUAT and len(pkg_norm) == len(popular):
            kd = keyboard_distance(pkg_norm, popular)
            if 0 < kd <= 1:
                hits.append((popular, kd, "keyboard-adj"))
                continue

        # Doubled-letter: curl → curll
        for i in range(len(popular)):
            if popular[:i] + popular[i] + popular[i:] == pkg_norm:
                hits.append((popular, 1, "doubled-letter"))
                break

        # Transposition: ab → ba
        if len(pkg_norm) == len(popular):
            diffs = [(a, b) for a, b in zip(pkg_norm, popular) if a != b]
            if len(diffs) == 2 and diffs[0] == (diffs[1][1], diffs[1][0]):
                hits.append((popular, 1, "transposition"))

    hits.sort(key=lambda t: t[1])
    return hits[:5]

# ─────────────────────────────────────────────────────────────────────────────
# TOCTOU
# ─────────────────────────────────────────────────────────────────────────────

def snapshot_repo(repo_dir: Path) -> Tuple[str, Dict[str, str]]:
    cp = git("rev-parse", "HEAD", cwd=repo_dir, capture_output=True)
    head_commit = (cp.stdout or "").strip()
    file_hashes: Dict[str, str] = {}
    ls_cp = git("ls-files", "-z", cwd=repo_dir, capture_output=True)
    for rel in (ls_cp.stdout or "").split("\0"):
        if not rel:
            continue
        p = repo_dir / rel
        if p.is_file():
            try:
                file_hashes[rel] = sha256_file(p)
            except OSError:
                pass
    return head_commit, file_hashes

def verify_toctou(pkgbase: str, saved_commit: str, scan: "PackageScan") -> bool:
    if not saved_commit:
        return True
    debug(f"TOCTOU check: ls-remote for {pkgbase}")
    try:
        cp = run(
            ["git", "ls-remote", f"{AUR_GIT}/{pkgbase}.git", "HEAD"],
            capture_output=True, check=False, timeout=15,
        )
        lines = (cp.stdout or "").strip().splitlines()
        if not lines:
            warn("TOCTOU: Could not reach AUR remote.")
            return True
        live_commit = lines[0].split()[0]
    except Exception as exc:
        warn(f"TOCTOU: Remote verification failed ({exc}); proceeding with caution.")
        return True
    if live_commit != saved_commit:
        print(
            f"\n{C['red']}⛔  TOCTOU ALERT — AUR repo changed between scan and install!{C['nc']}\n"
            f"   Scanned commit : {C['yellow']}{saved_commit}{C['nc']}\n"
            f"   Current commit : {C['red']}{live_commit}{C['nc']}\n"
        )
        scan.add("CRITICAL", "TOCTOU", 0,
                 f"AUR repo HEAD changed: {saved_commit[:12]} → {live_commit[:12]}",
                 category="toctou_changed")
        return False
    info("TOCTOU verification passed — AUR commit unchanged. ✓")
    return True

# ─────────────────────────────────────────────────────────────────────────────
# Build system detection (v8: deeper)
# ─────────────────────────────────────────────────────────────────────────────

_BUILD_SYS_PATTERNS: Dict[str, re.Pattern] = {
    "cmake":     re.compile(r"(?mi)^\s*cmake\b|CMakeLists\.txt"),
    "meson":     re.compile(r"(?mi)^\s*meson\b|meson\.build"),
    "cargo":     re.compile(r"(?mi)^\s*cargo\b|Cargo\.toml"),
    "go":        re.compile(r"(?mi)^\s*go\s+build\b|go\.mod"),
    "python":    re.compile(r"(?mi)^\s*python3?\s+setup\.py|pyproject\.toml|setup\.cfg"),
    "node":      re.compile(r"(?mi)^\s*npm\b|package\.json"),
    "make":      re.compile(r"(?mi)^\s*make\b|Makefile"),
    "autotools": re.compile(r"(?mi)^\s*(./configure|autoreconf|automake)\b"),
    "qmake":     re.compile(r"(?mi)\.pro\b|qmake\b"),
    "scons":     re.compile(r"(?mi)\bscons\b|SConstruct"),
    "electron":  re.compile(r"(?mi)\belectron\b"),
    "perl":      re.compile(r"(?mi)^\s*perl\b.*Makefile\.PL|Makefile\.PL"),
    "ruby":      re.compile(r"(?mi)^\s*gem\b|Gemfile|\.gemspec"),
    "java":      re.compile(r"(?mi)^\s*(mvn|gradle|ant)\b|pom\.xml|build\.gradle"),
    "dotnet":    re.compile(r"(?mi)^\s*dotnet\b|\.csproj|\.sln"),
    "zig":       re.compile(r"(?mi)^\s*zig\b|build\.zig"),
    "nim":       re.compile(r"(?mi)^\s*nim\b|\.nimble"),
    "haskell":   re.compile(r"(?mi)^\s*(cabal|stack)\b|\.cabal|stack\.yaml"),
    "dlang":     re.compile(r"(?mi)^\s*dub\b|dub\.json|dub\.sdl"),
}

def detect_build_system(text: str) -> Set[str]:
    return {name for name, pat in _BUILD_SYS_PATTERNS.items() if pat.search(text)}

def package_type_hints(pkgname: str) -> Set[str]:
    hints: Set[str] = set()
    n = pkgname.lower()
    if n.endswith("-bin"):                              hints.add("binary")
    if n.endswith("-git"):                              hints.add("vcs")
    if n.endswith(("-appimage",)):                      hints.add("appimage")
    if n.endswith(("-svn", "-hg", "-bzr")):             hints.add("vcs")
    if n.endswith("-electron") or "electron" in n:      hints.add("electron")
    if "-nightly" in n:                                 hints.add("nightly")
    if n.endswith(("-dkms",)):                          hints.add("kernel")
    if re.search(r"(?i)(lib|python-|perl-|ruby-|go-|rust-)", n):
        hints.add("library")
    return hints

# ─────────────────────────────────────────────────────────────────────────────
# v8 Source URL cross-reference
# ─────────────────────────────────────────────────────────────────────────────

def check_source_url_crossref(scan: "PackageScan", data: str) -> None:
    if not YSHIELD_SRC_CROSSREF:
        return
    url_m = _P.URL_FIELD_RE.search(data)
    if not url_m:
        return
    upstream_url  = url_m.group(1)
    try:
        upstream_host = urllib.parse.urlparse(upstream_url).netloc.lower()
        upstream_root = ".".join(upstream_host.rsplit(".", 2)[-2:])
    except Exception:
        return

    TRUSTED_CDN_ROOTS = {
        "github.com", "githubusercontent.com", "gitlab.com",
        "bitbucket.org", "sourceforge.net", "launchpad.net",
        "gnu.org", "kernel.org", "gnome.org", "kde.org",
        "freedesktop.org", "python.org", "pypi.org", "npmjs.com",
        "crates.io", "rubygems.org", "go.dev", "google.com",
        "googleapis.com", "electronjs.org", "nodejs.org",
        "archlinux.org", "aur.archlinux.org",
        "download.qt.io", "winehq.org", "msys2.org",
    }

    for block_m in re.finditer(r"(?ms)^\s*source(?:_\w+)?\+?=\s*\(([^)]*)\)", data):
        for entry in re.findall(r"""['"]?(?:[^:\s'"]+::)?(https?://[^'"\s#]+)['"]?""", block_m.group(1)):
            try:
                src_host = urllib.parse.urlparse(entry).netloc.lower()
                src_root = ".".join(src_host.rsplit(".", 2)[-2:])
            except Exception:
                continue
            if not src_root:
                continue
            if src_root in TRUSTED_CDN_ROOTS:
                continue
            if src_root == upstream_root:
                continue
            scan.add("HIGH", "PKGBUILD (source cross-ref)", 0,
                     f"source=() downloads from '{src_root}' but url= declares '{upstream_root}' "
                     "— host mismatch may indicate supply-chain substitution",
                     evidence=entry[:120],
                     confidence=0.80, category="src_crossref")

# ─────────────────────────────────────────────────────────────────────────────
# v8 Dependency confusion
# ─────────────────────────────────────────────────────────────────────────────

def check_dependency_confusion(scan: "PackageScan", data: str) -> None:
    if not YSHIELD_DEP_CONFUSION:
        return
    m = _P.PROVIDES_FIELD_RE.search(data)
    if not m:
        return
    provided = re.findall(r"['\"]?([A-Za-z0-9._+@\-]+)(?:=[^'\"'\s,]+)?['\"]?", m.group(1))
    for name in provided:
        name = name.strip()
        if not name or name == scan.pkg:
            continue
        if is_official_repo_package(name):
            scan.add("HIGH", "PKGBUILD (provides)", 0,
                     f"Package provides='{name}' which shadows an official repository package "
                     "— classic dependency-confusion attack vector",
                     category="dep_confusion_provides",
                     confidence=0.9)

# ─────────────────────────────────────────────────────────────────────────────
# v8 Active base64 decoder
# ─────────────────────────────────────────────────────────────────────────────

def try_active_b64_decode(scan: "PackageScan", rel: str, line_no: int,
                           line: str, scope: str, is_install_file: bool) -> None:
    if not YSHIELD_ACTIVE_B64_DECODE:
        return

    SHELL_PATTERNS_FOR_DECODED = [
        re.compile(r"(?i)(rm\s+-rf|wget|curl|bash|/bin/sh|eval|base64)"),
        _P.DANGEROUS_PIPE, _P.EVAL, _P.ROOT_DELETE,
        _P.DEV_TCP, _P.NC_EXEC, _P.MINER, _P.SUDOERS, _P.SHELL_C,
    ]

    for blob in _P.B64_BLOB_RE.findall(line):
        padded = blob + "=" * ((-len(blob)) % 4)
        try:
            decoded_bytes = base64.b64decode(padded)
            decoded = decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            continue
        has_shell = any(p.search(decoded) for p in SHELL_PATTERNS_FOR_DECODED)
        if has_shell:
            scan.add("CRITICAL", rel, line_no,
                     f"Active base64 decode reveals shell payload: {decoded[:80]}",
                     evidence=f"blob: {blob[:60]}… → decoded: {decoded[:120]}",
                     confidence=0.97, category="active_b64",
                     scope=scope, is_install_file=is_install_file)
        elif len(decoded) > 8 and shannon_entropy(decoded) < 3.0:
            scan.add("MEDIUM", rel, line_no,
                     f"Base64 blob decodes to readable text (possible encoded command): {decoded[:80]}",
                     evidence=f"decoded: {decoded[:120]}",
                     confidence=0.70, category="active_b64",
                     scope=scope, is_install_file=is_install_file)

# ─────────────────────────────────────────────────────────────────────────────
# v8 Systemd / Desktop file scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_service_file(scan: "PackageScan", rel: str, path: Path) -> None:
    if not YSHIELD_SERVICE_SCAN:
        return
    try:
        text = read_text(path)
    except Exception:
        return
    is_desktop = rel.endswith(".desktop")
    pattern    = _P.DESKTOP_EXEC_RE if is_desktop else _P.SERVICE_EXECSTART_RE

    for i, line in enumerate(text.splitlines(), 1):
        m = pattern.match(line)
        if not m:
            continue
        cmd = m.group(1).strip()
        if any(p.search(cmd) for p in [
            _P.DANGEROUS_PIPE, _P.EVAL, _P.DECODE,
            _P.MINER, _P.DEV_TCP, _P.NC_EXEC, _P.SOCAT_EXEC,
            _P.SUDOERS, _P.CURL_SILENT_OUT,
            re.compile(r"(?i)(python3?|perl|ruby)[ \t]+-c"),
            _P.PROC_SUB_NET,
        ]):
            scan.add("CRITICAL", rel, i,
                     f"Suspicious command in {'Exec=' if is_desktop else 'ExecStart='}: {cmd[:100]}",
                     evidence=line, confidence=0.90,
                     category="service_exec", scope="external")
        elif any(p.search(cmd) for p in [
            _P.SECRET_DIR, _P.TOKEN, _P.SUDO,
            _P.ADMIN_CMD, _P.SHELL_RC,
            re.compile(r"(?i)/tmp/|/dev/shm/"),
        ]):
            scan.add("HIGH", rel, i,
                     f"Potentially privileged command in {'Exec=' if is_desktop else 'ExecStart='}: {cmd[:100]}",
                     evidence=line, confidence=0.80,
                     category="service_exec", scope="external")
        if re.search(r"(?i)/tmp/|/dev/shm/|/var/tmp/", cmd):
            scan.add("HIGH", rel, i,
                     "ExecStart= references a world-writable temp path (TOCTOU / privilege escalation)",
                     evidence=line, confidence=0.85, category="service_exec")

# ─────────────────────────────────────────────────────────────────────────────
# v8 Git hook scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_git_hooks(scan: "PackageScan", repo_dir: Path) -> None:
    """Check for suspicious hook-named files or .gitattributes hook tricks."""
    if not YSHIELD_GIT_HOOK_SCAN:
        return

    # Check for files in repo root matching git hook names
    ls_cp = git("ls-files", "-z", cwd=repo_dir, capture_output=True)
    all_files = [r for r in (ls_cp.stdout or "").split("\0") if r]

    for rel in all_files:
        basename = Path(rel).name
        if _P.GIT_HOOK_NAMES.match(basename):
            scan.add("HIGH", rel, 0,
                     f"File named '{basename}' matches a git hook name — "
                     "may be injected into .git/hooks via post-checkout or similar",
                     category="git_hook_inject", confidence=0.75)

    # Check .gitattributes for filter/hook tricks
    gitattrs = repo_dir / ".gitattributes"
    if gitattrs.exists():
        try:
            content = read_text(gitattrs)
            # filter=lfs is fine; anything custom is suspicious
            if re.search(r"filter\s*=\s*(?!lfs\b)", content, re.I):
                scan.add("HIGH", ".gitattributes", 0,
                         "Custom git filter= attribute — can execute code during checkout",
                         evidence=content[:200], category="git_hook_inject", confidence=0.85)
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# Data Flow / Taint Analysis Engine
# ─────────────────────────────────────────────────────────────────────────────

_TAINT_SOURCES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\$\([ \t]*(curl|wget|fetch|aria2c)[^)]+\)"),              "download"),
    (re.compile(r"(?i)\$\([ \t]*(base64[^)]+(-d|--decode)|xxd[^)]*-r)[^)]*\)"), "decode"),
    (re.compile(r"(?i)\$\([ \t]*cat[ \t]+/proc/[^)]+\)"),                       "proc_read"),
    (re.compile(r"(?i)\$\([ \t]*(openssl[ \t]+enc[^)]*-d)[^)]*\)"),             "decode"),
    (re.compile(r"(?i)\$\([ \t]*(python3?|perl|ruby)[ \t]+-[cme][^)]+\)"),      "interpreter"),
    (re.compile(r"(?i)\$\([ \t]*(nc|ncat|netcat)[^)]+\)"),                       "network_input"),
    (re.compile(r"(?i)\$\([ \t]*read[ \t]"),                                      "user_input"),
    (re.compile(r"(?i)\$\([ \t]*(git[^)]*log|git[^)]*show)[^)]*\)"),            "git_content"),
    (re.compile(r"(?i)\$\([ \t]*gpg[^)]*--decrypt[^)]*\)"),                      "decode"),
    (re.compile(r"(?i)\$\([ \t]*zcat\b[^)]+\)"),                                  "decode"),
    (re.compile(r"(?i)\$\([ \t]*tr[ \t]+[^)]+\)"),                               "tr_transform"),
    # v8 new taint sources
    (re.compile(r"(?i)<\(\s*(curl|wget|fetch)[^)]+\)"),                          "proc_sub_download"),
    (re.compile(r"(?i)\$\([ \t]*cat\b[^)]*\)"),                                   "file_read"),
    (re.compile(r"(?i)\$\([ \t]*ssh\b[^)]+\)"),                                   "network_input"),
    (re.compile(r"(?i)<<<\s*\$\("),                                               "here_string"),
]

_TAINT_SINKS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"(?i)(^|[^A-Za-z0-9_])eval[ \t]+['\"]?\$\{?([A-Za-z_]\w*)\}?"),          "eval",       "CRITICAL"),
    (re.compile(r"(?i)(source|\.)[ \t]+['\"]?\$\{?([A-Za-z_]\w*)\}?"),                     "source",     "CRITICAL"),
    (re.compile(r"(?i)(bash|sh|zsh|dash)[ \t]+-c[ \t]+['\"]?\$\{?([A-Za-z_]\w*)\}?"),     "shell_c",    "CRITICAL"),
    (re.compile(r"(?i)(bash|sh|zsh|dash)[ \t]+['\"]?\$\{?([A-Za-z_]\w*)\}?"),             "shell",      "CRITICAL"),
    (re.compile(r"(?i)['\"]?\$\{?([A-Za-z_]\w*)\}?[\"']?[ \t]*\|[ \t]*(bash|sh|zsh|eval)"),     "pipe_shell", "CRITICAL"),
    (re.compile(r"(?i)exec\b[^#\n]*\$([A-Za-z_]\w*)"),                        "exec",       "CRITICAL"),
    (re.compile(r"(?m)^[ \t]*['\"]?\$\{?([A-Za-z_]\w*)\}?['\"]?(?:[ \t]|$)"), "var_as_cmd", "HIGH"),
    (re.compile(r"(?i)chmod[ \t]+\+x[^#\n]*\$([A-Za-z_]\w*)"),               "chmod_x",    "HIGH"),
    (re.compile(r"(?i)(>|>>|tee)[^#\n]*/etc/\S*\$([A-Za-z_]\w*)"),           "sys_write",  "HIGH"),
    (re.compile(r"(?i)python3?[^#\n]*\$([A-Za-z_]\w*)"),                      "python_run", "HIGH"),
    # v8 new sinks
    (re.compile(r"(?i)source\s+<\s*\(\s*\$([A-Za-z_]\w*)"),                   "proc_sub_source", "CRITICAL"),
    (re.compile(r"(?i)\|\s*(bash|sh|zsh)\s+\$([A-Za-z_]\w*)"),               "pipe_var_script", "CRITICAL"),
    (re.compile(r"(?i)\bxargs\b[^#\n]*\b(bash|sh)\b[^#\n]*\$([A-Za-z_]\w*)"), "xargs_var", "HIGH"),
]

_VAR_ASSIGN_RE = re.compile(r"^[ \t]*([A-Za-z_]\w*)=(.*)")
_VAR_EXPORT_RE = re.compile(r"^[ \t]*export[ \t]+([A-Za-z_]\w*)=(.*)")
_VAR_LOCAL_RE  = re.compile(r"^[ \t]*(?:local|declare|typeset|readonly)(?:[ \t]+-[A-Za-z]+)*[ \t]+([A-Za-z_]\w*)=(.*)")

@dataclass
class TaintedVar:
    name:        str
    taint_type:  str
    source_line: int
    chain:       List[str] = field(default_factory=list)

class DataFlowAnalyzer:
    def __init__(self) -> None:
        self.tainted: Dict[str, TaintedVar] = {}
        self.tainted_paths: Dict[str, TaintedVar] = {}

    def _normalize_io_path(self, token: str) -> str:
        token = shell_unquote(token.strip().rstrip(";"))
        token = token.replace("${srcdir}", "$srcdir").replace("${pkgdir}", "$pkgdir")
        return token

    def _extract_io_path(self, m: re.Match) -> str:
        groups = [g for g in m.groups() if g and g not in {"'", '"'}]
        return self._normalize_io_path(groups[-1]) if groups else ""

    def _rhs_reads_tainted_path(self, rhs: str, line_no: int) -> Optional[TaintedVar]:
        if not YSHIELD_FILE_TAINT_TRACK:
            return None
        for m in _P.FILE_TAINT_READ.finditer(rhs):
            path = self._extract_io_path(m)
            tv = self.tainted_paths.get(path)
            if tv:
                chain = tv.chain + [f"line {line_no}: read tainted file {path}"]
                return TaintedVar("", f"{tv.taint_type}:file", tv.source_line, chain)
        for path, tv in self.tainted_paths.items():
            if path and path in rhs and re.search(r"(?i)\b(cat|source|\.|<)\b", rhs):
                chain = tv.chain + [f"line {line_no}: read tainted file {path}"]
                return TaintedVar("", f"{tv.taint_type}:file", tv.source_line, chain)
        return None

    def _classify_rhs(self, rhs: str, line_no: int) -> Optional[TaintedVar]:
        rhs, _ = decode_bash_ansi_c_quotes(rhs)
        file_tv = self._rhs_reads_tainted_path(rhs, line_no)
        if file_tv:
            return file_tv
        for pat, label in _TAINT_SOURCES:
            if pat.search(rhs):
                return TaintedVar("", label, line_no, [f"line {line_no}: {rhs[:80]}"])
        for var_name, tv in self.tainted.items():
            for ref in (rf"\$\{{{re.escape(var_name)}\}}", rf"\${re.escape(var_name)}\b"):
                if re.search(ref, rhs):
                    chain = tv.chain + [f"line {line_no}: propagated via ${var_name}"]
                    return TaintedVar("", tv.taint_type, tv.source_line, chain)
        return None

    def _line_has_tainted_var(self, line: str) -> Optional[TaintedVar]:
        for var_name, tv in self.tainted.items():
            if re.search(rf"\$\{{{re.escape(var_name)}\}}|\${re.escape(var_name)}\b", line):
                return tv
        return None

    def _track_file_taint_io(self, line_no: int, line: str) -> None:
        if not YSHIELD_FILE_TAINT_TRACK:
            return
        tv = self._line_has_tainted_var(line)
        if tv:
            for m in _P.FILE_TAINT_WRITE.finditer(line):
                path = self._extract_io_path(m)
                if path:
                    chain = tv.chain + [f"line {line_no}: wrote tainted data to {path}"]
                    self.tainted_paths[path] = TaintedVar(path, f"{tv.taint_type}:file", tv.source_line, chain)

    def process_line(self, line_no: int, line: str) -> List[Tuple[str, str, str, List[str]]]:
        line = effective_shell_line(line)
        line, _ = decode_bash_ansi_c_quotes(line)
        if _P.COMMENT.match(line) or _P.BLANK.match(line):
            return []
        results: List[Tuple[str, str, str, List[str]]] = []
        stripped = line.strip()

        self._track_file_taint_io(line_no, stripped)

        pm = _P.PRINTF_V_ASSIGN.match(stripped)
        if pm:
            var_name = pm.group(1)
            rhs = decode_printf_format_string(pm.group(2))
            tv = self._classify_rhs(rhs, line_no)
            if tv is not None:
                tv.name = var_name
                self.tainted[var_name] = tv
            elif var_name in self.tainted:
                del self.tainted[var_name]
            if re.search(r"(?i)\b(curl|wget|bash|sh|eval|source|/dev/tcp)\b", rhs):
                self.tainted[var_name] = TaintedVar(
                    var_name, "printf_v_assignment", line_no,
                    [f"line {line_no}: printf -v reconstructed {rhs[:80]}"]
                )
            return results

        for assign_re in (_VAR_ASSIGN_RE, _VAR_EXPORT_RE, _VAR_LOCAL_RE):
            m = assign_re.match(stripped)
            if m:
                var_name, rhs = m.group(1), m.group(2)
                tv = self._classify_rhs(rhs, line_no)
                if tv is not None:
                    tv.name = var_name
                    self.tainted[var_name] = tv
                elif var_name in self.tainted:
                    del self.tainted[var_name]
                break

        for sink_pat, sink_label, sev in _TAINT_SINKS:
            m = sink_pat.search(line)
            if not m:
                continue
            groups = [g for g in m.groups() if g and re.match(r'^[A-Za-z_]\w*$', g)]
            for var_name in groups:
                if var_name in self.tainted:
                    tv = self.tainted[var_name]
                    chain = tv.chain + [f"line {line_no}: sink '{sink_label}'"]
                    results.append((tv.taint_type, sink_label, sev, chain))
        if YSHIELD_FILE_TAINT_TRACK:
            for m in _P.FILE_TAINT_READ.finditer(line):
                path = self._extract_io_path(m)
                tv = self.tainted_paths.get(path)
                if tv and re.search(r"(?i)\b(source|\.|bash|sh|zsh|dash|eval|exec)\b", line):
                    chain = tv.chain + [f"line {line_no}: executed tainted file {path}"]
                    results.append((tv.taint_type, "file_exec", "CRITICAL", chain))
        return results

    def check_string_reconstruction(self, lines: List[str]) -> List[Tuple[int, str]]:
        findings: List[Tuple[int, str]] = []
        for i, line in enumerate(lines, 1):
            line = effective_shell_line(line)
            if _P.COMMENT.match(line) or _P.BLANK.match(line):
                continue
            if _P.STRING_CONCAT.search(line):
                parts = re.findall(r'\$(?:\{[A-Za-z_]\w*\}|[A-Za-z_]\w*)', line)
                if len(parts) >= 3:
                    findings.append((i,
                        f"String reconstruction via {len(parts)} concatenated vars "
                        f"(command obfuscation): {line[:80].strip()}"))
            if _P.ARRAY_CMD.search(line):
                findings.append((i,
                    f"Array used as command (possible reconstructed command): {line[:80].strip()}"))
        junk_lines = [i for i, l in enumerate(lines, 1) if _P.JUNK_VAR_PATTERN.match(l)]
        if len(junk_lines) >= 5:
            window = junk_lines[-1] - junk_lines[0]
            if window <= 20:
                findings.append((junk_lines[0],
                    f"{len(junk_lines)} single/two-char variable assignments in {window} lines "
                    "(junk-variable injection / command reconstruction obfuscation)"))
        return findings

# ─────────────────────────────────────────────────────────────────────────────
# Call-Graph Analyzer
# ─────────────────────────────────────────────────────────────────────────────

_GRAPH_SINK_LINE_RE = re.compile(
    r"(?i)(?:^|[;|&({\s])(eval|source|\.|exec\b|bash[ \t]+-c|sh[ \t]+-c|python3?[ \t]+-[cme]|perl[ \t]+-e|ruby[ \t]+-e)\b"
)

class CallGraphAnalyzer:
    def __init__(self) -> None:
        self.calls: Dict[str, Set[str]] = defaultdict(set)
        self.direct_sinks: Dict[str, List[str]] = defaultdict(list)
        self._current_func = "global"
        self._depth = 0
        self._all_func_names: Set[str] = set()

    def feed_lines(self, lines: List[str]) -> None:
        for raw in lines:
            line = effective_shell_line(raw)
            if _P.COMMENT.match(raw) or _P.BLANK.match(raw):
                continue
            m = _P.FUNC_DEF.match(raw)
            if m and self._depth == 0:
                fname = m.group(1)
                self._current_func = fname
                self._all_func_names.add(self._current_func)
                self.calls.setdefault(self._current_func, set())
            opens  = line.count("{")
            closes = line.count("}")
            self._depth += opens - closes
            if self._depth <= 0:
                self._depth = 0
                if self._current_func != "global":
                    self._current_func = "global"
                continue
            if _GRAPH_SINK_LINE_RE.search(line):
                self.direct_sinks[self._current_func].append(line[:80])
            cm = _P.FUNC_CALL_MATCH.match(raw)
            if cm:
                callee = cm.group(1)
                if callee not in {"if","for","while","do","done","then","fi","case",
                                   "esac","else","elif","local","return","exit",
                                   "echo","printf","true","false","source","."}:
                    self.calls[self._current_func].add(callee)

    def _transitive_sinks(self, func: str, visited: Optional[Set[str]] = None) -> List[str]:
        if visited is None:
            visited = set()
        if func in visited:
            return []
        visited.add(func)
        sinks = list(self.direct_sinks.get(func, []))
        for callee in self.calls.get(func, set()):
            sinks.extend(self._transitive_sinks(callee, visited))
        return sinks

    def get_suspicious_chains(self) -> List[Tuple[str, str, List[str]]]:
        result = []
        top_level = {"build", "prepare", "check", "package", "pkgver",
                     "pre_install", "post_install", "pre_upgrade", "post_upgrade",
                     "pre_remove", "post_remove"}
        for func in self._all_func_names:
            if func in top_level:
                continue
            if func in self.direct_sinks:
                continue
            transitive = self._transitive_sinks(func)
            if transitive:
                called = sorted(self.calls.get(func, set()))
                result.append((func, " → ".join(called[:3]), transitive[:3]))
        return result

# ─────────────────────────────────────────────────────────────────────────────
# Heredoc Scanner
# ─────────────────────────────────────────────────────────────────────────────

_HEREDOC_OPEN_RE  = re.compile(r"<<[-]?[ \t]*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")
_HEREDOC_B64_RE   = re.compile(r"(?i)^[ \t]*(base64[ \t]+(-d|--decode)|[A-Za-z0-9+/]{60,}={0,2}$)")

def extract_heredocs(lines: List[str]) -> List[Tuple[str, List[str]]]:
    results: List[Tuple[str, List[str]]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _HEREDOC_OPEN_RE.search(line)
        if m:
            delim = m.group(1)
            body: List[str] = []
            i += 1
            while i < len(lines):
                if lines[i].strip() == delim or lines[i].rstrip("\n") == delim:
                    break
                body.append(lines[i])
                i += 1
        else:
            i += 1
            continue
        if body:
            results.append((delim, body))
        i += 1
    return results

def scan_heredoc_body(scan: "PackageScan", rel: str, lineno_offset: int,
                      body: List[str], dfa: Optional[DataFlowAnalyzer]) -> None:
    if not body:
        return
    combined = "\n".join(body)
    if _HEREDOC_B64_RE.search(combined) or len(combined) > 60:
        try:
            decoded = base64.b64decode(combined.replace("\n", "")).decode("utf-8", errors="replace")
            decoded_lines = decoded.splitlines()
            for i, dl in enumerate(decoded_lines):
                scan_line(scan, f"{rel}[heredoc-decoded]", lineno_offset + i, dl,
                          scope="global", is_install_file=False, var_map={},
                          array_ctx=ACTX_EXECUTABLE)
        except Exception:
            pass
    for i, line in enumerate(body):
        scan_line(scan, f"{rel}[heredoc]", lineno_offset + i, line,
                  scope="global", is_install_file=False, var_map={},
                  array_ctx=ACTX_EXECUTABLE)

# ─────────────────────────────────────────────────────────────────────────────
# Sandbox Runner
# ─────────────────────────────────────────────────────────────────────────────

_STRACE_NETWORK_RE   = re.compile(r"(?i)(connect|sendto|sendmsg|socket).*AF_INET")
_STRACE_WRITE_SYS_RE = re.compile(r'(?i)(openat|open)\([^)]*"(/etc/|/usr/|/bin/|/sbin/|/lib/)[^"]*",\s*O_WRONLY|O_RDWR')
_STRACE_PTRACE_RE    = re.compile(r"(?i)ptrace\(")
_STRACE_EXECVE_RE    = re.compile(r'(?i)execve\("([^"]+)"')
_STRACE_MOUNT_RE     = re.compile(r"(?i)mount\(")
_STRACE_SETUID_RE    = re.compile(r"(?i)(setuid|setgid|setresuid|setresgid)\(")
_STRACE_MMAP_EXEC_RE = re.compile(r"(?i)mmap[^)]*PROT_EXEC[^)]*MAP_ANONYMOUS")
_EXPECTED_EXECVE = {"/usr/bin/bash", "/bin/bash", "/usr/bin/sh", "/bin/sh",
                    "/usr/bin/git", "/usr/bin/file", "/usr/bin/find",
                    "/usr/bin/grep", "/usr/bin/sed", "/usr/bin/awk",
                    "/usr/bin/cat", "/usr/bin/echo"}

class SandboxRunner:
    def __init__(self, repo_dir: Path) -> None:
        self.repo_dir   = repo_dir
        self.has_bwrap  = command_exists("bwrap")
        self.has_strace = command_exists("strace")

    def available(self) -> bool:
        return self.has_bwrap

    def _build_bwrap_cmd(self, inner_cmd: List[str], workdir: Path,
                          allow_network: bool = False) -> List[str]:
        bwrap = ["bwrap",
            "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc", "/etc",
            "--ro-bind", str(self.repo_dir), "/build",
            "--bind", str(workdir), "/tmp",
            "--tmpfs", "/home", "--tmpfs", "/root",
            "--proc", "/proc", "--dev", "/dev",
            "--chdir", "/build", "--die-with-parent", "--new-session",
        ]
        if not allow_network:
            bwrap += ["--unshare-net"]
        bwrap += ["--unshare-pid", "--unshare-ipc", "--unshare-uts", "--"]
        bwrap += inner_cmd
        return bwrap

    def run_syntax_check(self, scan: "PackageScan") -> None:
        if not self.has_bwrap:
            return
        pkgbuild = self.repo_dir / "PKGBUILD"
        if not pkgbuild.exists():
            return
        workdir = TEMP_DIR / f"sandbox_work_{scan.pkg}"
        workdir.mkdir(exist_ok=True)
        try:
            inner_cmd = ["bash", "-n", "/build/PKGBUILD"]
            cmd = self._build_bwrap_cmd(inner_cmd, workdir)
            if self.has_strace:
                strace_log = workdir / "strace.log"
                cmd = ["strace", "-f", "-e", "trace=network,file,process,memory",
                       "-o", str(strace_log), "--"] + cmd
            else:
                strace_log = None
            try:
                run(cmd, capture_output=True, check=False, timeout=YSHIELD_SANDBOX_TIMEOUT)
            except subprocess.TimeoutExpired:
                scan.add("HIGH", "sandbox", 0,
                         "bash -n syntax check timed out in sandbox — infinite loop/sleep?",
                         category="dynamic_sandbox")
                return
            if strace_log and strace_log.exists():
                self._parse_strace(strace_log.read_text(encoding="utf-8", errors="replace"),
                                   scan, phase="syntax-check")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def _parse_strace(self, strace_output: str, scan: "PackageScan", phase: str) -> None:
        for line in strace_output.splitlines():
            if not line.strip():
                continue
            if _STRACE_NETWORK_RE.search(line):
                scan.add("CRITICAL", f"dynamic-sandbox:{phase}", 0,
                         f"Network connection attempt in sandbox during {phase}",
                         evidence=line[:200], category="dynamic_sandbox")
            elif _STRACE_WRITE_SYS_RE.search(line):
                scan.add("CRITICAL", f"dynamic-sandbox:{phase}", 0,
                         f"Write to system path in sandbox during {phase}",
                         evidence=line[:200], category="dynamic_sandbox")
            elif _STRACE_PTRACE_RE.search(line):
                scan.add("CRITICAL", f"dynamic-sandbox:{phase}", 0,
                         "ptrace() in sandbox — attempted to trace another process",
                         evidence=line[:200], category="dynamic_sandbox")
            elif _STRACE_SETUID_RE.search(line):
                scan.add("CRITICAL", f"dynamic-sandbox:{phase}", 0,
                         "setuid/setgid in sandbox — privilege escalation attempt",
                         evidence=line[:200], category="dynamic_sandbox")
            elif _STRACE_MMAP_EXEC_RE.search(line):
                scan.add("HIGH", f"dynamic-sandbox:{phase}", 0,
                         "mmap(PROT_EXEC | MAP_ANONYMOUS) — possible shellcode mapping",
                         evidence=line[:200], category="dynamic_sandbox")
            elif _STRACE_EXECVE_RE.search(line):
                m = _STRACE_EXECVE_RE.search(line)
                if m:
                    exe = m.group(1)
                    if exe not in _EXPECTED_EXECVE and not exe.startswith("/usr/lib"):
                        scan.add("MEDIUM", f"dynamic-sandbox:{phase}", 0,
                                 f"Unexpected execve({exe!r}) in sandbox",
                                 evidence=line[:200], category="dynamic_sandbox",
                                 confidence=0.7)

# ─────────────────────────────────────────────────────────────────────────────
# Binary Inspector
# ─────────────────────────────────────────────────────────────────────────────

BENIGN_BINARY_EXTS = {".png",".svg",".ico",".xpm",".jpg",".jpeg",".gif",".bmp",
                       ".webp",".icns",".ttf",".otf",".woff",".woff2",".eot",
                       ".pdf",".lock"}
IMAGE_EXTS         = {".png",".jpg",".jpeg",".gif",".bmp",".webp",".ico"}

_BINARY_SUSPICIOUS_RE = re.compile(
    r"(?i)(reverse.?shell|/bin/sh|/bin/bash|\bnc\b.*-e\b|/dev/tcp|"
    r"xmrig|stratum\+|cryptonight|"
    r"curl.*\|.*sh|wget.*\|.*sh|"
    r"base64.*-d\b|eval.*base64|"
    r"rm -rf /|dd if=/dev/zero|mkfs\.|"
    r"useradd|adduser|/etc/shadow|"
    r"\.ssh/authorized_keys|"
    r"GITHUB_TOKEN|AWS_SECRET|api.?key|"
    r"/etc/cron|crontab|"
    r"LD_PRELOAD|/etc/ld\.so)"
)

class BinaryInspector:
    def __init__(self, scan: "PackageScan") -> None:
        self.scan         = scan
        self.has_strings  = command_exists("strings")
        self.has_binwalk  = command_exists("binwalk")

    def inspect(self, rel: str, path: Path) -> None:
        if not YSHIELD_CHECK_BINARY_FILES:
            return
        ext      = Path(rel).suffix.lower()
        is_image = ext in IMAGE_EXTS
        pkg_hints = self.scan.pkg_type_hints
        if "binary" in pkg_hints or "appimage" in pkg_hints:
            base_sev = "LOW"
        elif ext in BENIGN_BINARY_EXTS:
            base_sev = "MEDIUM"
        else:
            base_sev = "HIGH"
        try:
            size = path.stat().st_size
        except OSError:
            size = -1
        self.scan.add(base_sev, rel, 0,
                      f"Binary file committed to AUR source tree ({size} bytes)",
                      category="committed_binary",
                      confidence=0.7 if base_sev == "MEDIUM" else 1.0)
        if YSHIELD_BINARY_STRINGS and self.has_strings and not is_image:
            self._run_strings(rel, path)
        if YSHIELD_STEGANOGRAPHY and self.has_binwalk and is_image:
            self._run_binwalk(rel, path)
        self._check_binary_entropy(rel, path)
        rlo = check_rlo_attack(rel)
        if rlo:
            self.scan.add("CRITICAL", rel, 0, rlo, category="rlo_attack")
        if _P.DOUBLE_EXT_DISGUISE.search(rel):
            self.scan.add("HIGH", rel, 0,
                          f"Suspicious double extension in committed file: {rel}",
                          category="polyglot")

    def _run_strings(self, rel: str, path: Path) -> None:
        try:
            cp = run(["strings", "-n", "8", str(path)], capture_output=True, check=False, timeout=30)
            output = cp.stdout or ""
        except Exception:
            return
        for i, line in enumerate(output.splitlines()):
            if _BINARY_SUSPICIOUS_RE.search(line):
                self.scan.add("HIGH", f"{rel}[strings]", i + 1,
                              f"Suspicious string in binary: {line[:100]}",
                              evidence=line[:200], category="binary_strings",
                              confidence=0.85)
            for url in _P.URL.findall(line):
                if _P.PASTE_SITE.search(url):
                    self.scan.add("CRITICAL", f"{rel}[strings]", i + 1,
                                  f"Paste-site URL embedded in binary: {url[:100]}",
                                  category="binary_strings")
                hint = check_url_homoglyphs(url)
                if hint:
                    self.scan.add("HIGH", f"{rel}[strings]", i + 1, hint, category="homoglyph")

    def _run_binwalk(self, rel: str, path: Path) -> None:
        try:
            cp = run(["binwalk", "--signature", "--quiet", str(path)],
                     capture_output=True, check=False, timeout=30)
            output = (cp.stdout or "").strip()
        except Exception:
            return
        lines = [l for l in output.splitlines()
                 if l.strip() and not l.startswith("DECIMAL") and not l.startswith("---")]
        if lines:
            self.scan.add("HIGH", rel, 0,
                          f"Steganography/embedded data in image ({len(lines)} signatures)",
                          evidence="\n".join(lines[:5]), category="steganography")

    def _check_binary_entropy(self, rel: str, path: Path) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            return
        if len(data) < 256:
            return
        sample = data[:65536]
        byte_counts = Counter(sample)
        n = len(sample)
        ent = -sum((c / n) * math.log2(c / n) for c in byte_counts.values())
        if ent > 7.9 and len(data) > 4096:
            ext = Path(rel).suffix.lower()
            if ext not in {".gz",".xz",".bz2",".zst",".lz4",".zip",".7z",".rar",".br",".lzma"}:
                self.scan.add("MEDIUM", rel, 0,
                              f"Very high byte entropy ({ent:.3f} bpb) — likely packed/encrypted payload",
                              category="binary_strings", confidence=0.6)

# ─────────────────────────────────────────────────────────────────────────────
# Findings data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass(slots=True)
class Finding:
    severity:   str
    file:       str
    line:       int
    reason:     str
    evidence:   str   = ""
    confidence: float = 1.0
    category:   str   = "generic"
    scope:      str   = ""
    mitre:      str   = ""

    def to_json(self) -> dict:
        return dataclasses.asdict(self)

INSTALL_SCRIPTLETS = {
    "pre_install","post_install","pre_upgrade","post_upgrade",
    "pre_remove","post_remove","pre_transaction","post_transaction",
}

_SAFE_SCRIPTLET_RE = re.compile(
    r"(?i)(ldconfig\b|update-desktop-database\b|gtk-update-icon-cache\b|"
    r"update-mime-database\b|fc-cache\b|glib-compile-schemas\b|"
    r"dconf\b|gdk-pixbuf-query-loaders\b|xdg-icon-resource\b|"
    r"update-ca-trust\b|systemd-tmpfiles\b|udevadm\b|"
    r"install -[Ddm]\b|getent\b|chown\b|chmod\b.*\$pkgdir|"
    r"xdg-mime\b|gio\b|kbuildsycoca\b|depmod\b)"
)

@dataclass
class PackageScan:
    pkg:             str
    pkgbase:         str
    maintainer:      str   = ""
    last_modified:   int   = 0
    first_submitted: int   = 0
    votes:           int   = 0
    popularity:      float = 0.0
    findings:        List[Finding]                    = field(default_factory=list)
    seen:            Set[Tuple[str, str, int, str]]   = field(default_factory=set)
    score:           float = 0.0
    critical:        int   = 0
    high:            int   = 0
    medium:          int   = 0
    low:             int   = 0
    suppressed:      int   = 0
    scan_commit:     str   = ""
    build_systems:   Set[str] = field(default_factory=set)
    pkg_type_hints:  Set[str] = field(default_factory=set)
    var_map:         Dict[str, str] = field(default_factory=dict)

    def add(self, severity: str, file: str, line: int, reason: str,
            evidence: str = "", confidence: float = 1.0, category: str = "generic",
            scope: str = "", is_install_file: bool = False) -> None:
        sev = severity.upper()
        if (sev == "LOW" and not YSHIELD_WEAK_ADVISORIES
                and confidence < 0.45 and category in WEAK_ADVISORY_CATEGORIES):
            return
        if (YSHIELD_GLOBAL_SCOPE_ESCALATION and scope == "global"
                and file in ("PKGBUILD",) and sev in ("MEDIUM", "HIGH")
                and category not in NO_GLOBAL_ESCALATION_CATEGORIES):
            sev = escalate_severity(sev)
            reason += " [escalated: executes at PKGBUILD parse time]"
        if (YSHIELD_INSTALL_SCRIPT_ESCALATION and is_install_file
                and scope in INSTALL_SCRIPTLETS and sev in ("MEDIUM", "HIGH")):
            sev = escalate_severity(sev)
            reason += f" [escalated: runs as root via .install '{scope}()' scriptlet]"
        key = (sev, file, line, reason)
        if key in self.seen:
            return
        self.seen.add(key)
        mitre_tag = MITRE.get(category, "")
        self.findings.append(Finding(sev, file, line, reason, evidence, confidence, category, scope, mitre_tag))
        sw   = scope_weight(scope)
        base = {"CRITICAL": 100.0, "HIGH": 40.0, "MEDIUM": 15.0, "LOW": 4.0}.get(sev, 0.0)
        self.score += base * max(0.2, min(confidence, 1.5)) * sw
        if   sev == "CRITICAL": self.critical += 1
        elif sev == "HIGH":     self.high     += 1
        elif sev == "MEDIUM":   self.medium   += 1
        elif sev == "LOW":      self.low      += 1
        if not meets_threshold(sev, YSHIELD_MIN_SEVERITY):
            self.suppressed += 1

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def highest_severity(self) -> str:
        if self.critical: return "CRITICAL"
        if self.high:     return "HIGH"
        if self.medium:   return "MEDIUM"
        if self.low:      return "LOW"
        return "CLEAN"

# ─────────────────────────────────────────────────────────────────────────────
# Function scope tracker
# ─────────────────────────────────────────────────────────────────────────────

def compute_scopes(lines: List[str]) -> List[str]:
    scopes: List[str] = []
    current_stack = ["global"]
    depth = 0
    for raw in lines:
        if depth == 0:
            m = _P.FUNC_DEF.match(raw)
            if m:
                fname = m.group(1)
                current_stack.append(fname)
                scopes.append(fname)
                opens  = raw.count("{")
                closes = raw.count("}")
                depth += opens - closes
                if depth <= 0:
                    depth = 0
                    current_stack.pop()
                continue
        scopes.append(current_stack[-1])
        if depth > 0:
            opens  = raw.count("{")
            closes = raw.count("}")
            depth += opens - closes
            if depth <= 0:
                depth = 0
                if len(current_stack) > 1:
                    current_stack.pop()
        continue
    return scopes

# ─────────────────────────────────────────────────────────────────────────────
# Preprocessing
# ─────────────────────────────────────────────────────────────────────────────

_HEREDOC_START_RE = re.compile(r"<<-?[ \t]*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")

def preprocess_text(text: str) -> List[str]:
    lines = text.splitlines()
    out: List[str] = []
    buf = ""
    in_heredoc    = False
    heredoc_delim = ""
    for raw in lines:
        line = raw.rstrip("\n")
        if not in_heredoc:
            m = _HEREDOC_START_RE.search(line)
            if m:
                heredoc_delim = m.group(1)
                in_heredoc    = True
                out.append(line)
                continue
        if in_heredoc:
            stripped = line.strip()
            if stripped == heredoc_delim or line.rstrip() == heredoc_delim:
                in_heredoc    = False
                heredoc_delim = ""
            else:
                out.append("HEREDOC_CONTENT: " + line)
            continue
        if line.endswith("\\"):
            buf += line[:-1]
            continue
        if buf:
            out.append(buf + line)
            buf = ""
        else:
            out.append(line)
    if buf:
        out.append(buf)
    return out

def is_relevant_file(rel: str) -> bool:
    return bool(re.search(
        r"(?i)^(PKGBUILD|\.SRCINFO|.*\.(install|hook|service|timer|socket|target|path|desktop|conf|rules|cmake|patch|sh|bash|zsh|fish|py|pl|rb|php|lua|tcl|awk|go|mk|spec|nimble|zig)|Makefile|makefile|GNUmakefile|Dockerfile|dockerfile|configure|configure\.ac|CMakeLists\.txt|meson\.build|meson_options\.txt|setup\.py|pyproject\.toml|Cargo\.toml|package\.json|\.npmrc|\.yarnrc|\.cargo/config\.toml|build\.zig)$",
        rel or "",
    ))

def has_shebang(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.readline(200).startswith(b"#!")
    except OSError:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# v8 Build-system-aware false positive suppression (major improvement)
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that are ALWAYS safe in the context of their build system
_CMAKE_SAFE_LINES = re.compile(
    r"(?i)(cmake|ExternalProject_|FetchContent_|find_package\b|"
    r"target_link_libraries\b|add_executable\b|install\s*\(|"
    r"configure_file\b|add_custom_command\b|cmake_minimum_required)"
)
_MESON_SAFE_LINES = re.compile(
    r"(?i)(meson\.(build|options)|subdir\s*\(|import\s*\(|"
    r"dependency\s*\(|executable\s*\(|install_data\s*\()"
)
_CARGO_SAFE_BUILD = re.compile(
    r"(?i)cargo\s+(build|test|check|clippy|fmt|doc|clean|bench|install\s+--path)\b"
)
_GO_SAFE_BUILD = re.compile(
    r"(?i)go\s+(build|test|vet|fmt|generate|mod\s+tidy|install\s+\.)\b"
)
_NPM_SAFE_BUILD = re.compile(
    r"(?i)npm\s+(install|ci|run\s+build|run\s+test|rebuild)\b"
)
_AUTOTOOLS_SAFE = re.compile(
    r"(?i)(autoreconf|automake|autoconf|libtoolize|aclocal|intltool-update|"
    r"gtkdocize|gnome-autogen|./autogen\.sh|./configure\s)"
)
_SAFE_PATCH = re.compile(r"(?i)^\s*patch\s+(-[A-Za-z0-9]+\s+)*(-i\s+|--input=|\S+\.patch)")
_SAFE_MAKE  = re.compile(
    r"(?i)^\s*make\b[^#\n]*(all|install|clean|check|distcheck|V=[01]|DESTDIR|"
    r"PREFIX|CFLAGS|LDFLAGS|JOBS|J=[0-9]+|-j\s*[0-9]*|-C\s)"
)

def is_safe_build_pattern(line: str, build_systems: Set[str], pkg_hints: Set[str]) -> bool:
    """
    Return True if the line is a well-known safe build pattern.
    This is the primary false-positive reducer.
    """
    # cmake --install is always safe
    if re.search(r"(?i)cmake\s+--install\b", line):
        return True
    # meson install / ninja install
    if re.search(r"(?i)(meson\s+install|ninja\s+install|ninja\s+-C)\b", line):
        return True
    # Standard DESTDIR install
    if re.search(r"(?i)DESTDIR=\$\{?pkgdir\}?", line):
        return True
    # cargo/go/npm in their own packages
    if "cargo" in build_systems and _CARGO_SAFE_BUILD.search(line):
        return True
    if "go" in build_systems and _GO_SAFE_BUILD.search(line):
        return True
    if "node" in build_systems and _NPM_SAFE_BUILD.search(line):
        return True
    if "autotools" in build_systems and _AUTOTOOLS_SAFE.search(line):
        return True
    # patch is safe
    if _SAFE_PATCH.search(line):
        return True
    # Standard make targets
    if _SAFE_MAKE.search(line):
        return True
    # Python package install within pkgdir
    if re.search(r"(?i)python\S*\s+setup\.py\s+install\b.*\$pkgdir", line):
        return True
    if re.search(r"(?i)pip\s+install\b.*\$\{?pkgdir\}?|pip\s+install\b.*--root=\$", line):
        return True
    # fakeroot / makepkg build context markers
    if re.search(r"(?i)\bfakeroot\b|\bmakepkg\b.*--noextract", line):
        return True
    return False

def has_pkgdir_context(lines: List[str], lineno: int, window: int = 5) -> bool:
    start = max(0, lineno - 1 - window)
    end   = min(len(lines), lineno + window)
    for l in lines[start:end]:
        if _P.SAFE_PKGDIR.search(l):
            return True
    return False

def is_safe_packaging_write(line: str) -> bool:
    return bool(_P.SAFE_INSTALL.search(line)) or bool(_P.SAFE_PKGDIR.search(line))

def is_non_suspicious_system_path_write(line: str) -> bool:
    if not _P.SYSTEM_PATH.search(line):
        return False
    return "pkgdir" in line or "DESTDIR" in line or "--destdir" in line

def likely_safe_package_install(line: str, build_systems: Set[str], pkg_hints: Set[str]) -> bool:
    if not _P.ECO_INSTALL.search(line):
        return False
    if "DESTDIR" in line or "$pkgdir" in line or "--target" in line:
        return True
    if re.search(r"(cargo install|pip install).*--path\s*\.", line, re.I):
        return True
    if "node" in build_systems and re.search(r"npm\s+(install|ci)\b", line, re.I):
        return True
    if "cargo" in build_systems and re.search(r"cargo\s+(build|test|install)\b", line, re.I):
        return True
    if "go" in build_systems and re.search(r"go\s+(build|test|get)\b", line, re.I):
        return True
    return "curl" not in line and "wget" not in line

def _is_known_safe_service_control(line: str) -> bool:
    return bool(re.search(r"(?i)systemctl\s+(daemon-reload|preset)\b", line))

def _is_safe_check_scope_pattern(line: str) -> bool:
    return bool(re.search(
        r"(?i)(sha256sum|sha512sum|md5sum|b2sum|gpg --verify|make\s+check\b|ctest\b|"
        r"diff\s+|cmp\s+|test\s+|cargo\s+test\b|go\s+test\b|pytest\b|unittest\b)", line))

_NVM_SAFE_RE = re.compile(
    r"(?i)(nvm\s+use|nvm\s+install|source.*nvm\.sh|\[ -s.*nvm.*\]|export\s+NVM_DIR)"
)

# ─────────────────────────────────────────────────────────────────────────────
# Correlation engine (scope-boundary aware, bitfield tags for speed)
# ─────────────────────────────────────────────────────────────────────────────

_TAG_DL      = 1 << 0
_TAG_DECODE  = 1 << 1
_TAG_EXEC    = 1 << 2
_TAG_CHMOD   = 1 << 3
_TAG_TMPFILE = 1 << 4
_TAG_WRITE   = 1 << 5
_TAG_PERSIST = 1 << 6

_DL_MRE      = re.compile(r"(?i)(curl|wget|fetch|aria2c)\b")
_EXEC_MRE    = re.compile(r"(?i)(eval|source|\.|exec\b|bash\s+-c|sh\s+-c|/bin/sh\b|/bin/bash\b)\b")
_DECODE_MRE  = re.compile(r"(?i)(base64|xxd|uudecode|openssl enc -d)")
_CHMOD_MRE   = re.compile(r"(?i)chmod\s+(\+x|[0-7]*[157][0-7][0-7])")
_TMPFILE_MRE = re.compile(r"(?i)(mktemp\b|/tmp/|/dev/shm/|/run/)")
_WRITE_MRE   = re.compile(r"(?i)(>>|>|tee)\s+/etc/|/usr/bin/|/usr/lib/")
_PERSIST_MRE = re.compile(r"(?i)(crontab|systemctl\s+enable|/etc/rc\.d|autostart|\.bashrc|\.profile|/etc/profile\.d)")

def _tag_line_bits(line: str) -> int:
    line = effective_shell_line(line)
    bits = 0
    if _DL_MRE.search(line):      bits |= _TAG_DL
    if _EXEC_MRE.search(line):    bits |= _TAG_EXEC
    if _DECODE_MRE.search(line):  bits |= _TAG_DECODE
    if _CHMOD_MRE.search(line):   bits |= _TAG_CHMOD
    if _TMPFILE_MRE.search(line): bits |= _TAG_TMPFILE
    if _WRITE_MRE.search(line):   bits |= _TAG_WRITE
    if _PERSIST_MRE.search(line): bits |= _TAG_PERSIST
    return bits

def _normalize_path_token(token: str, aliases: Dict[str, str]) -> str:
    token = shell_unquote(token.strip().rstrip(";"))
    m = re.fullmatch(r"\$\{?([A-Za-z_]\w*)\}?", token)
    if m:
        return aliases.get(m.group(1), token)
    return token

def _extract_first_grouped_path(pattern: re.Pattern, line: str,
                                aliases: Dict[str, str]) -> Optional[str]:
    m = pattern.search(line)
    if not m:
        return None
    groups = [g for g in m.groups() if g and g not in {"'", '"'}]
    if not groups:
        return None
    return _normalize_path_token(groups[-1], aliases)

def _extract_fetch_output_path(line: str, aliases: Dict[str, str]) -> Optional[str]:
    words = shell_words(line)
    if words:
        for i, word in enumerate(words):
            lw = word.lower()
            if lw in {"curl", "fetch"}:
                for j, w in enumerate(words[i + 1:], i + 1):
                    if w in {"-o", "--output"} and j + 1 < len(words):
                        return _normalize_path_token(words[j + 1], aliases)
                    if w.startswith("--output="):
                        return _normalize_path_token(w.split("=", 1)[1], aliases)
            if lw == "wget":
                for j, w in enumerate(words[i + 1:], i + 1):
                    if w == "-O" and j + 1 < len(words):
                        return _normalize_path_token(words[j + 1], aliases)
                    if w.startswith("--output-document="):
                        return _normalize_path_token(w.split("=", 1)[1], aliases)
    for pat in (_P.FETCH_OUT_CURL, _P.FETCH_OUT_WGET, _P.FETCH_REDIRECT):
        found = _extract_first_grouped_path(pat, line, aliases)
        if found:
            return found
    return None

def _extract_chmod_path(line: str, aliases: Dict[str, str]) -> Optional[str]:
    words = shell_words(line)
    if words and words[0] == "chmod" and len(words) >= 3:
        return _normalize_path_token(words[-1], aliases)
    return _extract_first_grouped_path(_P.CHMOD_EXEC_PATH, line, aliases)

def _extract_exec_path(line: str, aliases: Dict[str, str]) -> Optional[str]:
    words = shell_words(line)
    if words:
        cmd = words[0]
        if cmd in {"bash", "sh", "zsh", "dash", "exec", "source", "."} and len(words) >= 2:
            return _normalize_path_token(words[1], aliases)
        if (cmd.startswith(("./", "/tmp/", "/dev/shm/", "/var/tmp/"))
                or re.fullmatch(r"\$\{?[A-Za-z_]\w*\}?", cmd)):
            return _normalize_path_token(cmd, aliases)
    for pat in (_P.SHELL_EXEC_PATH, _P.DIRECT_EXEC_PATH):
        found = _extract_first_grouped_path(pat, line, aliases)
        if found:
            return found
    return None

def _same_path(a: str, b: str) -> bool:
    if not a or not b:
        return False
    if a == b:
        return True
    return Path(a).name == Path(b).name and (
        a.startswith(("/tmp/", "/dev/shm/", "/var/tmp/"))
        or b.startswith(("/tmp/", "/dev/shm/", "/var/tmp/"))
    )

def run_dropper_path_tracking(scan: PackageScan, rel: str, lines: List[str],
                              scopes: List[str], array_ctxs: List[str],
                              is_install_file: bool) -> None:
    if not YSHIELD_DROPPER_PATH_TRACKING:
        return
    W = max(4, YSHIELD_CORRELATION_WINDOW)
    aliases: Dict[str, str] = {}
    clean_lines = [effective_shell_line(l) for l in lines]

    for i, line in enumerate(clean_lines):
        if not line or (i < len(array_ctxs) and array_ctxs[i] == ACTX_DECLARATIVE):
            continue
        am = _P.SIMPLE_PATH_ASSIGN.match(line)
        if am:
            name, value = am.group(1), shell_unquote(am.group(3))
            if value.startswith(("/tmp/", "/dev/shm/", "/var/tmp/", "./")) or "$" not in value:
                aliases[name] = value

        out_path = _extract_fetch_output_path(line, aliases)
        if not out_path:
            continue
        scope = scopes[i] if i < len(scopes) else "global"
        saw_chmod = False
        saw_exec  = False
        evidence  = [lines[i].strip()]

        for j in range(i + 1, min(len(clean_lines), i + W + 1)):
            if j < len(scopes) and scopes[j] != scope:
                break
            later = clean_lines[j]
            if not later:
                continue
            chmod_path = _extract_chmod_path(later, aliases)
            exec_path  = _extract_exec_path(later, aliases)
            if chmod_path and _same_path(out_path, chmod_path):
                saw_chmod = True
                evidence.append(lines[j].strip())
            if exec_path and _same_path(out_path, exec_path):
                saw_exec = True
                evidence.append(lines[j].strip())

        if saw_exec:
            sev = "CRITICAL" if saw_chmod else "HIGH"
            chain = "download + chmod+x + execute" if saw_chmod else "download + execute"
            scan.add(sev, rel, i + 1,
                     f"Multi-line staged dropper: {chain} of same path '{out_path}'",
                     evidence=" | ".join(evidence[:4]), confidence=0.96,
                     category="dropper_path", scope=scope,
                     is_install_file=is_install_file)
        elif saw_chmod:
            scan.add("HIGH", rel, i + 1,
                     f"Downloaded file later marked executable at same path '{out_path}'",
                     evidence=" | ".join(evidence[:3]), confidence=0.88,
                     category="dropper_path", scope=scope,
                     is_install_file=is_install_file)

def run_correlation_pass(scan: PackageScan, rel: str, lines: List[str],
                         scopes: List[str], array_ctxs: List[str],
                         is_install_file: bool) -> None:
    W = YSHIELD_CORRELATION_WINDOW
    n = len(lines)
    fired: Set[Tuple[int, str, str, str]] = set()

    # Pre-compute tags for all lines
    line_tags = [
        0 if (i < len(array_ctxs) and array_ctxs[i] == ACTX_DECLARATIVE)
        else _tag_line_bits(lines[i])
        for i in range(n)
    ]

    for start in range(n):
        if array_ctxs[start] == ACTX_DECLARATIVE if start < len(array_ctxs) else False:
            continue
        end = min(start + W, n)
        window_bits  = 0
        window_scope = scopes[start] if start < len(scopes) else "global"

        for i in range(start, end):
            i_scope = scopes[i] if i < len(scopes) else "global"
            if i_scope != window_scope and i > start:
                break
            window_bits |= line_tags[i]

        scope = window_scope

        def _fire(cat: str, sev: str, msg: str, conf: float = 0.85) -> None:
            key = (start // max(1, W), scope, cat, msg[:48])
            if key not in fired:
                fired.add(key)
                scan.add(sev, rel, start + 1, msg, lines[start],
                         confidence=conf, category=cat,
                         scope=scope, is_install_file=is_install_file)

        dl   = bool(window_bits & _TAG_DL)
        dec  = bool(window_bits & _TAG_DECODE)
        ex   = bool(window_bits & _TAG_EXEC)
        ch   = bool(window_bits & _TAG_CHMOD)
        tmp  = bool(window_bits & _TAG_TMPFILE)
        wrt  = bool(window_bits & _TAG_WRITE)
        per  = bool(window_bits & _TAG_PERSIST)

        if dl and ex:
            _fire("correlation_dl_exec", "HIGH",
                  f"Multi-line: download + execution within {W} lines (dropper pattern)")
        if dec and ex:
            _fire("correlation_dl_exec", "HIGH",
                  f"Multi-line: decode + execution within {W} lines (encoded payload)", conf=0.9)
        if tmp and ch and ex:
            _fire("correlation_dl_exec", "CRITICAL",
                  f"Multi-line: tmpfile + chmod+x + execute within {W} lines (dropper triad)", conf=0.95)
        if dl and wrt:
            _fire("correlation_dl_exec", "HIGH",
                  f"Multi-line: download + system-path write within {W} lines")
        if dec and wrt:
            _fire("correlation_dl_exec", "HIGH",
                  f"Multi-line: decode + system-path write within {W} lines")
        if dl and per and ex:
            _fire("correlation_dl_exec", "CRITICAL",
                  f"Multi-line: download + persistence + execution within {W} lines "
                  "(complete malware install triad)", conf=0.92)

# ─────────────────────────────────────────────────────────────────────────────
# Entropy analysis (v8: improved trigram + architecture filter)
# ─────────────────────────────────────────────────────────────────────────────

_HASH_RE     = re.compile(r"^[0-9a-fA-F]{32,}$")
_ARCH_STR_RE = re.compile(r"(?i)(x86_64|aarch64|armv[67]h|riscv64|i[3-7]86|pentium4|loongarch)")
_VERSION_RE  = re.compile(r"^\d+\.\d+\.\d+")
_UUID_RE     = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_PGP_KEY_RE  = re.compile(r"^[0-9A-F]{16,40}$")

_COMMON_TRIGRAMS = frozenset([
    "the","ing","and","ion","tio","ent","for","her","his","not","but","are",
    "ver","ter","all","tha","res","ont","ons","our","pro","com","con","hat",
    "ati","str","ich","ack","age","ast","ist","ith","ous","ure","ers","ent",
    "get","set","run","usr","bin","lib","etc","var","opt","tmp","pkg","dir",
    "nam","src","url","git","sha","key","sum","dep","sys","app","win","lin",
    "tion","able","ould","have","this","from","with","been","were","that",
])

def _is_natural_text_v8(token: str) -> bool:
    """Improved natural-text filter: trigram + pattern shortcuts."""
    if not token or len(token) < 20:
        return False
    if _HASH_RE.match(token):
        return True
    if _ARCH_STR_RE.search(token):
        return True
    if _VERSION_RE.match(token):
        return True
    if _UUID_RE.match(token):
        return True
    if _PGP_KEY_RE.match(token):
        return True
    if token.startswith(("http://", "https://", "ftp://", "git+", "svn+", "hg+")):
        return True
    # PGP fingerprints: space-separated hex groups
    if re.match(r'^([0-9A-F]{4}\s+){4,}', token, re.I):
        return True
    lower = token.lower()
    trigrams_found = sum(1 for i in range(len(lower) - 2) if lower[i:i+3] in _COMMON_TRIGRAMS)
    coverage = trigrams_found / max(1, len(lower) // 3)
    return coverage > 0.18

def entropy_findings(scan: PackageScan, file: str, line_no: int, line: str,
                     *, scope: str, is_install_file: bool) -> None:
    candidates = re.findall(r'"([^"]{48,})"|\'([^\']{48,})\'|([A-Za-z0-9+/=]{48,})', line)
    for a, b, c in candidates:
        token = (a or b or c).strip()
        if len(token) < YSHIELD_MIN_ENTROPY_LEN:
            continue
        if _is_natural_text_v8(token):
            continue
        if token.startswith(("http://", "https://")):
            continue
        ent = shannon_entropy(token)
        if ent >= YSHIELD_ENTROPY_THRESHOLD:
            try_active_b64_decode(scan, file, line_no, line, scope, is_install_file)
            scan.add("HIGH", file, line_no,
                     f"High-entropy string (entropy={ent:.3f} bits/char — possible encoded payload)",
                     token, confidence=0.85, category="high_entropy",
                     scope=scope, is_install_file=is_install_file)

# ─────────────────────────────────────────────────────────────────────────────
# GPG validation
# ─────────────────────────────────────────────────────────────────────────────

def _check_gpg_key_trust(key_ids: List[str], scan: PackageScan) -> None:
    if not command_exists("gpg") or not key_ids:
        return
    for kid in key_ids:
        kid = kid.strip()
        if not re.match(r'^[0-9A-Fa-f]{16,}$', kid):
            continue
        cp = run(["gpg", "--list-keys", "--", kid], capture_output=True, check=False, timeout=5)
        if cp.returncode != 0:
            scan.add("MEDIUM", "PKGBUILD (validpgpkeys)", 0,
                     f"validpgpkeys contains {kid!r} which is NOT in your local GPG keyring "
                     "— upstream signature verification will fail or be skipped",
                     category="gpg_keyimport", confidence=0.9)

def extract_validpgpkeys(text: str) -> List[str]:
    m = re.search(r"(?ms)^\s*validpgpkeys=\(([^)]*)\)", text)
    if not m:
        return []
    raw = m.group(1)
    return [k.strip().strip("'\"") for k in re.findall(r"['\"]?([0-9A-Fa-f]{16,})['\"]?", raw)]

# ─────────────────────────────────────────────────────────────────────────────
# Diff-aware incremental scanning
# ─────────────────────────────────────────────────────────────────────────────

def run_diff_aware_scan(scan: PackageScan, repo_dir: Path) -> None:
    if not YSHIELD_DIFF_AWARE:
        return
    pkgbuild = repo_dir / "PKGBUILD"
    if not pkgbuild.exists():
        return
    cache_f = cache_file_for_pkg(scan.pkg + ".text")
    if not cache_f.exists():
        try:
            cache_f.write_text(read_text(pkgbuild), encoding="utf-8")
        except Exception:
            pass
        return
    try:
        old_text = cache_f.read_text(encoding="utf-8", errors="replace")
        new_text = read_text(pkgbuild)
    except Exception:
        return
    if old_text == new_text:
        return
    old_lines = set(old_text.splitlines())
    new_lines  = new_text.splitlines()
    added = [(i + 1, l) for i, l in enumerate(new_lines) if l not in old_lines and l.strip()]
    if not added:
        return
    info(f"Diff-aware scan: {len(added)} newly added line(s) in PKGBUILD")
    dfa = DataFlowAnalyzer() if YSHIELD_DATA_FLOW else None
    for lineno, line in added:
        if _P.COMMENT.match(line) or _P.BLANK.match(line):
            continue
        scan_line(scan, "PKGBUILD[diff]", lineno, line,
                  scope="diff", is_install_file=False, var_map=scan.var_map,
                  array_ctx=ACTX_EXECUTABLE)
        if dfa:
            hits = dfa.process_line(lineno, line)
            for taint_type, sink_label, sev, chain in hits:
                chain_str = " → ".join(chain)
                scan.add(sev, "PKGBUILD[diff]", lineno,
                         f"Newly introduced taint-flow: {taint_type} → '{sink_label}': {chain_str[:200]}",
                         evidence=line, confidence=0.98,
                         category="diff_introduced", scope="diff")
    try:
        cache_f.write_text(new_text, encoding="utf-8")
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# Main per-line scanner (v8: complete, with all new patterns)
# ─────────────────────────────────────────────────────────────────────────────

def scan_line(scan: PackageScan, rel: str, line_no: int, line: str,
              *, scope: str = "global", is_install_file: bool = False,
              var_map: Dict[str, str],
              all_lines: Optional[List[str]] = None,
              array_ctx: str = ACTX_EXECUTABLE) -> None:

    original_line = line
    line = effective_shell_line(line)
    decoded_line, decoded_changed = decode_bash_ansi_c_quotes(line)
    if decoded_changed:
        line = decoded_line
    normalized = line.strip()
    if not normalized:
        return

    # ── SRCINFO: URL checks only ─────────────────────────────────────────────
    if is_srcinfo_file(rel):
        for url in _P.URL.findall(line):
            if _P.PASTE_SITE.search(url):
                scan.add("HIGH", rel, line_no,
                         f"Paste-site URL in .SRCINFO: {url[:80]}",
                         category="paste_site", scope=scope, confidence=0.9)
            if _P.BAD_DOMAIN.search(url):
                scan.add("HIGH", rel, line_no,
                         f"Typosquatted domain in .SRCINFO URL: {url[:80]}",
                         category="domain_typosquat", scope=scope)
            hint = check_url_homoglyphs(url)
            if hint and YSHIELD_HOMOGLYPH:
                scan.add("HIGH", rel, line_no, hint, category="homoglyph")
        return

    # ── Declarative array: zero execution weight ─────────────────────────────
    if array_ctx == ACTX_DECLARATIVE:
        return

    # ── Source array: URL scoring only ───────────────────────────────────────
    if array_ctx == ACTX_SOURCE:
        for url in _P.URL.findall(line):
            if _P.PASTE_SITE.search(url):
                scan.add("CRITICAL", rel, line_no,
                         f"Paste-site URL in source=(): {url[:80]}",
                         category="paste_site", scope=scope)
            if _P.BAD_DOMAIN.search(url):
                scan.add("CRITICAL", rel, line_no,
                         f"Typosquatted domain in source URL: {url[:80]}",
                         category="domain_typosquat", scope=scope)
            hint = check_url_homoglyphs(url)
            if hint and YSHIELD_HOMOGLYPH:
                scan.add("HIGH", rel, line_no, hint, category="homoglyph")
        return

    # ── Variable substitution pass ───────────────────────────────────────────
    if YSHIELD_SEMANTIC_VARS and var_map:
        expanded = resolve_shell_expansions_in_line(line, var_map)
        if expanded != line:
            _scan_expanded(scan, rel, line_no, expanded, line,
                           scope=scope, is_install_file=is_install_file)
            if _P.MUTATED_UNKNOWN.search(expanded) and _P.UNKNOWN_EXEC_SINK.search(expanded):
                scan.add("HIGH", f"{rel}[var-expanded]", line_no,
                         "Parameter/array transformation becomes unknown at an execution sink",
                         evidence=f"original: {original_line[:100]} → expanded: {expanded[:120]}",
                         confidence=0.86, category="param_transform",
                         scope=scope, is_install_file=is_install_file)

    # ── Context flags ────────────────────────────────────────────────────────
    has_pkgdir      = bool(_P.SAFE_PKGDIR.search(line))
    safe_write      = has_pkgdir or is_safe_packaging_write(line) or is_non_suspicious_system_path_write(line)
    safe_ecosystem  = likely_safe_package_install(line, scan.build_systems, scan.pkg_type_hints)
    safe_cdn_url    = bool(_P.SAFE_CDN.search(line))
    in_check_scope  = scope == "check" or scope.startswith("check")
    in_source_line  = bool(_P.SOURCE_LINE.search(line))
    in_checksum_line= bool(_P.CHECKSUM_LINE.search(line))

    # ── High-priority safe-exit rules ────────────────────────────────────────
    if is_install_file and _SAFE_SCRIPTLET_RE.search(line):
        return
    if in_check_scope and _is_safe_check_scope_pattern(line):
        return
    if in_source_line and safe_cdn_url:
        return
    if in_checksum_line:
        return
    if _NVM_SAFE_RE.search(line) and ("electron" in scan.pkg_type_hints or "node" in scan.build_systems):
        return
    # v8: suppress safe build patterns
    if is_safe_build_pattern(line, scan.build_systems, scan.pkg_type_hints):
        return

    def add(sev: str, reason: str, category: str, confidence: float = 1.0) -> None:
        scan.add(sev, rel, line_no, reason, original_line,
                 confidence=confidence, category=category,
                 scope=scope, is_install_file=is_install_file)

    if decoded_changed and line != original_line:
        decoded_probe = line
        for pat, sev, reason, cat in [
            (_P.DANGEROUS_PIPE, "CRITICAL", "ANSI-C decoded line reveals download piped to shell", "ansi_c_obfuscation"),
            (_P.EVAL, "CRITICAL", "ANSI-C decoded line reveals eval execution", "ansi_c_obfuscation"),
            (_P.SHELL_C, "HIGH", "ANSI-C decoded line reveals shell -c execution", "ansi_c_obfuscation"),
            (_P.FETCH, "HIGH", "ANSI-C decoded line reveals hidden network fetch", "ansi_c_obfuscation"),
            (_P.DEV_TCP, "CRITICAL", "ANSI-C decoded line reveals /dev/tcp socket use", "ansi_c_obfuscation"),
        ]:
            if pat.search(decoded_probe) and not pat.search(original_line):
                scan.add(sev, f"{rel}[ansi-decoded]", line_no, reason,
                         evidence=f"decoded: {decoded_probe[:160]}",
                         confidence=0.92, category=cat,
                         scope=scope, is_install_file=is_install_file)
                break

    # ── Invisible/control char attacks ──────────────────────────────────────
    rlo = check_rlo_attack(line)
    if rlo:
        add("CRITICAL", rlo, "rlo_attack"); return

    if _P.NULL_BYTE.search(line):
        add("CRITICAL", "Null byte in script line (null injection / scanner bypass)", "hex_obfuscation"); return

    # Comment injection: invisible chars inside comments
    if _P.COMMENT_INJECTION.search(line):
        add("CRITICAL", "Comment contains invisible/control character injection "
            "(may become executable in some shell contexts)", "hex_obfuscation"); return

    # ── Anti-analysis ────────────────────────────────────────────────────────
    if YSHIELD_ANTI_ANALYSIS:
        if _P.ANTI_ANALYSIS.search(line):
            add("HIGH", "Anti-analysis / environment probing detected "
                "(checks for sandbox/debug/VM before executing)", "anti_analysis", 0.8); return
        if _P.TIME_PAYLOAD.search(line) and not in_check_scope:
            add("MEDIUM", "Date/time-conditional logic (possible time-delayed payload)",
                "time_payload", 0.7); return

    # ── v11 Bash grammar/state evasions ─────────────────────────────────────
    if _P.IFS_MANIP.search(line):
        add("CRITICAL", "IFS mutation changes shell word splitting (command obfuscation / parser bypass)",
            "ifs_obfuscation"); return

    if _P.PRINTF_V_ASSIGN.search(line):
        pm = _P.PRINTF_V_ASSIGN.search(line)
        decoded_fmt = decode_printf_format_string(pm.group(2)) if pm else ""
        if re.search(r"(?i)\b(curl|wget|fetch|aria2c|bash|sh|zsh|dash|eval|source|/dev/tcp)\b", decoded_fmt):
            add("HIGH", "printf -v reconstructs a network or execution token into a variable",
                "printf_v_assignment", 0.86); return

    if YSHIELD_ARRAY_INDEX_TRACK and _P.DYNAMIC_ARRAY_INDEX.search(line):
        if re.search(r"(?i)(^|[;|&({\s])(?:eval|source|\.|exec|bash|sh|zsh|dash)\b|^\s*\$\{", line):
            add("HIGH", "Dynamic Bash array index reaches execution context; cannot resolve statically",
                "dynamic_array_index", 0.84); return

    if YSHIELD_PARAM_TRANSFORM_TRACK and _P.PARAM_TRANSFORM.search(line):
        transformed = resolve_shell_expansions_in_line(line, var_map) if var_map else "__YSHIELD_MUTATED_UNKNOWN__"
        if _P.MUTATED_UNKNOWN.search(transformed) and _P.UNKNOWN_EXEC_SINK.search(line):
            add("HIGH", "Unresolved Bash parameter transformation at execution sink",
                "param_transform", 0.86); return

    shadow = _P.TRUSTED_TOOL_SHADOW.search(line)
    if shadow:
        add("HIGH",
            f"Build script redefines trusted tool '{shadow.group(1)}' via alias/function",
            "trusted_tool_shadow", 0.88); return

    # ────────────────────────────────────────────────────────────────────────
    # v8 NEW CRITICAL: Process-substitution network exec (bypass closed)
    # ────────────────────────────────────────────────────────────────────────
    if YSHIELD_PROC_SUB_NET and _P.PROC_SUB_NET.search(line):
        add("CRITICAL",
            "Process substitution executes network-fetched content: "
            "source <(curl ...) / bash <(wget ...) — direct code execution from network",
            "proc_sub_net_exec"); return

    if _P.EVAL_NET_SUBSHELL.search(line):
        add("CRITICAL",
            "eval \"$(network-fetch ...)\" — remote code execution via eval",
            "proc_sub_net_exec"); return

    # ── v8 NEW: Trap handler with suspicious payload ─────────────────────────
    if YSHIELD_TRAP_ANALYSIS and _P.TRAP_SUSPICIOUS.search(line):
        add("CRITICAL",
            "trap handler contains suspicious payload (curl/wget/eval/bash) — "
            "guarantees execution even on script failure",
            "trap_payload"); return

    # ── v8 NEW: exec file-descriptor TCP trick ──────────────────────────────
    if _P.EXEC_FD_TCP.search(line):
        add("CRITICAL",
            "exec {fd}<>/dev/tcp/... — opens raw TCP socket without curl/nc "
            "(common reverse-shell evasion technique)",
            "exec_fd_trick"); return

    if _P.EXEC_FD_PROC.search(line):
        add("CRITICAL", "exec opens /proc/self/fd/ for code injection",
            "exec_fd_trick"); return

    # ── v8 NEW: Double eval ─────────────────────────────────────────────────
    if _P.DOUBLE_EVAL.search(line):
        add("CRITICAL", "Double eval: eval \"$(eval ...)\" — obfuscated code execution",
            "eval"); return

    # ── v8 NEW: Arithmetic char-code reconstruction ──────────────────────────
    if YSHIELD_ARITH_CHARCODE and _P.ARITH_CHARCODE.search(line):
        reconstructed = try_arith_charcode_decode(line)
        if reconstructed:
            add("HIGH",
                f"Arithmetic char-code obfuscation detected "
                f"(possible reconstructed command: '{reconstructed[:40]}')",
                "arith_charcode", 0.85); return

    # ── v8 NEW: mapfile/readarray piped to eval ──────────────────────────────
    if _P.MAPFILE_EVAL.search(line):
        add("CRITICAL", "mapfile/readarray piped into eval/bash — dynamic command execution",
            "mapfile_exec"); return

    # ── CRITICAL tier (v7 patterns retained) ────────────────────────────────
    if _P.DANGEROUS_PIPE.search(line):
        add("CRITICAL", "Download piped directly into shell", "pipe_to_shell"); return

    if _P.EVAL.search(line):
        add("CRITICAL", "eval() detected", "eval"); return

    if _P.DECODE.search(line):
        try_active_b64_decode(scan, rel, line_no, line, scope, is_install_file)
        add("CRITICAL", "Binary/obfuscation decode pattern detected", "decode_pattern"); return

    if _P.SHELL_C.search(line):
        if re.search(r"(?i)\b(bash|sh|zsh|dash)[ \t]+-c[ \t]+\$", line):
            add("CRITICAL", "Shell -c with variable argument (dynamic inline execution)", "shell_dash_c"); return
        elif re.search(r"(?i)\b(bash|sh|zsh|dash)[ \t]+-c[ \t]+['\"][^'\"]{80,}", line):
            add("HIGH", "Shell -c with unusually long inline string", "shell_dash_c", 0.75); return
        else:
            add("MEDIUM", "Shell -c inline execution detected", "shell_dash_c", 0.6); return

    if _P.ROOT_DELETE.search(line):
        if not re.search(r"(?i)(\$\{?pkgdir\}?|DESTDIR=|/tmp/|/dev/shm/)", line):
            add("CRITICAL", "Destructive root delete detected", "root_delete"); return

    if _P.FORMAT_UTIL.search(line):
        add("CRITICAL", "Disk/destructive utility detected", "disk_destructive"); return

    if _P.HEX_CMD.search(line):
        add("CRITICAL", "Hex-escaped shell command construction", "hex_obfuscation"); return

    if _P.INTERP.search(line) and re.search(r"(__import__|exec|eval|system|popen|subprocess)", line):
        add("CRITICAL", "Inline interpreter executing dangerous built-in", "interpreter_exec"); return

    # v8: Python dangerous one-liner
    if _P.PYTHON_ONE_LINER.search(line):
        add("CRITICAL", "Dangerous Python one-liner (os/subprocess/socket/exec)", "interpreter_exec"); return

    if _P.TRAVERSAL.search(line):
        add("CRITICAL", "Path traversal targeting sensitive system files", "path_traversal"); return

    if _P.PASTE_SITE.search(line):
        add("CRITICAL", "Download from paste/code-sharing site (common malware dropper)", "paste_site"); return

    if _P.EBPF.search(line):
        add("CRITICAL", "eBPF program loading (potential rootkit)", "ebpf"); return

    if _P.PROC_PRIV.search(line):
        add("CRITICAL", "Reading privileged /proc entries", "proc_read"); return

    if _P.PROC_MEM.search(line):
        add("CRITICAL", "Direct /proc/<pid>/mem access (process injection)", "proc_read"); return

    if _P.FD_EXEC.search(line):
        add("CRITICAL", "Execution via /dev/fd or /proc/self/fd (evasion)", "fd_exec"); return

    if _P.DEV_TCP.search(line) or _P.NC_EXEC.search(line) or _P.SOCAT_EXEC.search(line):
        add("CRITICAL", "Reverse-shell pattern (/dev/tcp, nc -e, or socat exec)", "reverse_shell"); return

    if _P.MINER.search(line):
        add("CRITICAL", "Cryptocurrency-mining indicator", "crypto_miner"); return

    if _P.SUDOERS.search(line):
        add("CRITICAL", "sudoers file access/modification (privilege escalation)", "sudoers_tamper"); return

    if _P.ENV_EXFIL.search(line):
        add("CRITICAL", "Environment variables piped to network (credential exfiltration)", "env_exfil"); return

    if _P.LD_SO_PRELOAD.search(line) and not safe_write:
        add("CRITICAL", "Write to /etc/ld.so.preload (LD_PRELOAD rootkit)", "ld_preload_rootkit"); return

    if _P.PRINTF_EXEC.search(line):
        add("CRITICAL", "printf/echo hex payload piped into shell (shellcode)", "hex_obfuscation"); return

    if _P.SHM_EXEC.search(line):
        add("CRITICAL", "Script executed from /dev/shm or /run/shm", "source_temp"); return

    if _P.HEREDOC_EXEC.search(line):
        add("CRITICAL", "Shell/interpreter executes heredoc body (inline script injection)",
            "heredoc_exec"); return

    if _P.TR_OBFUSC.search(line):
        add("CRITICAL", "tr-based string transformation piped to shell (rot13/Caesar obfuscation)",
            "tr_obfusc"); return

    if _P.ROT13_PIPE.search(line):
        add("CRITICAL", "ROT13 transformation piped to interpreter (obfuscated command)",
            "tr_obfusc"); return

    if _P.HERE_STRING_EXEC.search(line):
        add("CRITICAL", "Here-string passing command-substituted content to interpreter",
            "here_string_exec"); return

    # v8: /dev/stdin exec
    if _P.STDIN_EXEC.search(line):
        add("CRITICAL", "Shell executes /dev/stdin — receives piped commands", "pipe_to_shell"); return

    # v8: read into eval
    if _P.READ_EVAL.search(line):
        add("CRITICAL", "read piped to eval — user/network input executed as shell code",
            "eval"); return

    # v8: dd writing to disk device
    if _P.DD_WRITE.search(line):
        add("CRITICAL", "dd writing to raw disk device — disk destructive / bootkit",
            "disk_destructive"); return

    # ── Obfuscation ──────────────────────────────────────────────────────────
    if YSHIELD_STRING_RECONSTRUCT and _P.VAR_SLICE.search(line):
        add("HIGH", "Variable-slicing command reconstruction (obfuscation)", "var_slice_obfuscation"); return

    if _P.ANSI_C_QUOTE.search(line) and re.search(r"(?i)(bash|sh|eval|exec|source|\bdo\b)", line):
        add("CRITICAL", "ANSI-C quoting ($'\\xNN') + shell execution (shellcode obfuscation)", "ansi_c_obfuscation"); return

    if _P.NAMESPACE.search(line):
        add("HIGH", "Namespace/container escape utility (nsenter/unshare/chroot)", "namespace_escape"); return

    if _P.PACMAN_U_NOCONFIRM.search(line):
        add("HIGH", "Silent pacman -U (local package install without confirmation)", "local_pkg_install"); return

    # v8: Glob obfuscation
    if YSHIELD_GLOB_OBFUSC and _P.GLOB_CMD_OBFUSC.search(line):
        m = _P.GLOB_CMD_OBFUSC.search(line)
        if m:
            candidate = m.group(1)
            # Only flag if it looks like it could be a shell command (short, lowercase, glob chars)
            if re.search(r'[?*]', candidate) and len(candidate) <= 8:
                add("HIGH",
                    f"Glob-based command name obfuscation detected: '{candidate}' "
                    "— shell glob expansion can hide command names from static scanners",
                    "glob_obfusc", 0.80); return

    # v8: Indirect variable reference
    if YSHIELD_INDIRECT_VAR and _P.INDIRECT_VAR_REF.search(line):
        add("HIGH",
            "${!var} indirect variable reference — can resolve to any command at runtime",
            "indirect_var_exec", 0.75); return

    # v8: Brace expansion obfuscation
    if _P.BRACE_EXPAND_OBFUSC.search(line):
        expanded_guess = re.sub(r'\{([a-z](?:,[a-z])+)\}',
                                lambda m: ''.join(m.group(1).split(',')), line)
        if _DL_MRE.search(expanded_guess) or _EXEC_MRE.search(expanded_guess):
            add("HIGH", "Brace expansion obfuscation of command name "
                f"(expands to: {expanded_guess[:80]})", "brace_expand_obfusc", 0.85); return

    # v8: printf building command char by char
    if _P.PRINTF_CHARBYCHAR.search(line) and not in_check_scope:
        add("HIGH", "printf char-by-char command reconstruction (obfuscation)",
            "printf_obfusc", 0.80); return

    # v8: FIFO exec
    if _P.FIFO_EXEC.search(line):
        add("HIGH", "Named pipe (FIFO) creation — potential covert execution channel",
            "fifo_exec", 0.75); return

    # v8: Associative array as command
    if _P.ASSOC_ARRAY_CMD.search(line):
        add("HIGH", "Associative array expansion used as command — "
            "possible command reconstruction via array elements",
            "associate_array_exec", 0.80); return

    # v8: xargs exec
    if _P.XARGS_EXEC.search(line):
        add("HIGH", "xargs passes data to shell/interpreter — possible injection vector",
            "interpreter_exec", 0.75); return

    # v8: char-concat obfuscation (3+ vars concatenated)
    if YSHIELD_STRING_RECONSTRUCT and _P.CHAR_CONCAT_EXEC.search(line):
        parts = re.findall(r'\$(?:\{[A-Za-z_]\w*\}|[A-Za-z_]\w*)', line)
        if len(parts) >= 4:
            add("HIGH", f"Excessive variable concatenation ({len(parts)} vars) — "
                "possible command reconstruction obfuscation",
                "char_concat_obfusc", 0.75); return

    # v8: shell option disable
    if YSHIELD_SHELL_OPT_ANALYSIS and _P.SHELL_OPT_DISABLE.search(line):
        add("MEDIUM", "Shell options disabled (set +e/+x/+v) — "
            "disables error-exit and tracing, common before covert operations",
            "shell_opt_disable", 0.65); return

    depth = _nested_subshell_depth(line)
    if depth >= 4:
        add("HIGH", f"Excessive nested command substitution depth ({depth}) — likely obfuscation",
            "ansi_c_obfuscation", 0.8); return

    if _P.INDIRECT_EXEC.search(line):
        add("MEDIUM", "declare/typeset -n/-f indirect function reference (potential indirect exec)", "indirect_exec"); return

    if _P.PROC_SUB_EXEC.search(line):
        add("HIGH", "Process-substitution passed to interpreter/source (evasion)", "process_sub_obfuscation"); return

    if _P.TILDE_PRIV.search(line):
        add("HIGH", "Tilde expansion to privileged user home directory", "secret_dir"); return

    if _P.GPG_BATCH.search(line):
        add("MEDIUM", "Silent/batch GPG key import (--batch --yes) — unconfirmed key acceptance", "gpg_keyimport"); return

    if _P.GIT_BYPASS.search(line):
        add("MEDIUM", "git --no-verify bypasses signature/hook verification", "gpg_keyimport"); return

    if _P.NO_TLS_VERIFY.search(line):
        add("HIGH", "TLS certificate verification disabled — MITM risk", "insecure_tls", 0.9); return

    if _P.FLAG_INJECTION.search(line):
        add("HIGH", "Variable used as command-line flags — possible flag injection",
            "flag_injection", 0.8); return

    if _P.CURL_SILENT_OUT.search(line) or _P.WGET_QUIET_OUT.search(line):
        add("HIGH", "Silent download to temp path (common dropper staging technique)",
            "pipe_to_shell", 0.85); return

    # ── HIGH tier ────────────────────────────────────────────────────────────
    if _P.SECRET_DIR.search(line):
        add("HIGH", "Access to credential/secret directory", "secret_dir"); return

    if _P.TOKEN.search(line):
        add("HIGH", "Reference to authentication token/credential variable", "token_ref"); return

    if _P.BROWSER.search(line):
        add("HIGH", "Access to browser profile/session data", "browser_profile"); return

    if _P.SSH_TOOL.search(line) and not in_check_scope:
        add("HIGH", "Remote shell/file-transfer tool in build script", "ssh_tool"); return

    if _P.ADMIN_CMD.search(line):
        add("HIGH", "User/group management command in build script", "admin_command"); return

    if _P.SUDO.search(line):
        add("HIGH", "sudo invocation in build script", "sudo_invocation"); return

    if _P.SUID.search(line):
        add("HIGH", "SUID/SGID bit set on file", "suid_bit"); return

    if _P.SETCAP.search(line):
        add("HIGH", "setcap invocation (Linux capability grant)", "setcap"); return

    if _P.KERNEL_MODULE.search(line) and "kernel" not in scan.pkg_type_hints:
        add("HIGH", "Kernel module load/unload command", "kernel_module"); return

    if _P.PACMAN_CONF.search(line):
        add("HIGH", "Modification of pacman configuration (may disable signature checks)", "pacman_conf_tamper"); return

    if _P.SHELL_RC.search(line):
        add("HIGH", "Modification of user shell startup file (persistence)", "shell_rc_persistence"); return

    if _P.PROFILE_D.search(line) and not safe_write:
        add("HIGH", "Write to /etc/profile.d (system-wide shell persistence)", "profile_d_persistence"); return

    if _P.SYSTEM_SHELLRC.search(line) and not safe_write:
        add("HIGH", "Write to system-wide shell init or /etc/environment (persistence)", "profile_d_persistence"); return

    if _P.CRONTAB_INSTALL.search(line):
        add("HIGH", "crontab installation (persistence)", "cron_persistence"); return

    if _P.HTTP_POST_EXFIL.search(line) and not in_source_line:
        add("HIGH", "Outbound HTTP POST with data (possible exfiltration)", "http_exfil", 0.85); return

    if _P.CRON.search(line):
        add("HIGH", "Cron/at job manipulation", "cron_persistence"); return

    if _P.SERVICE.search(line) and not _is_known_safe_service_control(line):
        add("HIGH", "System service control command", "service_control"); return

    if _P.TRACER.search(line):
        add("HIGH", "Process tracer (strace/gdb) on running process (credential scraping risk)",
            "strace_scraping"); return

    # v8: npm/pip/cargo registry tampering (in config files)
    if _P.NPM_REGISTRY_TAMPER.search(line):
        add("HIGH", "npm registry override detected — could redirect package downloads "
            "to attacker-controlled server (supply-chain attack)",
            "npm_registry_tamper", 0.90); return

    if _P.PIP_CONF_TAMPER.search(line):
        add("HIGH", "pip index-url override — redirects Python package downloads",
            "npm_registry_tamper", 0.90); return

    if _P.CARGO_REGISTRY.search(line) and rel.endswith(("config.toml", "config")):
        add("HIGH", "Cargo registry/source override in config — may redirect crate downloads",
            "cargo_registry_tamper", 0.85); return

    # v8: PKGBUILD self-modification
    if _P.PKGBUILD_SELF_MOD.search(line):
        add("HIGH", "PKGBUILD appears to modify itself during build — "
            "may inject malicious content that runs after initial scan",
            "self_modify", 0.85); return

    # v8: makepkg with integrity bypasses
    if _P.MAKEPKG_RECURSIVE.search(line):
        add("HIGH", "makepkg with integrity-skip flags (--skipinteg/--nosign) "
            "— may install unverified packages",
            "makepkg_recursive", 0.85); return

    # v8: proc/self/exe
    if _P.PROC_SELF_EXE.search(line):
        add("HIGH", "/proc/self/exe access — executable self-reference or replacement",
            "fd_exec", 0.80); return

    # ── Network fetch (context-sensitive) ────────────────────────────────────
    if _P.FETCH.search(line):
        if not in_source_line:
            if safe_cdn_url:
                add("LOW", "Network fetch from known CDN in build logic", "network_fetch", 0.5)
            elif safe_ecosystem:
                add("LOW", "Network fetch in ecosystem build context", "network_fetch", 0.5)
            elif in_check_scope:
                add("LOW", "Network fetch in check() scope", "network_fetch", 0.4)
            else:
                add("HIGH", "Network fetch in build logic (unexpected)", "network_fetch")
        return

    # ── MEDIUM tier ──────────────────────────────────────────────────────────
    if _P.DNS_EXFIL.search(line):
        add("MEDIUM", "DNS query with command substitution (possible DNS exfiltration)", "dns_exfil"); return

    if _P.GPG_KEY.search(line):
        add("MEDIUM", "GPG key import from keyserver — verify key ownership", "gpg_keyimport"); return

    if _P.AUTOSTART.search(line):
        add("MEDIUM", "XDG autostart entry (persistence)", "xdg_autostart"); return

    if _P.SYSTEMD_USER.search(line):
        add("MEDIUM", "systemd user-unit manipulation", "systemd_user_unit"); return

    if _P.HISTORY_TAMPER.search(line):
        add("MEDIUM", "Shell history disabling (evasion)", "history_tamper"); return

    if _P.DBUS.search(line):
        add("MEDIUM", "dbus call — can silently interact with desktop session", "dbus_desktop_access"); return

    if _P.AT_SCHEDULE.search(line):
        add("MEDIUM", "at/batch job scheduling (persistence/delayed execution)", "at_batch_schedule"); return

    if _P.GIT_CLONE.search(line) and "vcs" not in scan.pkg_type_hints:
        add("MEDIUM", "git clone in build logic (potential secondary payload)", "git_clone"); return

    if _P.DOWNLOAD_SCRIPT.search(line) and not safe_cdn_url:
        add("MEDIUM", "Download of executable/script file", "download_script"); return

    if _P.LOCAL_PKG.search(line):
        add("MEDIUM", "Local package installation from file (pacman -U)", "local_pkg_install"); return

    if _P.INTERP.search(line):
        add("MEDIUM", "Inline interpreter execution", "interpreter_exec"); return

    if _P.CHMOD_CRITICAL.search(line) and not safe_write:
        add("MEDIUM", "Permission change on critical system directory", "permission_escalation"); return

    if _P.SOURCE_TEMP.search(line):
        add("MEDIUM", "Sourcing/executing script from temp/volatile path", "source_temp"); return

    if _P.FIREWALL.search(line):
        add("MEDIUM", "Firewall rule manipulation", "service_control"); return

    if _P.ETC_HOSTS.search(line):
        add("MEDIUM", "Modification of /etc/hosts", "etc_hosts"); return

    if _P.PROC_HIDE.search(line):
        add("MEDIUM", "/proc remount or hidepid manipulation (process hiding)", "proc_hide"); return

    if _P.ANSI_C_QUOTE.search(line):
        add("MEDIUM", "ANSI-C quoting ($'...') with non-printable escapes — possible obfuscation",
            "ansi_c_obfuscation", 0.7); return

    if _P.POLYGLOT_PY.search(line) and rel.endswith((".sh", ".bash", "PKGBUILD")):
        add("MEDIUM", "Python import statement in shell script (possible polyglot payload)",
            "polyglot", 0.75); return

    if _P.POLYGLOT_PHP.search(line):
        add("HIGH", "PHP opening tag in file (polyglot attack)", "polyglot", 0.9); return

    # v8: cmake ExternalProject
    if YSHIELD_BUILD_SYSTEM_DEEP and _P.CMAKE_EXTERNAL.search(line):
        add("MEDIUM", "CMake ExternalProject_Add with URL — fetches code during build "
            "(unverified external dependency)", "cmake_external", 0.80); return

    # v8: meson wrap
    if YSHIELD_BUILD_SYSTEM_DEEP and _P.MESON_WRAP.search(line):
        add("MEDIUM", "Meson wrap file detected — downloads external source during build "
            "(supply chain risk)", "meson_wrap", 0.75); return

    # ── LOW tier ─────────────────────────────────────────────────────────────
    if _P.ECO_INSTALL.search(line):
        conf = 0.35 if safe_ecosystem else 0.85
        add("LOW", "Language ecosystem build/install command", "eco_install", conf); return

    if _P.WRITE_SYS.search(line) and not safe_write:
        add("HIGH", "Write/copy to sensitive system path", "system_path_write"); return

    if re.search(r"(?i)\b(LD_PRELOAD|DYLD_INSERT_LIBRARIES)\s*=", line):
        add("MEDIUM", "Dynamic linker env manipulation (LD_PRELOAD)", "ld_preload_rootkit"); return

    if re.search(r"(?i)\bLD_LIBRARY_PATH\s*=", line):
        if re.search(r"(?i)(/tmp/|/dev/shm/|/proc/self|curl|wget|base64|eval)", line):
            add("HIGH", "LD_LIBRARY_PATH with suspicious path/construction", "ld_preload_rootkit")
        else:
            add("LOW", "LD_LIBRARY_PATH assignment (common in wrappers)", "eco_install", 0.3)
        return

    # v8: masqueraded file extension used in execution
    if _P.MASQUERADE_EXT.search(line):
        add("MEDIUM", "File with benign extension (png/jpg/pdf) used in execution context "
            "— possible extension masquerading", "polyglot", 0.75); return

    entropy_findings(scan, rel, line_no, line, scope=scope, is_install_file=is_install_file)


def _nested_subshell_depth(line: str) -> int:
    depth = max_depth = 0
    i = 0
    while i < len(line):
        if line[i:i+2] == "$(":
            depth += 1
            max_depth = max(max_depth, depth)
            i += 2
        elif line[i] == ")":
            depth = max(0, depth - 1)
            i += 1
        else:
            i += 1
    return max_depth


def _scan_expanded(scan: PackageScan, rel: str, line_no: int,
                   expanded: str, original: str,
                   *, scope: str, is_install_file: bool) -> None:
    if expanded == original:
        return
    for pat, sev, reason, cat in [
        (_P.DANGEROUS_PIPE,   "CRITICAL", "Variable expansion reveals download-pipe-to-shell", "pipe_to_shell"),
        (_P.EVAL,             "CRITICAL", "Variable expansion reveals eval()", "eval"),
        (_P.DECODE,           "CRITICAL", "Variable expansion reveals decode operation", "decode_pattern"),
        (_P.MINER,            "CRITICAL", "Variable expansion reveals mining software", "crypto_miner"),
        (_P.PASTE_SITE,       "CRITICAL", "Variable expansion reveals paste-site download", "paste_site"),
        (_P.DEV_TCP,          "CRITICAL", "Variable expansion reveals /dev/tcp reverse shell", "reverse_shell"),
        (_P.NC_EXEC,          "CRITICAL", "Variable expansion reveals nc -e reverse shell", "reverse_shell"),
        (_P.SUDOERS,          "CRITICAL", "Variable expansion reveals sudoers write", "sudoers_tamper"),
        (_P.PROC_SUB_NET,     "CRITICAL", "Variable expansion reveals process-substitution network exec", "proc_sub_net_exec"),
        (_P.EVAL_NET_SUBSHELL,"CRITICAL", "Variable expansion reveals eval+network fetch", "proc_sub_net_exec"),
    ]:
        if pat.search(expanded) and not pat.search(original):
            scan.add(sev, f"{rel}[var-expanded]", line_no,
                     reason, evidence=f"original: {original[:80]} → expanded: {expanded[:80]}",
                     confidence=0.9, category=cat,
                     scope=scope, is_install_file=is_install_file)

# ─────────────────────────────────────────────────────────────────────────────
# ShellCheck integration
# ─────────────────────────────────────────────────────────────────────────────

SHELLCHECK_DANGEROUS_CODES: Dict[str, Tuple[str, str]] = {
    "SC2091": ("MEDIUM", "SC2091: expression executes as command — likely unintended execution"),
    "SC2046": ("MEDIUM", "SC2046: unquoted command substitution — word-splitting injection risk"),
    "SC2086": ("LOW",    "SC2086: unquoted variable — word-splitting risk"),
    "SC2006": ("MEDIUM", "SC2006: backtick command substitution — legacy/obfuscated syntax"),
    "SC2164": ("LOW",    "SC2164: cd without error handling — unintended path traversal risk"),
    "SC2094": ("LOW",    "SC2094: TOCTOU risk — write to file also read in pipeline"),
    "SC2059": ("MEDIUM", "SC2059: printf format string uses variable — format string injection"),
    "SC2155": ("MEDIUM", "SC2155: declare+assign on same line — exit code masking"),
    "SC2162": ("LOW",    "SC2162: read without -r — backslash mangling"),
    "SC2148": ("LOW",    "SC2148: shebang missing — file interpreted as Bash by makepkg"),
    "SC2050": ("MEDIUM", "SC2050: expression is always true (possible logic error)"),
    "SC2218": ("MEDIUM", "SC2218: function used before definition — possible shadowing"),
}

def run_shellcheck(scan: PackageScan, rel: str, path: Path) -> None:
    if not YSHIELD_SHELLCHECK or not command_exists("shellcheck"):
        return
    try:
        cp = run(
            ["shellcheck", "--format=json", "--shell=bash", "--severity=style", "--", str(path)],
            capture_output=True, check=False, timeout=30,
        )
        if not cp.stdout:
            return
        items = json.loads(cp.stdout)
    except Exception as exc:
        debug(f"shellcheck failed for {rel}: {exc}")
        return
    for item in items:
        code = f"SC{item.get('code', 0)}"
        if code not in SHELLCHECK_DANGEROUS_CODES:
            continue
        sev, reason = SHELLCHECK_DANGEROUS_CODES[code]
        line_no = int(item.get("line", 0))
        message = item.get("message", "")
        scan.add(sev, rel, line_no,
                 f"shellcheck {reason} — {message}",
                 category="shellcheck", confidence=0.65)

# ─────────────────────────────────────────────────────────────────────────────
# PKGBUILD structural checks (v8 extended)
# ─────────────────────────────────────────────────────────────────────────────

def scan_pkgbuild_structure(scan: PackageScan, repo_dir: Path) -> None:
    path = repo_dir / "PKGBUILD"
    if not path.exists():
        return

    try:
        cp = run(["bash", "-n", str(path)], check=False, capture_output=True)
        if cp.returncode != 0:
            scan.add("HIGH", "PKGBUILD", 0,
                     "PKGBUILD failed bash -n syntax check (tampered/malformed)",
                     cp.stderr or "", category="syntax")
    except Exception:
        pass

    run_shellcheck(scan, "PKGBUILD", path)

    try:
        data = read_text(path)
    except Exception:
        return

    scan.build_systems  = detect_build_system(data)
    scan.pkg_type_hints = package_type_hints(scan.pkg)
    scan.var_map        = extract_pkgbuild_vars(data) if YSHIELD_SEMANTIC_VARS else {}
    debug(f"Build systems: {scan.build_systems}, hints: {scan.pkg_type_hints}")

    source_blocks_for_noise = extract_shell_array_blocks(data, {"source"})
    flat_sources_for_noise = [v for b in source_blocks_for_noise for v in b.values if v and v not in {"(", ")"}]
    remote_non_vcs_sources = [
        _source_without_fragment(s) for s in flat_sources_for_noise
        if _is_remote_source(_source_without_fragment(s)) and not _is_vcs_source(s)
    ]

    # Structural integrity checks
    if _P.SOURCE_LINE.search(data) and not _P.CHECKSUM_LINE.search(data):
        if remote_non_vcs_sources:
            scan.add("HIGH", "PKGBUILD", 0,
                     "Remote non-VCS source= entry has no checksum array",
                     category="missing_checksums", confidence=0.92)

    if _P.SKIP_CHECKSUM.search(data):
        if remote_non_vcs_sources and "vcs" not in scan.pkg_type_hints:
            scan.add("HIGH", "PKGBUILD", 0,
                     "Checksum set to SKIP for a remote non-VCS source (integrity bypass)",
                     category="skip_checksum", confidence=0.92)
        else:
            scan.add("LOW", "PKGBUILD", 0,
                     "Checksum SKIP present, but package appears VCS/local-only; verify source integrity manually",
                     category="skip_checksum", confidence=0.40)

    if _P.NO_CHECK.search(data):
        scan.add("MEDIUM", "PKGBUILD", 0,
                 "options=(!check) disables package check() phase", category="no_check")

    if _P.NON_HTTPS_SRC.search(data):
        scan.add("HIGH", "PKGBUILD", 0,
                 "Insecure (non-HTTPS) source transport in source=()", category="insecure_source")

    if _P.IP_SOURCE.search(data):
        scan.add("HIGH", "PKGBUILD", 0,
                 "source URL points to IP address (potential C2/dropper)", category="ip_source")

    if _P.SUSPICIOUS_TLD.search(data):
        scan.add("HIGH", "PKGBUILD", 0,
                 "source URL uses suspicious TLD (common malware hosting)", category="suspicious_tld")

    epoch_m = _P.EPOCH_HIGH.search(data)
    if epoch_m and int(epoch_m.group(1)) > 99:
        scan.add("MEDIUM", "PKGBUILD", 0,
                 f"Unusually high epoch={epoch_m.group(1)} (may force updates bypassing version order)",
                 category="high_epoch")

    install_m = _P.INSTALL_NO_FILE.search(data)
    if install_m:
        script_name = re.sub(r"^install=['\"]?|['\"]?$", "",
                             install_m.group(0).strip()).strip()
        if script_name and not (repo_dir / script_name).exists():
            scan.add("MEDIUM", "PKGBUILD", 0,
                     f"install= references '{script_name}' but file not found in repo",
                     category="missing_install_file")

    if _P.UNPINNED_VCS.search(data) and not _P.VCS_PINNED.search(data):
        if "vcs" in scan.pkg_type_hints:
            scan.add("LOW", "PKGBUILD", 0,
                     "VCS package uses a moving source reference; expected for -git/-svn style packages",
                     category="unpinned_vcs_source", confidence=0.40)
        else:
            scan.add("MEDIUM", "PKGBUILD", 0,
                     "VCS source without explicit commit/tag pinning (weaker supply-chain integrity)",
                     category="unpinned_vcs_source", confidence=0.70)

    if _P.VALIDPGP_EMPTY.search(data):
        scan.add("MEDIUM", "PKGBUILD", 0,
                 "validpgpkeys=() is empty — upstream PGP verification disabled",
                 category="no_pgp_validation")

    if _P.INTEGRITY_DISABLED.search(data):
        scan.add("MEDIUM", "PKGBUILD", 0,
                 "Multiple package integrity checks disabled via options= (strip/debug/check)",
                 category="integrity_disabled")

    # GPG key trust
    if YSHIELD_GPG_VERIFY:
        gpg_keys = extract_validpgpkeys(data)
        if gpg_keys:
            _check_gpg_key_trust(gpg_keys, scan)

    # v7/v8: source URL cross-reference
    check_source_url_crossref(scan, data)

    # v7/v8: dependency confusion
    check_dependency_confusion(scan, data)

    # URL-level checks
    for url in _P.URL.findall(data):
        if _P.NEWISH_DOMAIN.search(url):
            scan.add("MEDIUM", "PKGBUILD (source URL)", 0,
                     f"Source URL domain looks algorithmically named: {url[:80]}",
                     category="newish_domain", confidence=0.6)
        if _P.BAD_DOMAIN.search(url):
            scan.add("CRITICAL", "PKGBUILD (source URL)", 0,
                     f"Source URL looks like a typosquatted domain: {url[:80]}",
                     category="domain_typosquat")
        hint = check_url_homoglyphs(url)
        if hint and YSHIELD_HOMOGLYPH:
            scan.add("CRITICAL", "PKGBUILD (source URL)", 0, hint, category="homoglyph")

    _check_global_download_functions(scan, data)

    # v8: check for PKGBUILD function ordering issues
    _check_function_ordering(scan, data)


def _check_function_ordering(scan: PackageScan, data: str) -> None:
    """Check for suspicious patterns in function structure."""
    # Check if package() writes outside $pkgdir
    lines = data.splitlines()
    in_package = False
    depth = 0
    for i, line in enumerate(lines, 1):
        if re.match(r"^\s*package(?:_\S+)?\s*\(\s*\)\s*\{?\s*$", line, re.I):
            in_package = True
            depth = 0
        if in_package:
            depth += line.count("{") - line.count("}")
            if depth <= 0 and in_package and i > 1:
                in_package = False
            if in_package and _P.WRITE_SYS.search(line) and "$pkgdir" not in line and "DESTDIR" not in line:
                scan.add("HIGH", "PKGBUILD", i,
                         "package() writes to system path outside $pkgdir — unexpected side effect",
                         evidence=line, category="system_path_write", scope="package",
                         confidence=0.85)


def _check_global_download_functions(scan: PackageScan, data: str) -> None:
    known_pkgbuild_funcs = {
        "prepare","build","check","package","pkgver",
        "pre_install","post_install","pre_upgrade","post_upgrade","pre_remove","post_remove",
    }
    lines = data.splitlines()
    in_func = False
    func_name = ""
    depth = 0
    func_has_download = False
    for raw in lines:
        line = raw.strip()
        if not in_func:
            m = _P.FUNC_DEF.match(raw)
            if m:
                func_name = m.group(1)
                if func_name not in known_pkgbuild_funcs and not func_name.startswith("package_"):
                    in_func = True
                    depth = 0
        if in_func:
            depth += raw.count("{") - raw.count("}")
            if _DL_MRE.search(line):
                func_has_download = True
            if depth <= 0:
                if func_has_download:
                    scan.add("HIGH", "PKGBUILD", 0,
                             f"Non-standard function '{func_name}()' performs network download "
                             "— possible payload delivery helper",
                             category="suspicious_helper_func", confidence=0.8)
                in_func = False
                func_name = ""
                func_has_download = False


def check_git_submodules(scan: PackageScan, repo_dir: Path) -> None:
    if (repo_dir / ".gitmodules").exists():
        scan.add("HIGH", ".gitmodules", 0,
                 "Repo contains .gitmodules (submodules can hide malicious secondary code)",
                 category="git_submodules")
    cp = git("submodule", "status", "--recursive", cwd=repo_dir, capture_output=True)
    if (cp.stdout or "").strip():
        scan.add("HIGH", "git-submodule", 0,
                 "Active git submodule references detected", cp.stdout or "",
                 category="git_submodules")


def inspect_git_history(scan: PackageScan, repo_dir: Path) -> None:
    cp = git("rev-list", "--count", "HEAD", cwd=repo_dir, capture_output=True)
    try:
        commit_count = int((cp.stdout or "0").strip() or "0")
    except ValueError:
        commit_count = 0
    if commit_count == 0:
        return

    depth = min(commit_count, YSHIELD_DIFF_COMMITS)
    log_cp = git("log", "--oneline", f"-{depth}", cwd=repo_dir, capture_output=True)
    for log_line in (log_cp.stdout or "").splitlines():
        if _P.RECENT_COMMIT.search(log_line):
            scan.add("MEDIUM", "git-log", 0,
                     f"Recent commit message contains suspicious keyword: {log_line}",
                     category="suspicious_commit_msg")

    if commit_count == 1:
        scan.add("MEDIUM", "git-history", 0,
                 "AUR repo has only 1 commit (possible force-push to hide history)",
                 category="suspicious_commit_msg", confidence=0.6)

    if depth >= 2:
        diff_cp = git("diff", f"HEAD~{depth-1}..HEAD", "--", "PKGBUILD",
                      cwd=repo_dir, capture_output=True)
    else:
        diff_cp = git("show", "HEAD:PKGBUILD", cwd=repo_dir, capture_output=True)
    diff_text = diff_cp.stdout or ""

    for added in diff_text.splitlines():
        if not added.startswith("+") or added.startswith("+++"):
            continue
        line = added[1:]
        if (_P.DANGEROUS_PIPE.search(line) or _P.EVAL.search(line)
                or _P.DECODE.search(line) or _P.SHELL_C.search(line)
                or _P.PROC_SUB_NET.search(line)):
            scan.add("HIGH", "git-diff (PKGBUILD)", 0,
                     "Recent PKGBUILD commit introduced suspicious pattern", line,
                     category="recent_diff_suspicious")

    # v8: check commit signatures if GPG available
    if YSHIELD_GPG_VERIFY and command_exists("gpg"):
        sig_cp = git("log", "--show-signature", "-1", cwd=repo_dir, capture_output=True)
        sig_out = sig_cp.stdout or ""
        if "Good signature" not in sig_out and "gpg: " in sig_out:
            scan.add("LOW", "git-signature", 0,
                     "Most recent commit is not GPG-signed or signature invalid — "
                     "reduced verifiability of commit authorship",
                     category="gpg_keyimport", confidence=0.4)


def check_srcinfo_consistency(scan: PackageScan, repo_dir: Path) -> None:
    if not YSHIELD_CHECK_SRCINFO:
        return
    srcinfo  = repo_dir / ".SRCINFO"
    pkgbuild = repo_dir / "PKGBUILD"
    if not pkgbuild.exists():
        return
    if not srcinfo.exists():
        scan.add("LOW", ".SRCINFO", 0, ".SRCINFO file missing from repo",
                 category="srcinfo_missing", confidence=0.3)
        return
    try:
        si_text = read_text(srcinfo)
        pb_text = read_text(pkgbuild)
    except Exception:
        return

    si_pkgbase = re.search(r"(?m)^\s*pkgbase\s*=\s*(\S+)", si_text)
    pb_pkgbase = re.search(r"(?m)^\s*pkgbase=([A-Za-z0-9._+@-]+)", pb_text)
    pb_pkgname = re.search(r"(?m)^\s*pkgname=([A-Za-z0-9._+@-]+)", pb_text)
    expected = pb_pkgbase or pb_pkgname
    if si_pkgbase and expected and si_pkgbase.group(1) != expected.group(1):
        scan.add("MEDIUM", ".SRCINFO", 0,
                 f".SRCINFO pkgbase ('{si_pkgbase.group(1)}') doesn't match PKGBUILD "
                 f"('{expected.group(1)}') — stale metadata / possible tamper",
                 category="srcinfo_mismatch")

    si_sources = re.findall(r"(?m)^\s*source\s*=\s*(\S+)", si_text)
    pb_sources = re.findall(r"(?ms)source(?:_\w+)?\+?=\(([^)]+)\)", pb_text)
    if si_sources and pb_sources:
        si_count = len(si_sources)
        pb_count = len(re.findall(r"['\"]?[^\s'\"]+['\"]?", pb_sources[0]))
        if abs(si_count - pb_count) > 2:
            scan.add("HIGH", ".SRCINFO", 0,
                     f".SRCINFO lists {si_count} source(s) but PKGBUILD has ~{pb_count} "
                     "— metadata/code divergence (tampered PKGBUILD?)",
                     category="srcinfo_mismatch")


def check_source_integrity_deep(scan: PackageScan, repo_dir: Path) -> None:
    if not YSHIELD_SOURCE_INTEGRITY_DEEP:
        return
    pkgbuild = repo_dir / "PKGBUILD"
    if not pkgbuild.exists():
        return
    try:
        text = read_text(pkgbuild)
    except Exception:
        return

    source_blocks = extract_shell_array_blocks(text, {"source"})
    sum_blocks = extract_shell_array_blocks(text, {
        "sha256sums", "sha512sums", "b2sums", "md5sums", "sha1sums",
        "cksums", "sha224sums", "sha384sums",
    })

    for block in source_blocks + sum_blocks:
        if not block.closed:
            scan.add("HIGH", "PKGBUILD", block.line,
                     f"Malformed/unclosed {block.name}=() array; static integrity checks may be bypassed",
                     evidence=safe_join_preview(block.body),
                     category="source_integrity", confidence=0.90)

    sources = [v for b in source_blocks for v in b.values if v and v not in {"(", ")"}]
    sums = [v for b in sum_blocks for v in b.values if v and v not in {"(", ")"}]
    non_vcs_sources = [s for s in sources if not _is_vcs_source(s)]
    remote_non_vcs_sources = [
        s for s in non_vcs_sources
        if _is_remote_source(_source_without_fragment(s))
    ]
    effective_sums = [s for s in sums if not _is_checksum_skip(s)]

    if remote_non_vcs_sources and not sum_blocks:
        scan.add("HIGH", "PKGBUILD", 0,
                 "Remote non-VCS source=() entries exist but no checksum array could be statically extracted",
                 category="missing_checksums", confidence=0.90)

    if sources and sums and len(sums) != len(sources):
        scan.add("MEDIUM", "PKGBUILD", 0,
                 f"source/checksum count mismatch ({len(sources)} source entries vs {len(sums)} checksum entries)",
                 category="source_integrity", confidence=0.65)

    if _P.WEAK_CHECKSUM_LINE.search(text) and not _P.CHECKSUM_LINE.search(text):
        scan.add("MEDIUM", "PKGBUILD", 0,
                 "Only weak checksum algorithms found (md5/sha1/ck); prefer sha256/sha512/b2",
                 category="source_integrity", confidence=0.75)

    for block in source_blocks:
        for value in block.values:
            if not value:
                continue
            src = _source_without_fragment(value)
            if _P.SOURCE_CMD_SUBST.search(value):
                sev = "CRITICAL" if re.search(r"(?i)(curl|wget|fetch|eval|bash|sh|python|perl|ruby)", value) else "HIGH"
                scan.add(sev, "PKGBUILD", block.line,
                         "source=() entry contains command/parameter substitution; source URL can change at build time",
                         evidence=safe_join_preview(value),
                         category="source_command_subst", confidence=0.92)
            if _P.SHELL_META_FILENAME.search(src) and not _is_remote_source(src):
                scan.add("MEDIUM", "PKGBUILD", block.line,
                         "Local source filename contains shell metacharacters or whitespace",
                         evidence=safe_join_preview(value),
                         category="source_integrity", confidence=0.65)
            if not _is_remote_source(src) and "$" not in src and not src.startswith(("/", "~")):
                if src and not (repo_dir / src).exists():
                    scan.add("MEDIUM", "PKGBUILD", block.line,
                             f"Local source file referenced but not tracked/present: {src}",
                             category="source_integrity", confidence=0.70)
            if _P.ARCHIVE_EXT.search(src) and (not sums or all(_is_checksum_skip(s) for s in sums)):
                sev = "HIGH" if not _is_vcs_source(value) else "MEDIUM"
                scan.add(sev, "PKGBUILD", block.line,
                         "Archive source has no effective checksum verification",
                         evidence=safe_join_preview(value),
                         category="source_integrity", confidence=0.85)

    if remote_non_vcs_sources and sums and not effective_sums:
        scan.add("HIGH", "PKGBUILD", 0,
                 "All checksum entries are SKIP for remote non-VCS sources",
                 category="skip_checksum", confidence=0.95)


def scan_symlink_and_archive_risks(scan: PackageScan, repo_dir: Path) -> None:
    try:
        cp = git("ls-files", "-z", cwd=repo_dir, capture_output=True)
        tracked = [r for r in (cp.stdout or "").split("\0") if r]
    except Exception:
        return

    sensitive_prefixes = ("/etc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/proc/", "/dev/", "/root/")
    tool_names = {"yay", "pacman", "git", "curl", "wget", "sudo", "su", "makepkg", "bash", "sh", "python", "python3"}
    for rel in tracked[:2000]:
        p = repo_dir / rel
        if YSHIELD_SYMLINK_SCAN and p.is_symlink():
            try:
                target = os.readlink(p)
            except OSError:
                target = ""
            norm = os.path.normpath(target)
            if target.startswith(sensitive_prefixes) or norm.startswith("../") or "/../" in norm:
                scan.add("HIGH", rel, 0,
                         f"Tracked symlink points outside the package tree: {target}",
                         category="symlink_escape", confidence=0.88)
            elif target.startswith("/"):
                scan.add("MEDIUM", rel, 0,
                         f"Tracked symlink uses absolute target: {target}",
                         category="symlink_escape", confidence=0.70)

        name = Path(rel).name
        if YSHIELD_ARCHIVE_RISK_SCAN:
            if rel.startswith("../") or "/../" in rel or rel.startswith("/"):
                scan.add("HIGH", rel, 0,
                         "Tracked path contains traversal/absolute path components",
                         category="archive_traversal", confidence=0.90)
            if _P.SHELL_META_FILENAME.search(rel):
                scan.add("LOW", rel, 0,
                         "Tracked filename contains shell metacharacters/whitespace; review quoting in PKGBUILD",
                         category="archive_traversal", confidence=0.45)

        if name in tool_names:
            try:
                mode = p.stat().st_mode
            except OSError:
                mode = 0
            sev = "HIGH" if (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) else "MEDIUM"
            scan.add(sev, rel, 0,
                     f"Repository contains file named like a trusted tool ('{name}') — possible PATH shadowing",
                     category="repo_shadowing", confidence=0.78)


def check_pkgbuild_changed(scan: PackageScan, pkg: str, repo_dir: Path) -> None:
    pkgbuild = repo_dir / "PKGBUILD"
    if not pkgbuild.exists():
        return
    current = sha256_file(pkgbuild)
    cfile   = cache_file_for_pkg(pkg)
    if cfile.exists():
        old = cfile.read_text(encoding="utf-8", errors="ignore").strip()
        if old and old != current:
            scan.add("HIGH", "PKGBUILD (cache)", 0,
                     "PKGBUILD has changed since last yay-shield scan — review the diff!",
                     category="pkgbuild_changed")
            info(f"Previous PKGBUILD SHA256: {old}")
            info(f"Current  PKGBUILD SHA256: {current}")
        else:
            info("PKGBUILD unchanged since last scan. ✓")
    else:
        info(f"No previous scan cached for {pkg}; saving baseline now.")
    try:
        cfile.write_text(current + "\n", encoding="utf-8")
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# v8 Build-system-specific deep scan
# ─────────────────────────────────────────────────────────────────────────────

def scan_build_system_files(scan: PackageScan, repo_dir: Path) -> None:
    """Deep scan of build system config files for supply-chain issues."""
    if not YSHIELD_BUILD_SYSTEM_DEEP:
        return

    # CMakeLists.txt: ExternalProject_Add, FetchContent with no hash
    for cmake_file in list(repo_dir.rglob("CMakeLists.txt"))[:5]:
        try:
            content = read_text(cmake_file)
            rel = str(cmake_file.relative_to(repo_dir))
            for i, line in enumerate(content.splitlines(), 1):
                if _P.CMAKE_EXTERNAL.search(line):
                    # Check if there's a URL_HASH in the block
                    block_start = max(0, i - 1)
                    block_end   = min(len(content.splitlines()), i + 20)
                    block       = "\n".join(content.splitlines()[block_start:block_end])
                    if "URL_HASH" not in block and "GIT_TAG" not in block:
                        scan.add("MEDIUM", rel, i,
                                 "CMake ExternalProject_Add without URL_HASH or GIT_TAG "
                                 "— unpinned external dependency",
                                 evidence=line, category="cmake_external", confidence=0.80)
        except Exception:
            pass

    # meson.wrap files
    for wrap_file in list((repo_dir / "subprojects").glob("*.wrap"))[:5] if (repo_dir / "subprojects").exists() else []:
        try:
            content = read_text(wrap_file)
            rel = str(wrap_file.relative_to(repo_dir))
            if _P.MESON_WRAP.search(content):
                if not re.search(r"(?i)(hash|sha256|sha512)", content):
                    scan.add("MEDIUM", rel, 0,
                             "Meson wrap file without hash verification — unpinned dependency",
                             category="meson_wrap", confidence=0.75)
        except Exception:
            pass

    # .npmrc: registry override
    npmrc = repo_dir / ".npmrc"
    if npmrc.exists():
        try:
            content = read_text(npmrc)
            if _P.NPM_REGISTRY_TAMPER.search(content):
                scan.add("HIGH", ".npmrc", 0,
                         "Custom npm registry in .npmrc — package downloads redirected",
                         evidence=content[:200], category="npm_registry_tamper", confidence=0.92)
        except Exception:
            pass

    # .cargo/config.toml: registry override
    cargo_config = repo_dir / ".cargo" / "config.toml"
    if cargo_config.exists():
        try:
            content = read_text(cargo_config)
            rel = ".cargo/config.toml"
            if _P.CARGO_REGISTRY.search(content):
                scan.add("HIGH", rel, 0,
                         "Cargo source/registry override in .cargo/config.toml "
                         "— crate downloads may be redirected",
                         evidence=content[:200], category="cargo_registry_tamper", confidence=0.90)
        except Exception:
            pass

def scan_manifest_files(scan: PackageScan, repo_dir: Path) -> None:
    if not YSHIELD_MANIFEST_DEEP:
        return

    pkg_json = repo_dir / "package.json"
    if pkg_json.exists() and is_text_file(pkg_json):
        data = load_json_manifest(scan, "package.json", pkg_json)
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if isinstance(scripts, dict):
            for name, cmd in scripts.items():
                if not isinstance(cmd, str):
                    continue
                lifecycle = name in {"preinstall", "install", "postinstall", "prepare", "prepublish", "postpack"}
                if lifecycle and any(p.search(cmd) for p in (
                    _P.DANGEROUS_PIPE, _P.EVAL, _P.DECODE, _P.DEV_TCP,
                    _P.NC_EXEC, _P.SOCAT_EXEC, _P.PASTE_SITE, _P.NO_TLS_VERIFY,
                    _P.PYTHON_ONE_LINER, _P.PROC_SUB_NET, _P.EVAL_NET_SUBSHELL,
                )):
                    scan.add("CRITICAL", "package.json", 0,
                             f"npm lifecycle script '{name}' contains dangerous execution/fetch logic",
                             evidence=cmd[:200], category="manifest_script", confidence=0.95)
                elif lifecycle and (_P.FETCH.search(cmd) or _P.INTERP.search(cmd) or _P.SHELL_C.search(cmd)):
                    scan.add("HIGH", "package.json", 0,
                             f"npm lifecycle script '{name}' executes network/interpreter logic",
                             evidence=cmd[:200], category="manifest_script", confidence=0.85)
                elif lifecycle and re.search(r"(?i)\b(node|npm|pnpm|yarn)\b.*\b(run|exec|dlx|create)\b", cmd):
                    scan.add("MEDIUM", "package.json", 0,
                             f"npm lifecycle script '{name}' delegates to package-manager execution",
                             evidence=cmd[:200], category="package_manager_hook", confidence=0.65)
        for field in ("resolutions", "overrides", "packageManager"):
            if isinstance(data, dict) and field in data:
                scan.add("LOW", "package.json", 0,
                         f"package.json uses '{field}' which can alter dependency resolution",
                         category="package_manager_hook", confidence=0.45)

    cargo_toml = repo_dir / "Cargo.toml"
    if cargo_toml.exists() and is_text_file(cargo_toml):
        content = read_manifest_text(scan, "Cargo.toml", cargo_toml) or ""
        cargo_data = load_toml_manifest(scan, "Cargo.toml", cargo_toml)
        if _P.CARGO_BUILD_RS.search(content):
            build_rs = repo_dir / "build.rs"
            if build_rs.exists() and is_text_file(build_rs):
                build_text = read_manifest_text(scan, "build.rs", build_rs) or ""
                if any(p.search(build_text) for p in (
                    _P.FETCH, _P.DANGEROUS_PIPE, _P.EVAL, _P.SHELL_C,
                    _P.DEV_TCP, _P.NC_EXEC, _P.PASTE_SITE, _P.PROC_SUB_NET,
                )):
                    scan.add("HIGH", "build.rs", 0,
                             "Cargo build.rs performs network or dynamic shell behavior during build",
                             evidence=build_text[:240], category="cargo_build_script",
                             confidence=0.85)
        cargo_remote_patch = bool(_P.CARGO_PATCH_REMOTE.search(content))
        if cargo_remote_patch:
            scan.add("HIGH", "Cargo.toml", 0,
                     "Cargo patch/source override redirects crates to a non-standard remote",
                     evidence=safe_join_preview(_P.CARGO_PATCH_REMOTE.search(content).group(0)),
                     category="cargo_registry_tamper", confidence=0.85)
        if (not cargo_remote_patch and isinstance(cargo_data, dict)
                and any(str(k).startswith("patch") for k in cargo_data.keys())):
            scan.add("LOW", "Cargo.toml", 0,
                     "Cargo patch section present; dependency source is overridden",
                     category="cargo_registry_tamper", confidence=0.45)

    go_mod = repo_dir / "go.mod"
    if go_mod.exists() and is_text_file(go_mod):
        content = read_manifest_text(scan, "go.mod", go_mod) or ""
        if _P.GO_REPLACE_REMOTE.search(content):
            scan.add("MEDIUM", "go.mod", 0,
                     "go.mod replace directive points to a remote URL — dependency source is redirected",
                     evidence="\n".join(_P.GO_REPLACE_REMOTE.findall(content)[:3]),
                     category="go_replace", confidence=0.75)
        if _P.GO_EXCLUDE_REPLACE.search(content):
            count = len(_P.GO_EXCLUDE_REPLACE.findall(content))
            scan.add("LOW", "go.mod", 0,
                     f"go.mod contains {count} replace/exclude directive(s); review dependency source changes",
                     category="go_replace", confidence=0.45)

    for rel_name in ("pyproject.toml", "setup.cfg", "pip.conf", "tox.ini", "poetry.toml"):
        f = repo_dir / rel_name
        if not f.exists() or not is_text_file(f):
            continue
        if rel_name.endswith(".toml"):
            load_toml_manifest(scan, rel_name, f)
        elif rel_name.endswith((".cfg", ".ini")):
            load_ini_manifest(scan, rel_name, f)
        content = read_manifest_text(scan, rel_name, f) or ""
        if _P.PY_ALT_INDEX.search(content):
            scan.add("MEDIUM", rel_name, 0,
                     "Python packaging config references alternate indexes or trusted-host settings",
                     evidence=content[:240], category="npm_registry_tamper", confidence=0.70)

    for rel_name in ("package-lock.json", "npm-shrinkwrap.json"):
        f = repo_dir / rel_name
        if not f.exists() or not is_text_file(f) or not YSHIELD_LOCKFILE_SCAN:
            continue
        data = load_json_manifest(scan, rel_name, f)
        text = read_manifest_text(scan, rel_name, f) or ""
        if _P.LOCKFILE_HTTP.search(text):
            scan.add("HIGH", rel_name, 0,
                     "Lockfile resolves dependency over plain HTTP",
                     category="lockfile_integrity", confidence=0.85)
        if isinstance(data, dict) and "packages" in data and not _P.LOCKFILE_INTEGRITY.search(text):
            scan.add("MEDIUM", rel_name, 0,
                     "Lockfile lacks obvious integrity/checksum fields",
                     category="lockfile_integrity", confidence=0.65)
        if _P.LOCKFILE_SCRIPT_HINT.search(text):
            scan.add("LOW", rel_name, 0,
                     "Lockfile indicates install/build scripts in dependencies",
                     category="lockfile_script", confidence=0.45)

    for rel_name in ("pnpm-lock.yaml", "yarn.lock", "bun.lockb"):
        f = repo_dir / rel_name
        if not f.exists() or not YSHIELD_LOCKFILE_SCAN:
            continue
        if is_text_file(f):
            text = read_manifest_text(scan, rel_name, f) or ""
            if _P.LOCKFILE_HTTP.search(text):
                scan.add("HIGH", rel_name, 0,
                         "Lockfile resolves dependency over plain HTTP",
                         category="lockfile_integrity", confidence=0.85)
            if _P.LOCKFILE_SCRIPT_HINT.search(text):
                scan.add("LOW", rel_name, 0,
                         "Lockfile indicates dependency install/build scripts",
                         category="lockfile_script", confidence=0.45)
        else:
            scan.add("LOW", rel_name, 0,
                     "Binary lockfile present; deep dependency integrity checks are limited",
                     category="lockfile_integrity", confidence=0.40)

    for rel_name in (".npmrc", ".yarnrc", ".yarnrc.yml"):
        f = repo_dir / rel_name
        if f.exists() and is_text_file(f):
            content = read_manifest_text(scan, rel_name, f) or ""
            if _P.NPM_REGISTRY_TAMPER.search(content) or _P.NPM_HOOK_CONFIG.search(content):
                scan.add("HIGH", rel_name, 0,
                         "Package-manager config changes registry/script execution behavior",
                         evidence=content[:240], category="package_manager_hook", confidence=0.85)

    for rel_name in ("Gemfile", "Gemfile.lock", "build.gradle", "settings.gradle", "pom.xml"):
        f = repo_dir / rel_name
        if not f.exists() or not is_text_file(f):
            continue
        content = read_manifest_text(scan, rel_name, f) or ""
        if _P.GEM_SOURCE_REMOTE.search(content):
            scan.add("MEDIUM", rel_name, 0,
                     "Ruby/Bundler source uses a non-default gem server",
                     evidence=safe_join_preview(_P.GEM_SOURCE_REMOTE.search(content).group(0)),
                     category="package_manager_hook", confidence=0.70)
        if _P.GRADLE_REPO_REMOTE.search(content) or _P.MAVEN_REPO_REMOTE.search(content):
            scan.add("MEDIUM", rel_name, 0,
                     "Java build config references a plain-HTTP artifact repository",
                     category="package_manager_hook", confidence=0.75)

    try:
        cp = git("ls-files", "-z", cwd=repo_dir, capture_output=True)
        tracked = [r for r in (cp.stdout or "").split("\0") if r]
    except Exception:
        tracked = []
    for rel in tracked[:500]:
        p = repo_dir / rel
        if not p.is_file():
            continue
        try:
            mode = p.stat().st_mode
        except OSError:
            continue
        if not (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
            continue
        ext = p.suffix.lower()
        if ext in {".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".awk"}:
            continue
        if rel in {"PKGBUILD", "configure"} or rel.endswith(".install"):
            continue
        if rel.startswith((".git", "pkg/", "src/")):
            continue
        sev = "HIGH" if ext in {".png", ".jpg", ".gif", ".txt", ".conf", ".dat"} else "MEDIUM"
        scan.add(sev, rel, 0,
                 "Tracked executable file has an unexpected extension/name — review for vendored payload",
                 category="vendored_executable", confidence=0.70)

def _tracked_or_walked_files(repo_dir: Path, limit: int = 2500) -> List[str]:
    try:
        cp = git("ls-files", "-z", cwd=repo_dir, capture_output=True)
        files = [r for r in (cp.stdout or "").split("\0") if r]
        if files:
            return files[:limit]
    except Exception:
        pass
    out: List[str] = []
    for p in repo_dir.rglob("*"):
        if len(out) >= limit:
            break
        if ".git" in p.parts or not p.is_file():
            continue
        try:
            out.append(str(p.relative_to(repo_dir)))
        except ValueError:
            continue
    return out

def _dangerous_script_text(text: str) -> bool:
    return _dangerous_script_reason(text) is not None

def _dangerous_script_reason(text: str) -> Optional[str]:
    probes = [text]
    decoded, changed = decode_bash_ansi_c_quotes(text)
    if changed:
        probes.append(decoded)
    for probe in probes:
        for pat, reason in (
            (_P.DANGEROUS_PIPE, "download piped to shell"),
            (_P.EVAL, "eval/dynamic shell execution"),
            (_P.SHELL_C, "shell -c execution"),
            (_P.DECODE, "decode-and-execute behavior"),
            (_P.DEV_TCP, "/dev/tcp socket use"),
            (_P.NC_EXEC, "netcat execution"),
            (_P.SOCAT_EXEC, "socat execution"),
            (_P.PASTE_SITE, "paste-site fetch"),
            (_P.NO_TLS_VERIFY, "TLS verification disabled"),
            (_P.PYTHON_ONE_LINER, "interpreter one-liner"),
            (_P.PROC_SUB_NET, "process-substitution network execution"),
            (_P.EVAL_NET_SUBSHELL, "eval of network-fetched command"),
            (_P.HTTP_POST_EXFIL, "HTTP POST/exfiltration pattern"),
            (_P.ENV_EXFIL, "environment exfiltration pattern"),
        ):
            if pat.search(probe):
                return reason
        if _P.FETCH.search(probe) and re.search(r"(?i)\b(sh|bash|zsh|dash|eval|exec|chmod|install)\b", probe):
            return "network fetch combined with execution/setup behavior"
    for blob in _P.B64_BLOB_RE.findall(text):
        padded = blob + "=" * ((-len(blob)) % 4)
        try:
            decoded_blob = base64.b64decode(padded).decode("utf-8", errors="replace")
        except Exception:
            continue
        if any(p.search(decoded_blob) for p in (
            _P.DANGEROUS_PIPE, _P.EVAL, _P.SHELL_C, _P.DEV_TCP,
            _P.NC_EXEC, _P.MINER, _P.SUDOERS, _P.PROC_SUB_NET,
        )):
            return "base64 blob decodes to shell payload"
    return None

_LOW_RISK_LIFECYCLE_RE = re.compile(
    r"(?i)^\s*(?:true|:|echo\b.*|node-gyp\s+rebuild(?:\s|$)|"
    r"cmake-js\s+(?:compile|build)(?:\s|$)|tsc(?:\s|$)|"
    r"vite\s+build(?:\s|$)|rollup\s+-c(?:\s|$))"
)

def _low_risk_lifecycle_cmd(cmd: str) -> bool:
    if not _LOW_RISK_LIFECYCLE_RE.search(cmd):
        return False
    return not any(p.search(cmd) for p in (
        _P.DANGEROUS_PIPE, _P.EVAL, _P.SHELL_C, _P.DECODE, _P.DEV_TCP,
        _P.NC_EXEC, _P.SOCAT_EXEC, _P.PASTE_SITE, _P.NO_TLS_VERIFY,
        _P.PYTHON_ONE_LINER, _P.PROC_SUB_NET, _P.EVAL_NET_SUBSHELL,
        _P.FETCH, _P.HTTP_POST_EXFIL, _P.ENV_EXFIL,
    ))

def scan_downstream_execution_surfaces(scan: PackageScan, repo_dir: Path) -> None:
    if not YSHIELD_DOWNSTREAM_SCRIPT_CRAWL:
        return
    pkgbuild = repo_dir / "PKGBUILD"
    try:
        pkg_text = read_text(pkgbuild) if pkgbuild.exists() else ""
    except Exception:
        pkg_text = ""
    invokes_cargo = bool(re.search(r"(?i)\bcargo\s+(build|test|check|install|run|bench)\b", pkg_text))
    invokes_node = bool(re.search(r"(?i)\b(npm|pnpm|yarn|bun)\s+(install|ci|rebuild|run|exec|dlx)\b", pkg_text))
    invokes_python = bool(re.search(r"(?i)\b(python3?|pip3?)\b[^#\n]*(setup\.py|build|install|wheel|pip\s+install)", pkg_text))
    invokes_make = bool(re.search(r"(?i)(^|[ \t;|&])make(?:[ \t]|$)|cmake\s+--build|ninja\b|meson\s+compile", pkg_text))

    for rel in _tracked_or_walked_files(repo_dir):
        path = repo_dir / rel
        if not path.is_file() or not _P.DOWNSTREAM_HOOK_FILE.search(rel):
            continue
        if not is_text_file(path):
            continue
        content = read_manifest_text(scan, rel, path) or ""
        if not content:
            continue
        suspicious_reason = _dangerous_script_reason(content)
        suspicious = suspicious_reason is not None

        if _P.BUILD_RS_FILE.search(rel):
            if suspicious:
                scan.add("HIGH", rel, 0,
                         f"Cargo build.rs contains {suspicious_reason}",
                         evidence=content[:260], category="downstream_build_hook", confidence=0.88)
            elif invokes_cargo and rel != "build.rs":
                scan.add("LOW", rel, 0,
                         "Nested Cargo build.rs will execute during cargo build; review hook contents",
                         category="downstream_build_hook", confidence=0.45)
            continue

        if _P.SETUP_PY_FILE.search(rel):
            if suspicious:
                scan.add("HIGH", rel, 0,
                         f"Python setup.py contains {suspicious_reason}",
                         evidence=content[:260], category="downstream_build_hook", confidence=0.86)
            elif invokes_python and rel != "setup.py":
                scan.add("LOW", rel, 0,
                         "Nested setup.py may execute during Python build/install",
                         category="downstream_build_hook", confidence=0.42)
            continue

        if rel.endswith("package.json") and invokes_node:
            data = load_json_manifest(scan, rel, path)
            scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
            if isinstance(scripts, dict):
                for name, cmd in scripts.items():
                    if not isinstance(cmd, str) or name not in {"preinstall", "install", "postinstall", "prepare", "prepublish", "postpack"}:
                        continue
                    cmd_reason = _dangerous_script_reason(cmd)
                    if cmd_reason:
                        scan.add("HIGH", rel, 0,
                                 f"Nested package.json lifecycle script '{name}' contains {cmd_reason}",
                                 evidence=cmd[:220], category="downstream_build_hook", confidence=0.84)
                    elif not _low_risk_lifecycle_cmd(cmd):
                        scan.add("LOW", rel, 0,
                                 f"Nested package.json lifecycle script '{name}' executes during package-manager install/build",
                                 evidence=cmd[:160], category="lockfile_script", confidence=0.38)
            continue

        if _P.MAKEFILE_FILE.search(rel) and invokes_make:
            if suspicious or _P.MAKEFILE_NET.search(content):
                scan.add("HIGH", rel, 0,
                         f"Makefile contains {suspicious_reason or 'network behavior'} reachable from make",
                         evidence=content[:260], category="downstream_build_hook", confidence=0.82)
            elif "/" in rel:
                scan.add("LOW", rel, 0,
                         "Nested Makefile present in a package that invokes make; review generated build hooks",
                         category="downstream_build_hook", confidence=0.35)
            continue

        if rel.endswith(("CMakeLists.txt", "meson.build")) and invokes_make:
            if _P.CMAKE_EXTERNAL.search(content) or _P.MESON_WRAP.search(content) or suspicious:
                scan.add("MEDIUM", rel, 0,
                         "Nested build-system file fetches or executes external content",
                         evidence=content[:260], category="downstream_build_hook", confidence=0.72)

def check_install_script_uniformity(scan: PackageScan, repo_dir: Path) -> None:
    if not YSHIELD_INSTALL_UNIFORM_SCAN:
        return
    referenced: Set[str] = set()
    pkgbuild = repo_dir / "PKGBUILD"
    try:
        pkg_text = read_text(pkgbuild) if pkgbuild.exists() else ""
    except Exception:
        pkg_text = ""
    for m in _P.INSTALL_ASSIGN.finditer(pkg_text):
        referenced.add(m.group(2))
    candidates = referenced | {rel for rel in _tracked_or_walked_files(repo_dir, limit=1000) if rel.endswith(".install")}
    for rel in sorted(candidates):
        path = repo_dir / rel
        if not path.exists():
            continue
        if not is_text_file(path):
            scan.add("HIGH", rel, 0,
                     ".install script is not readable text; lifecycle hook scan cannot verify behavior",
                     category="install_scriptlet", confidence=0.82)
            continue
        content = read_manifest_text(scan, rel, path) or ""
        for fn in INSTALL_SCRIPTLETS:
            if re.search(rf"(?m)^\s*(?:function\s+)?{re.escape(fn)}\s*\(\)\s*(?:\{{|$)", content):
                body_hint = "\n".join(
                    line for line in content.splitlines()
                    if re.search(r"(?i)(curl|wget|fetch|eval|bash|sh|source|/dev/tcp|base64|xxd)", line)
                )
                content_reason = _dangerous_script_reason(content)
                if body_hint or content_reason:
                    scan.add("HIGH", rel, 0,
                             f".install lifecycle hook '{fn}()' contains network/execution indicators",
                             evidence=(body_hint or content_reason or "")[:240],
                             category="install_scriptlet", confidence=0.84,
                             scope=fn, is_install_file=True)

# ─────────────────────────────────────────────────────────────────────────────
# Maintainer reputation (v8: maturity decay retained + improved)
# ─────────────────────────────────────────────────────────────────────────────

def check_maintainer_reputation(scan: PackageScan) -> None:
    if not YSHIELD_MAINTAINER_REP or not scan.maintainer or scan.maintainer == "null":
        return
    debug(f"Checking maintainer reputation for {scan.maintainer!r}")
    try:
        params = urllib.parse.urlencode([("by", "maintainer"), ("arg", scan.maintainer)])
        url    = f"{AUR_SEARCH}?{params}"
        req    = urllib.request.Request(url, headers={"User-Agent": "yay-shield/10"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        results = data.get("results", [])
    except Exception as exc:
        debug(f"Maintainer reputation check failed: {exc}")
        return
    if not results:
        return

    pkg_count  = len(results)
    flagged    = [r for r in results if r.get("OutOfDate") is not None]
    oldest_ts  = min((int(r.get("FirstSubmitted") or time.time()) for r in results), default=int(time.time()))
    age_days   = max(1, int((time.time() - oldest_ts) / 86400))

    if pkg_count < 3 and scan.first_submitted > 0:
        submit_age = max(0, int((time.time() - scan.first_submitted) / 86400))
        if submit_age < 30:
            scan.add("MEDIUM", "AUR metadata (maintainer)", 0,
                     f"Maintainer '{scan.maintainer}' has only {pkg_count} package(s) "
                     f"and this was submitted {submit_age} day(s) ago — limited track record",
                     category="new_maintainer", confidence=0.8)

    if pkg_count > 0 and len(flagged) / pkg_count > 0.5:
        scan.add("MEDIUM", "AUR metadata (maintainer)", 0,
                 f"Maintainer '{scan.maintainer}' has {len(flagged)}/{pkg_count} packages "
                 "flagged out-of-date — possibly inactive/abandoned",
                 category="maintainer_neglect", confidence=0.6)

    names = [r.get("Name", "") for r in results]
    if len(names) >= 3:
        similar_count = sum(
            1 for i, a in enumerate(names) for b in names[i+1:]
            if levenshtein(a, b) <= 2
        )
        if similar_count >= 4 and YSHIELD_MAINTAINER_MATURITY_DECAY:
            maturity_score = _sigmoid(age_days / max(1.0, pkg_count) - 1.0)
            adjusted_confidence = 0.7 * (1.0 - maturity_score * 0.98)
            if adjusted_confidence >= YSHIELD_TYPOSQUAT_FARM_MIN_CONF:
                scan.add("HIGH", "AUR metadata (maintainer)", 0,
                         f"Maintainer '{scan.maintainer}' has many very similar package names "
                         f"(possible typosquat farm; {similar_count} near-duplicate pairs among "
                         f"{pkg_count} packages; account age {age_days}d)",
                         category="typosquat", confidence=adjusted_confidence)
            else:
                debug(f"Typosquat farm suppressed: maturity={maturity_score:.3f}, conf={adjusted_confidence:.3f}")
        elif similar_count >= 4 and not YSHIELD_MAINTAINER_MATURITY_DECAY:
            scan.add("HIGH", "AUR metadata (maintainer)", 0,
                     f"Maintainer '{scan.maintainer}' has many very similar package names "
                     "(possible typosquat farm)",
                     category="typosquat", confidence=0.7)

    info(f"Maintainer '{scan.maintainer}': {pkg_count} pkg(s), acct age ~{age_days} days")

# ─────────────────────────────────────────────────────────────────────────────
# AUR dependency scanning
# ─────────────────────────────────────────────────────────────────────────────

def extract_pkgbuild_depends(pkgbuild_text: str) -> List[str]:
    deps: List[str] = []
    for m in re.finditer(r"(?ms)^\s*(?:make|check)?depends(?:\+?=)\(([^)]*)\)", pkgbuild_text):
        for entry in re.findall(r"['\"]?([A-Za-z0-9@_.+\-]+)(?:[><=][^'\"'\s,]+)?['\"]?", m.group(1)):
            entry = entry.strip()
            if entry:
                deps.append(entry)
    return list(set(deps))


def scan_aur_dependencies(scan: PackageScan, repo_dir: Path, depth: int = 1) -> None:
    if not YSHIELD_SCAN_AUR_DEPS or depth <= 0:
        return
    pkgbuild = repo_dir / "PKGBUILD"
    if not pkgbuild.exists():
        return
    try:
        text = read_text(pkgbuild)
    except Exception:
        return

    deps = extract_pkgbuild_depends(text)
    if not deps:
        return

    aur_deps: List[str] = []
    for dep in deps:
        if not is_official_repo_package(dep):
            try:
                if fetch_aur_info(dep).get("resultcount", 0) > 0:
                    aur_deps.append(dep)
            except Exception:
                pass

    if aur_deps:
        scan.add("LOW", "PKGBUILD (deps)", 0,
                 f"Package has {len(aur_deps)} AUR dependenc(ies): {', '.join(aur_deps[:8])}. "
                 "AUR dependencies expand the trust surface; verify each one.",
                 category="aur_dependency", confidence=0.9)

    if depth <= 1 or not aur_deps:
        return

    for dep in aur_deps[:3]:
        dep_repo = TEMP_DIR / f"dep_{dep}"
        info(f"Recursively scanning AUR dep: {dep}")
        if clone_aur_repo(dep, dep_repo, depth=2):
            dep_scan = PackageScan(pkg=dep, pkgbase=dep)
            scan_package_repo(dep_scan, dep_repo, _dep_scan=True)
            for f in dep_scan.findings:
                if meets_threshold(f.severity, "HIGH"):
                    scan.add(f.severity, f"[dep:{dep}]/{f.file}", f.line,
                             f"(via AUR dependency '{dep}') {f.reason}",
                             f.evidence, confidence=f.confidence * 0.8,
                             category=f"dep_{f.category}")
            shutil.rmtree(dep_repo, ignore_errors=True)

# ─────────────────────────────────────────────────────────────────────────────
# VCS source scanning
# ─────────────────────────────────────────────────────────────────────────────

def parse_pkgbuild_sources(pkgbuild_text: str) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    for m in re.finditer(r"(?ms)^\s*source(?:_\w+)?\+?=\(([^)]*)\)", pkgbuild_text):
        block = m.group(1)
        for entry in re.findall(r"""['"]?([^'"\s]+)['"]?""", block):
            entry = entry.strip().strip(",")
            if not entry:
                continue
            if "::" in entry:
                label, url = entry.split("::", 1)
            else:
                label, url = "", entry
            results.append((label, url))
    return results


def scan_vcs_sources(scan: PackageScan, repo_dir: Path) -> None:
    if not YSHIELD_SCAN_VCS_SOURCES:
        return
    pkgbuild = repo_dir / "PKGBUILD"
    if not pkgbuild.exists():
        return
    try:
        text = read_text(pkgbuild)
    except Exception:
        return

    entries = parse_pkgbuild_sources(text)
    vcs_dir = repo_dir / "_yshield_vcs"
    vcs_dir.mkdir(exist_ok=True)
    scanned = 0
    dfa = DataFlowAnalyzer()
    try:
        for label, url in entries:
            if scanned >= YSHIELD_MAX_VCS_SOURCES:
                break
            clone_url = url
            if clone_url.lower().startswith("git+"):
                clone_url = clone_url[4:]
            clone_url = clone_url.split("#")[0]
            if not re.match(r"(?i)^https?://|^git://|^ssh://", clone_url):
                continue
            dest = vcs_dir / f"vcs_src_{scanned}"
            info(f"VCS scan: cloning {clone_url} (depth=1) …")
            cp = run(["git", "clone", "--depth", "1", "--quiet", clone_url, str(dest)],
                     capture_output=True, check=False, timeout=120)
            if cp.returncode != 0:
                continue
            scanned += 1
            ls_cp = git("ls-files", "-z", cwd=dest, capture_output=True)
            for rel in (ls_cp.stdout or "").split("\0"):
                if not rel:
                    continue
                p = dest / rel
                if p.is_file() and is_text_file(p) and (is_relevant_file(rel) or has_shebang(p)):
                    scan_file_with_data_flow(scan, f"[vcs-source:{label or clone_url[:40]}]/{rel}", p, dfa)
    finally:
        shutil.rmtree(vcs_dir, ignore_errors=True)

# ─────────────────────────────────────────────────────────────────────────────
# File scanner with data-flow (v7: array context + SRCINFO routing)
# ─────────────────────────────────────────────────────────────────────────────

def scan_file_with_data_flow(scan: PackageScan, rel: str, path: Path,
                              analyzer: Optional[DataFlowAnalyzer] = None) -> None:
    try:
        text = read_text(path)
    except Exception:
        return
    lines = preprocess_text(text)
    is_install = rel.endswith(".install")
    is_pkgbuild = (rel == "PKGBUILD" or rel == "PKGBUILD[diff]")

    if is_pkgbuild or is_install:
        scopes = compute_scopes(lines)
    else:
        scopes = ["external"] * len(lines)

    # v7: compute array contexts (only meaningful for PKGBUILD)
    array_ctxs = compute_array_contexts(lines) if (is_pkgbuild and YSHIELD_ARRAY_CTX) else [ACTX_EXECUTABLE] * len(lines)

    var_map = scan.var_map if (is_pkgbuild and YSHIELD_SEMANTIC_VARS) else {}

    # Data-flow analysis (skip declarative-array lines)
    if YSHIELD_DATA_FLOW and analyzer is not None:
        for i, raw in enumerate(lines, 1):
            if i - 1 < len(array_ctxs) and array_ctxs[i - 1] == ACTX_DECLARATIVE:
                continue
            hits = analyzer.process_line(i, raw)
            for taint_type, sink_label, sev, chain in hits:
                chain_str = " → ".join(chain)
                scope = scopes[i - 1] if i - 1 < len(scopes) else "global"
                scan.add(sev, rel, i,
                         f"Taint-flow: {taint_type} source reaches '{sink_label}' sink "
                         f"— chain: {chain_str[:200]}",
                         evidence=raw, confidence=0.95,
                         category="taint_flow", scope=scope, is_install_file=is_install)
        if YSHIELD_STRING_RECONSTRUCT:
            for line_no, desc in analyzer.check_string_reconstruction(lines):
                scope = scopes[line_no - 1] if line_no - 1 < len(scopes) else "global"
                scan.add("HIGH", rel, line_no,
                         f"String reconstruction (obfuscation): {desc}",
                         confidence=0.85, category="string_reconstruct",
                         scope=scope, is_install_file=is_install)

    # Heredoc scanning
    if YSHIELD_HEREDOC_SCAN:
        heredocs = extract_heredocs(lines)
        for delim, body in heredocs:
            body_start = 0
            for i, l in enumerate(lines):
                if delim in l:
                    body_start = i + 2
                    break
            scan_heredoc_body(scan, rel, body_start, body,
                              analyzer if YSHIELD_DATA_FLOW else None)

    # Regular line-by-line scan
    for i, raw in enumerate(lines, 1):
        effective = effective_shell_line(raw)
        if _P.COMMENT.match(effective) or _P.BLANK.match(effective):
            continue
        scope    = scopes[i - 1] if i - 1 < len(scopes) else "global"
        actx     = array_ctxs[i - 1] if i - 1 < len(array_ctxs) else ACTX_EXECUTABLE
        scan_line(scan, rel, i, raw, scope=scope, is_install_file=is_install,
                  var_map=var_map, all_lines=lines, array_ctx=actx)

    run_correlation_pass(scan, rel, lines, scopes, array_ctxs, is_install)
    run_dropper_path_tracking(scan, rel, lines, scopes, array_ctxs, is_install)

# ─────────────────────────────────────────────────────────────────────────────
# Package repo scanner (orchestrator)
# ─────────────────────────────────────────────────────────────────────────────

# Extensions for service/desktop scanning
_SERVICE_EXTS = {".service", ".timer", ".socket", ".target", ".path"}
_DESKTOP_EXTS = {".desktop"}

def scan_package_repo(scan: PackageScan, repo_dir: Path, _dep_scan: bool = False) -> None:
    scan_pkgbuild_structure(scan, repo_dir)
    check_git_submodules(scan, repo_dir)
    scan_git_hooks(scan, repo_dir)
    inspect_git_history(scan, repo_dir)
    if not _dep_scan:
        check_pkgbuild_changed(scan, scan.pkg, repo_dir)
        run_diff_aware_scan(scan, repo_dir)
    check_srcinfo_consistency(scan, repo_dir)
    check_source_integrity_deep(scan, repo_dir)
    scan_symlink_and_archive_risks(scan, repo_dir)
    scan_build_system_files(scan, repo_dir)
    scan_manifest_files(scan, repo_dir)
    scan_downstream_execution_surfaces(scan, repo_dir)
    check_install_script_uniformity(scan, repo_dir)
    if not _dep_scan:
        scan_aur_dependencies(scan, repo_dir, depth=YSHIELD_AUR_DEP_DEPTH)

    if YSHIELD_SANDBOX and not _dep_scan:
        sandbox = SandboxRunner(repo_dir)
        if sandbox.available():
            info("Running sandbox syntax check …")
            sandbox.run_syntax_check(scan)
        else:
            debug("bwrap not available; sandbox skipped")

    dfa        = DataFlowAnalyzer() if YSHIELD_DATA_FLOW else None
    cga        = CallGraphAnalyzer() if YSHIELD_CALL_GRAPH else None
    binspector = BinaryInspector(scan)

    cp  = git("ls-files", "-z", cwd=repo_dir, capture_output=True)
    raw = cp.stdout or ""
    all_files = [r for r in raw.split("\0") if r]

    def _process_file(rel: str) -> None:
        path = repo_dir / rel
        if not path.is_file():
            return
        ext = Path(rel).suffix.lower()

        # Route service/desktop files to dedicated scanners.
        if YSHIELD_SERVICE_SCAN and (ext in _SERVICE_EXTS or ext in _DESKTOP_EXTS):
            scan_service_file(scan, rel, path)
            return

        if not is_text_file(path):
            binspector.inspect(rel, path)
            return
        if is_relevant_file(rel) or has_shebang(path):
            debug(f"Scanning: {rel}")
            if cga and (rel == "PKGBUILD" or rel.endswith(".install")):
                try:
                    t  = read_text(path)
                    ls = preprocess_text(t)
                    cga.feed_lines(ls)
                except Exception:
                    pass
            scan_file_with_data_flow(scan, rel, path, dfa)

    if YSHIELD_FILE_WORKERS > 1 and len(all_files) > 4:
        with concurrent.futures.ThreadPoolExecutor(max_workers=YSHIELD_FILE_WORKERS) as ex:
            futures = [ex.submit(_process_file, rel) for rel in all_files]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    fut.result()
                except Exception as exc:
                    debug(f"File scan error: {exc}")
    else:
        for rel in all_files:
            _process_file(rel)

    if cga:
        for func, chain, evidence in cga.get_suspicious_chains():
            scan.add("MEDIUM", "PKGBUILD (call-graph)", 0,
                     f"Helper function '{func}()' transitively reaches dangerous execution sinks "
                     f"(chain: {func} → {chain})",
                     evidence="\n".join(evidence), confidence=0.75,
                     category="call_graph")

    if not _dep_scan:
        if YSHIELD_SCAN_VCS_SOURCES:
            scan_vcs_sources(scan, repo_dir)

# ─────────────────────────────────────────────────────────────────────────────
# Argument handling
# ─────────────────────────────────────────────────────────────────────────────

ARG_TAKING_FLAGS = {
    "--config","--cachedir","--gpgdir","--hookdir","--logfile","--dbpath",
    "--root","--color","--ask","--print-format","-b","--builddir",
    "--answerclean","--answerdiff","--answeredit","--answerupgrade",
    "--mflags","--gpgflags","--sudoflags","--editor","--editorflags",
    "--pacman","--git","--gitflags",
}

_INFO_ONLY_SYNC_RE = re.compile(r"^-S[isl]+$")

def has_install_sync_operation(argv: List[str]) -> bool:
    for arg in argv:
        if arg in {"-S", "--sync"}:
            return True
        if arg.startswith("-") and not arg.startswith("--") and "S" in arg[1:]:
            if _INFO_ONLY_SYNC_RE.match(arg):
                continue
            return True
    return False

def is_yay_passthrough_mode(argv: List[str]) -> bool:
    if has_install_sync_operation(argv):
        return False
    passthrough_flags = {
        "-Ss","--search","-Si","--info","-Qs","--query","-Q","-Qu","-Qe",
        "-Qo","-Qm","-Qn","-Qd","-Ql","-Qk","--help","-h","--version","-V",
        "-P","--show",
    }
    for arg in argv:
        if arg in passthrough_flags or arg.startswith(("-Ss","-Si","-Qs","-Q","--show")):
            return True
    return False

def extract_sync_targets(argv: List[str]) -> List[str]:
    targets: List[str] = []
    sync_seen = False
    skip_next = False
    for arg in argv:
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            continue
        if arg in ARG_TAKING_FLAGS and "=" not in arg:
            skip_next = True
            continue
        if arg in {"-S","--sync"}:
            sync_seen = True
            continue
        if arg.startswith("-S") and arg != "-S":
            sync_seen = True
            continue
        if arg.startswith("-"):
            continue
        if sync_seen:
            targets.append(arg)
    return targets

def rewrite_sync_targets(argv: List[str], replacements: Dict[str, str]) -> List[str]:
    if not replacements:
        return list(argv)
    rewritten: List[str] = []
    sync_seen = False
    skip_next = False
    for arg in argv:
        if skip_next:
            rewritten.append(arg)
            skip_next = False
            continue
        if arg == "--":
            rewritten.append(arg)
            continue
        if arg in ARG_TAKING_FLAGS and "=" not in arg:
            rewritten.append(arg)
            skip_next = True
            continue
        if arg in {"-S", "--sync"}:
            sync_seen = True
            rewritten.append(arg)
            continue
        if arg.startswith("-S") and arg != "-S":
            sync_seen = True
            rewritten.append(arg)
            continue
        if arg.startswith("-"):
            rewritten.append(arg)
            continue
        rewritten.append(replacements.get(arg, arg) if sync_seen else arg)
    return rewritten

def offer_official_repo_alternatives(targets: List[str],
                                     yay_argv: List[str]) -> Tuple[List[str], List[str]]:
    if not YSHIELD_OFFICIAL_ALT_PROMPT:
        return yay_argv, targets
    replacements: Dict[str, str] = {}
    for target in targets:
        alt = official_alternative_for(target)
        if not alt or alt == package_atom_name(target):
            continue
        print(
            f"\n{C['yellow']}Official repository alternative available:{C['nc']} "
            f"{C['bold']}{package_atom_name(target)}{C['nc']} → "
            f"{C['green']}{alt}{C['nc']}"
        )
        print(
            "The AUR variant is maintained outside the official repos. "
            "The official package is usually the safer default when it provides the same software."
        )
        if prompt_yes_no(f"Install official package '{alt}' instead? [y/N]: "):
            replacements[target] = alt
    if not replacements:
        return yay_argv, targets
    rewritten_argv = rewrite_sync_targets(yay_argv, replacements)
    rewritten_targets = [replacements.get(t, t) for t in targets]
    return rewritten_argv, rewritten_targets

# ─────────────────────────────────────────────────────────────────────────────
# Package scan (top-level)
# ─────────────────────────────────────────────────────────────────────────────

def scan_package(pkg: str) -> Tuple["PackageScan", bool, str]:
    scan = PackageScan(pkg=pkg, pkgbase=pkg)
    print(f"\n{C['bold']}━━━ 📦 Package: {pkg}{C['nc']}")

    if YSHIELD_HOMOGLYPH:
        if has_homoglyphs(pkg):
            normalized = normalize_homoglyphs(pkg)
            scan.add("CRITICAL", "package name", 0,
                     f"Package name contains confusable Unicode chars (normalises to '{normalized}')",
                     category="homoglyph")
        rlo = check_rlo_attack(pkg)
        if rlo:
            scan.add("CRITICAL", "package name", 0, rlo, category="rlo_attack")

    if is_allowlisted_package(pkg):
        print(f"   {C['green']}[ALLOWLISTED]{C['nc']} Skipping scan.\n")
        return scan, True, ""

    if YSHIELD_ALLOW_OFFICIAL and is_official_repo_package(pkg):
        print(f"   {C['green']}✓ Official repo package — skipping AUR inspection.{C['nc']}\n")
        return scan, True, ""

    try:
        rpc = fetch_aur_info(pkg)
    except Exception as exc:
        error(f"Failed to query AUR RPC for {pkg!r}: {exc}")
        return scan, False, ""

    result               = rpc["results"][0]
    scan.pkgbase         = result.get("PackageBase") or pkg
    scan.maintainer      = result.get("Maintainer") or ""
    scan.last_modified   = int(result.get("LastModified") or 0)
    scan.first_submitted = int(result.get("FirstSubmitted") or 0)
    scan.votes           = int(result.get("NumVotes") or 0)
    try:
        scan.popularity = float(result.get("Popularity") or 0.0)
    except ValueError:
        scan.popularity = 0.0

    if not scan.maintainer or scan.maintainer == "null":
        print(f"   {C['yellow']}⚠ Maintainer: ORPHANED{C['nc']}")
        scan.add("HIGH", "AUR metadata", 0, "Package is orphaned (no active maintainer)",
                 category="orphaned")
    elif is_trusted_maintainer(scan.maintainer):
        print(f"   {C['green']}✓ Maintainer: {scan.maintainer} (trusted){C['nc']}")
    else:
        print(f"   {C['cyan']}Maintainer:{C['nc']} {scan.maintainer}")

    print(
        f"   {C['cyan']}Base:{C['nc']} {scan.pkgbase:<30}  "
        f"{C['cyan']}Votes:{C['nc']} {scan.votes:<6}  "
        f"{C['cyan']}Popularity:{C['nc']} {scan.popularity}"
    )

    if scan.last_modified > 0:
        age_days = max(0, int((time.time() - scan.last_modified) / 86400))
        if age_days < 7:
            print(f"   {C['yellow']}Last modified: {age_days} days ago  ⚠ RECENT CHANGE{C['nc']}")
        else:
            print(f"   {C['green']}Last modified: {age_days} days ago{C['nc']}")

    if scan.votes < 3:
        scan.add("MEDIUM", "AUR metadata", 0,
                 f"Package has very few votes ({scan.votes}) — minimal community scrutiny",
                 category="low_votes", confidence=0.72)
    elif scan.votes < 10:
        scan.add("LOW", "AUR metadata", 0,
                 f"Package has fewer than 10 votes ({scan.votes}) — limited community scrutiny",
                 category="low_votes", confidence=0.40)

    if scan.first_submitted > 0:
        submit_age_days = max(0, int((time.time() - scan.first_submitted) / 86400))
        if submit_age_days < YSHIELD_NEW_PACKAGE_DAYS:
            scan.add("MEDIUM", "AUR metadata", 0,
                     f"Package first submitted {submit_age_days} day(s) ago — minimal community vetting",
                     category="new_package")
            print(f"   {C['yellow']}First submitted: {submit_age_days} day(s) ago  ⚠ NEW PACKAGE{C['nc']}")

    if YSHIELD_CHECK_TYPOSQUAT:
        for popular, dist, method in check_typosquat(pkg):
            sev = "HIGH" if dist == 1 else "MEDIUM"
            if is_official_repo_package(popular):
                sev = escalate_severity(sev)
            scan.add(sev, "AUR metadata", 0,
                     f"Package name '{pkg}' closely resembles '{popular}' "
                     f"({method}, distance {dist}) — possible typosquat",
                     category="typosquat")

    check_maintainer_reputation(scan)

    repo_dir = TEMP_DIR / scan.pkgbase
    print(f"   {C['cyan']}Cloning AUR repo (depth={YSHIELD_CLONE_DEPTH})…{C['nc']}")
    if not clone_aur_repo(scan.pkgbase, repo_dir):
        error(f"Unable to clone AUR repo {scan.pkgbase!r}.")
        return scan, False, ""

    scanned_commit, _ = snapshot_repo(repo_dir)
    scan.scan_commit   = scanned_commit

    t0 = time.monotonic()
    print(f"   {C['cyan']}Scanning…{C['nc']}")
    scan_package_repo(scan, repo_dir)
    elapsed = time.monotonic() - t0

    render_findings(scan)

    label = normalize_severity_label(scan)
    color = {"CRITICAL": C["red"], "HIGH": C["magenta"],
             "MEDIUM": C["yellow"], "LOW": C["blue"], "CLEAN": C["green"]}[label]
    print(
        f"\n   {color}[{label}]{C['nc']} "
        f"Summary: {scan.total} findings "
        f"({scan.critical} critical / {scan.high} high / "
        f"{scan.medium} medium / {scan.low} low)  "
        f"risk score={scan.score:.1f}  {C['dim']}[{elapsed:.1f}s]{C['nc']}"
    )
    if scan.suppressed:
        print(
            f"   {C['dim']}({scan.suppressed} finding(s) below "
            f"YSHIELD_MIN_SEVERITY={YSHIELD_MIN_SEVERITY} not shown){C['nc']}"
        )
    if scan.total == 0:
        print(f"   {C['green']}✓ No suspicious patterns found.{C['nc']}")

    return scan, True, scanned_commit

# ─────────────────────────────────────────────────────────────────────────────
# Findings rendering
# ─────────────────────────────────────────────────────────────────────────────

def render_findings(scan: PackageScan) -> None:
    if not scan.findings:
        return
    groups: Dict[Tuple[str, str, str], List[Finding]] = defaultdict(list)
    order:  List[Tuple[str, str, str]] = []
    seen_keys: Set[Tuple[str, str, str]] = set()

    for f in scan.findings:
        if not meets_threshold(f.severity, YSHIELD_MIN_SEVERITY):
            continue
        key = (f.severity, f.category, f.reason[:100])
        groups[key].append(f)
        if key not in seen_keys:
            seen_keys.add(key)
            order.append(key)

    if not order:
        return
    order.sort(key=lambda k: -severity_rank(k[0]))
    print()
    for sev, _cat, reason in order:
        items  = groups[(sev, _cat, reason)]
        header = colorize_sev(sev, f"⚠️  [{sev}]".ljust(11))
        mitre  = items[0].mitre
        mitre_str = f"  {C['dim']}[MITRE {mitre}]{C['nc']}" if mitre else ""
        if len(items) == 1:
            f0 = items[0]
            print(f"{header} {f0.file:<25} :{f0.line} {reason}{mitre_str}")
            preview = safe_join_preview(f0.evidence)
            if preview:
                print(f"        {C['dim']}{preview}{C['nc']}")
        else:
            print(f"{header} {reason}  {C['dim']}({len(items)} occurrences){C['nc']}{mitre_str}")
            for f0 in items[:YSHIELD_MAX_SIMILAR_SHOWN]:
                preview = safe_join_preview(f0.evidence)
                loc     = f"{f0.file}:{f0.line}"
                if preview:
                    print(f"        {loc:<32} {C['dim']}{preview}{C['nc']}")
                else:
                    print(f"        {loc}")
            extra = len(items) - YSHIELD_MAX_SIMILAR_SHOWN
            if extra > 0:
                print(f"        {C['dim']}… and {extra} more (see JSON report){C['nc']}")

# ─────────────────────────────────────────────────────────────────────────────
# JSON report
# ─────────────────────────────────────────────────────────────────────────────

def write_json_report(scans: List[PackageScan]) -> None:
    data = {
        "tool": "yay-shield",
        "version": 12,
        "generated": int(time.time()),
        "config": {
            "sandbox":                    YSHIELD_SANDBOX,
            "data_flow":                  YSHIELD_DATA_FLOW,
            "call_graph":                 YSHIELD_CALL_GRAPH,
            "shellcheck":                 YSHIELD_SHELLCHECK,
            "binary_strings":             YSHIELD_BINARY_STRINGS,
            "homoglyph":                  YSHIELD_HOMOGLYPH,
            "semantic_vars":              YSHIELD_SEMANTIC_VARS,
            "heredoc_scan":               YSHIELD_HEREDOC_SCAN,
            "diff_aware":                 YSHIELD_DIFF_AWARE,
            "gpg_verify":                 YSHIELD_GPG_VERIFY,
            "array_ctx":                  YSHIELD_ARRAY_CTX,
            "src_crossref":               YSHIELD_SRC_CROSSREF,
            "service_scan":               YSHIELD_SERVICE_SCAN,
            "active_b64_decode":          YSHIELD_ACTIVE_B64_DECODE,
            "dep_confusion":              YSHIELD_DEP_CONFUSION,
            "maintainer_maturity_decay":  YSHIELD_MAINTAINER_MATURITY_DECAY,
            "trap_analysis":              YSHIELD_TRAP_ANALYSIS,
            "glob_obfusc":                YSHIELD_GLOB_OBFUSC,
            "indirect_var":               YSHIELD_INDIRECT_VAR,
            "build_system_deep":          YSHIELD_BUILD_SYSTEM_DEEP,
            "git_hook_scan":              YSHIELD_GIT_HOOK_SCAN,
            "arith_charcode":             YSHIELD_ARITH_CHARCODE,
            "proc_sub_net":               YSHIELD_PROC_SUB_NET,
            "shell_opt_analysis":         YSHIELD_SHELL_OPT_ANALYSIS,
            "keyboard_typosquat":         YSHIELD_KEYBOARD_TYPOSQUAT,
            "strip_inline_comments":      YSHIELD_STRIP_INLINE_COMMENTS,
            "dropper_path_tracking":      YSHIELD_DROPPER_PATH_TRACKING,
            "verify_yay_binary":          YSHIELD_VERIFY_YAY_BINARY,
            "sanitize_env":               YSHIELD_SANITIZE_ENV,
            "manifest_deep":              YSHIELD_MANIFEST_DEEP,
            "fail_closed_manifests":       YSHIELD_FAIL_CLOSED_MANIFESTS,
            "source_integrity_deep":       YSHIELD_SOURCE_INTEGRITY_DEEP,
            "symlink_scan":                YSHIELD_SYMLINK_SCAN,
            "archive_risk_scan":           YSHIELD_ARCHIVE_RISK_SCAN,
            "lockfile_scan":               YSHIELD_LOCKFILE_SCAN,
            "handoff_arg_guard":           YSHIELD_HANDOFF_ARG_GUARD,
            "bash_eager_decode":            YSHIELD_BASH_EAGER_DECODE,
            "param_transform_track":        YSHIELD_PARAM_TRANSFORM_TRACK,
            "array_index_track":            YSHIELD_ARRAY_INDEX_TRACK,
            "file_taint_track":             YSHIELD_FILE_TAINT_TRACK,
            "downstream_script_crawl":      YSHIELD_DOWNSTREAM_SCRIPT_CRAWL,
            "install_uniform_scan":         YSHIELD_INSTALL_UNIFORM_SCAN,
            "official_alt_prompt":          YSHIELD_OFFICIAL_ALT_PROMPT,
            "weak_advisories":              YSHIELD_WEAK_ADVISORIES,
        },
        "summary": {
            "total_findings": sum(s.total      for s in scans),
            "critical":       sum(s.critical   for s in scans),
            "high":           sum(s.high       for s in scans),
            "medium":         sum(s.medium     for s in scans),
            "low":            sum(s.low        for s in scans),
            "suppressed":     sum(s.suppressed for s in scans),
        },
        "packages": [
            {
                "pkg":              s.pkg,
                "pkgbase":          s.pkgbase,
                "maintainer":       s.maintainer,
                "votes":            s.votes,
                "popularity":       s.popularity,
                "last_modified":    s.last_modified,
                "first_submitted":  s.first_submitted,
                "scan_commit":      s.scan_commit,
                "score":            round(s.score, 2),
                "highest_severity": s.highest_severity,
                "build_systems":    sorted(s.build_systems),
                "pkg_type_hints":   sorted(s.pkg_type_hints),
                "findings":         [f.to_json() for f in s.findings],
            }
            for s in scans
        ],
    }
    YSHIELD_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    YSHIELD_REPORT_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    info(f"JSON report written to: {YSHIELD_REPORT_PATH}")

# ─────────────────────────────────────────────────────────────────────────────
# yay handoff hardening
# ─────────────────────────────────────────────────────────────────────────────

_DANGEROUS_ENV_KEYS: FrozenSet[str] = frozenset({
    "BASH_ENV", "ENV", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "PYTHONPATH",
    "PYTHONSTARTUP", "PERL5OPT", "RUBYOPT", "NODE_OPTIONS",
    "GCONV_PATH", "SHELLOPTS", "BASH_XTRACEFD",
})

def _path_has_unsafe_permissions(path: Path) -> Optional[str]:
    try:
        st = path.stat()
    except OSError as exc:
        return f"cannot stat {path}: {exc}"
    if st.st_mode & stat.S_IWOTH:
        return f"{path} is world-writable"
    if st.st_mode & stat.S_IWGRP:
        return f"{path} is group-writable"
    return None

def resolve_yay_binary() -> Optional[str]:
    yay = shutil.which("yay")
    if not yay:
        error("yay executable not found in PATH.")
        return None
    path = Path(yay).resolve()
    if not YSHIELD_VERIFY_YAY_BINARY:
        return str(path)
    if not path.is_file():
        error(f"Resolved yay path is not a regular file: {path}")
        return None
    if os.access(str(path), os.W_OK):
        error(f"Resolved yay binary is writable by the current user: {path}")
        error("Refusing handoff. Set YSHIELD_VERIFY_YAY_BINARY=0 only if you intentionally trust it.")
        return None
    unsafe = _path_has_unsafe_permissions(path)
    if unsafe:
        error(f"Unsafe yay binary permissions: {unsafe}")
        return None
    cwd = Path.cwd().resolve()
    try:
        if path.parent == cwd or cwd in path.parents:
            error(f"Resolved yay is inside the current working tree: {path}")
            return None
    except RuntimeError:
        pass
    for parent in [path.parent, *path.parents]:
        unsafe_parent = _path_has_unsafe_permissions(parent)
        if unsafe_parent:
            error(f"Unsafe directory in yay path: {unsafe_parent}")
            return None
        if parent.parent == parent:
            break
    return str(path)

def sanitized_yay_env() -> Dict[str, str]:
    if not YSHIELD_SANITIZE_ENV:
        return dict(os.environ)
    env = dict(os.environ)
    removed = [k for k in _DANGEROUS_ENV_KEYS if k in env]
    for key in removed:
        env.pop(key, None)
    if removed:
        debug(f"Sanitized env keys before yay handoff: {', '.join(sorted(removed))}")
    return env

def _looks_like_shell_injection(value: str) -> bool:
    return bool(re.search(r"(?i)(`|\$\(|;|\|\||&&|\bLD_PRELOAD=|\bBASH_ENV=|\bENV=|\bcurl\b|\bwget\b)", value))

def _handoff_binary_is_unsafe(value: str) -> Optional[str]:
    try:
        words = shlex.split(value)
    except ValueError:
        return "cannot safely parse command value"
    if not words:
        return "empty command value"
    exe = words[0]
    resolved = shutil.which(exe) if "/" not in exe else exe
    if not resolved:
        return f"command not found: {exe}"
    path = Path(resolved).resolve()
    cwd = Path.cwd().resolve()
    temp_roots = [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"), TEMP_DIR]
    if any(path == root or root in path.parents for root in temp_roots):
        return f"{path} is in a temporary/world-writable location"
    try:
        if path.parent == cwd or cwd in path.parents:
            return f"{path} is inside the current working tree"
    except RuntimeError:
        pass
    if os.access(str(path), os.W_OK):
        return f"{path} is writable by the current user"
    unsafe = _path_has_unsafe_permissions(path)
    if unsafe:
        return unsafe
    for parent in [path.parent, *path.parents]:
        if parent.parent == parent:
            break
        unsafe_parent = _path_has_unsafe_permissions(parent)
        if unsafe_parent:
            return unsafe_parent
    return None

def validate_handoff_args(yay_argv: List[str]) -> bool:
    if not YSHIELD_HANDOFF_ARG_GUARD:
        return True
    guarded_command_flags = {"--pacman", "--git", "--editor"}
    guarded_text_flags = {"--mflags", "--gpgflags", "--sudoflags", "--editorflags", "--gitflags"}
    i = 0
    ok = True
    while i < len(yay_argv):
        arg = yay_argv[i]
        key = arg.split("=", 1)[0]
        value: Optional[str] = None
        if "=" in arg and key in guarded_command_flags | guarded_text_flags:
            value = arg.split("=", 1)[1]
        elif key in guarded_command_flags | guarded_text_flags and i + 1 < len(yay_argv):
            value = yay_argv[i + 1]
            i += 1

        if value is not None:
            if key in guarded_command_flags:
                reason = _handoff_binary_is_unsafe(value)
                if reason:
                    error(f"Unsafe yay handoff argument {key}={value!r}: {reason}")
                    ok = False
            if key in guarded_text_flags and _looks_like_shell_injection(value):
                error(f"Unsafe yay handoff argument {key} contains shell/env injection syntax.")
                ok = False

        if key in {"--hookdir", "--dbpath", "--root"}:
            error(f"Refusing high-risk pacman path override during guarded install: {key}")
            ok = False
        i += 1
    if not ok:
        error("Refusing handoff. Set YSHIELD_HANDOFF_ARG_GUARD=0 only if you intentionally trust these arguments.")
    return ok

def call_yay(yay_argv: List[str]) -> int:
    if not validate_handoff_args(yay_argv):
        return 1
    yay_path = resolve_yay_binary()
    if not yay_path:
        return 1
    return subprocess.call([yay_path, *yay_argv], env=sanitized_yay_env())

# ─────────────────────────────────────────────────────────────────────────────
# Summary, decision, TOCTOU
# ─────────────────────────────────────────────────────────────────────────────

def summarize_and_decide(
    scans:      List[PackageScan],
    commit_map: Dict[str, str],
    yay_argv:   List[str],
) -> int:
    total     = sum(s.total      for s in scans)
    critical  = sum(s.critical   for s in scans)
    high      = sum(s.high       for s in scans)
    medium    = sum(s.medium     for s in scans)
    low       = sum(s.low        for s in scans)
    suppressed= sum(s.suppressed for s in scans)
    overall   = sum(s.score      for s in scans)

    print(f"\n{C['bold']}{C['blue']}━━━ Overall Summary ━━━{C['nc']}")
    print(
        f"{C['bold']}Total findings:{C['nc']} {total}  "
        f"({C['red']}{critical} critical{C['nc']} / "
        f"{C['magenta']}{high} high{C['nc']} / "
        f"{C['yellow']}{medium} medium{C['nc']} / "
        f"{C['blue']}{low} low{C['nc']})  "
        f"risk score={overall:.1f}"
    )
    if suppressed:
        print(f"{C['dim']}({suppressed} below YSHIELD_MIN_SEVERITY={YSHIELD_MIN_SEVERITY} omitted){C['nc']}")

    if YSHIELD_REPORT_JSON:
        write_json_report(scans)

    if total == 0:
        print(f"{C['green']}✓ No suspicious findings. Performing TOCTOU check…{C['nc']}")
        if not _toctou_all(scans, commit_map):
            return 1
        return call_yay(yay_argv)

    highest = "CLEAN"
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
        if any(s.highest_severity == sev for s in scans):
            highest = sev
            break

    if not meets_threshold(highest, YSHIELD_BLOCK_MIN_SEVERITY):
        print(f"{C['green']}Findings below blocking threshold ({YSHIELD_BLOCK_MIN_SEVERITY}). "
              f"Performing TOCTOU check…{C['nc']}")
        if not _toctou_all(scans, commit_map):
            return 1
        return call_yay(yay_argv)

    if YSHIELD_FORCE:
        warn("YSHIELD_FORCE=1 — proceeding despite findings.")
        if not _toctou_all(scans, commit_map):
            if not prompt_yes_no(f"{C['red']}Repo changed AND YSHIELD_FORCE=1. Still proceed? [y/N]: {C['nc']}"):
                return 1
        return call_yay(yay_argv)

    if prompt_yes_no(
        f"{C['yellow']}Suspicious findings detected. "
        f"Proceed with installation at your own risk? [y/N]: {C['nc']}"
    ):
        print(f"{C['cyan']}Performing TOCTOU verification before handing off to yay…{C['nc']}")
        if not _toctou_all(scans, commit_map):
            print(f"{C['red']}⛔  Install blocked: AUR repo(s) changed since scan.{C['nc']}")
            if not prompt_yes_no(
                f"{C['red']}Force proceed anyway? [y/N]: {C['nc']}"
            ):
                print(f"{C['green']}✓ Installation aborted. Your system is safe.{C['nc']}")
                return 1
        print(f"{C['red']}⚠ Proceeding at your own risk…{C['nc']}")
        return call_yay(yay_argv)

    print(f"{C['green']}✓ Installation aborted. Your system is safe.{C['nc']}")
    return 1


def _toctou_all(scans: List[PackageScan], commit_map: Dict[str, str]) -> bool:
    if not YSHIELD_TOCTOU_CHECK:
        return True
    all_ok = True
    for s in scans:
        saved = commit_map.get(s.pkg, "")
        if saved:
            ok = verify_toctou(s.pkgbase, saved, s)
            if not ok:
                all_ok = False
    return all_ok

# ─────────────────────────────────────────────────────────────────────────────
# Usage
# ─────────────────────────────────────────────────────────────────────────────

def usage() -> None:
    print(f"""{C['bold']}yay-shield{C['nc']} v12

Usage: yay-shield [yay arguments...]

A multi-layer security scanner and wrapper around yay for AUR packages.

Environment variables (subset — see source for full list):
  YSHIELD_FORCE=1                     Continue despite findings
  YSHIELD_ALLOW_OFFICIAL=1            Skip official repo packages (default:1)
  YSHIELD_MIN_SEVERITY=MEDIUM         Hide findings below this level
  YSHIELD_BLOCK_MIN_SEVERITY=HIGH     Prompt/block threshold
  YSHIELD_CLONE_DEPTH=5               Git history depth
  YSHIELD_ENTROPY_THRESHOLD=4.9       Shannon entropy threshold
  YSHIELD_CACHE_DIR=~/.cache/yay-shield
  YSHIELD_REPORT_JSON=1               Write JSON report
  YSHIELD_ALLOWLIST=~/.config/yay-shield/allowlist
  YSHIELD_TRUSTED_MAINTAINERS=alice:bob
  YSHIELD_PARALLEL=1                  Parallel multi-package scanning
  YSHIELD_FILE_WORKERS=8              Parallel file scanning threads
  YSHIELD_DEBUG=1                     Verbose debug output

  ── Analysis toggles ─────────────────────────────────────────────────────────
  YSHIELD_DATA_FLOW=1                 Taint-flow analysis
  YSHIELD_CALL_GRAPH=1                Function call-graph analysis
  YSHIELD_SHELLCHECK=1                ShellCheck integration
  YSHIELD_BINARY_STRINGS=1            strings(1) on committed binaries
  YSHIELD_HOMOGLYPH=1                 Unicode homoglyph detection
  YSHIELD_ANTI_ANALYSIS=1             Anti-analysis/evasion probing detection
  YSHIELD_STRING_RECONSTRUCT=1        Command reconstruction obfuscation
  YSHIELD_SANDBOX=0                   bwrap sandbox (requires: bwrap)
  YSHIELD_STEGANOGRAPHY=0             binwalk on images (requires: binwalk)
  YSHIELD_SCAN_VCS_SOURCES=0          Clone and scan git+ VCS sources
  YSHIELD_SCAN_AUR_DEPS=0             Recursively scan AUR dependencies

  ── v7/v8/v9 analysis ───────────────────────────────────────────────────────
  YSHIELD_SEMANTIC_VARS=1             Variable resolution before scanning
  YSHIELD_HEREDOC_SCAN=1             Scan heredoc body content
  YSHIELD_DIFF_AWARE=1                Incremental diff-aware scanning
  YSHIELD_GPG_VERIFY=1                Check validpgpkeys against local keyring
  YSHIELD_PROC_SUB_NET=1              Process-substitution network exec checks
  YSHIELD_TRAP_ANALYSIS=1             Trap handler payload checks
  YSHIELD_GLOB_OBFUSC=1               Glob-obfuscated command checks
  YSHIELD_INDIRECT_VAR=1              Bash indirect variable exec checks
  YSHIELD_BUILD_SYSTEM_DEEP=1         CMake/Meson/npm/Cargo config checks
  YSHIELD_GIT_HOOK_SCAN=1             Git hook injection checks
  YSHIELD_ARITH_CHARCODE=1            Arithmetic char-code reconstruction
  YSHIELD_SHELL_OPT_ANALYSIS=1        Suspicious shell option changes
  YSHIELD_STRIP_INLINE_COMMENTS=1     Bash-aware inline comment stripping
  YSHIELD_DROPPER_PATH_TRACKING=1     Track download/chmod/execute path chains
  YSHIELD_MANIFEST_DEEP=1             npm/Cargo/Go/Python manifest checks
  YSHIELD_VERIFY_YAY_BINARY=1         Verify resolved yay binary before handoff
  YSHIELD_SANITIZE_ENV=1              Strip dangerous env hooks before handoff
  YSHIELD_FAIL_CLOSED_MANIFESTS=1     Report malformed manifests as scan blind spots
  YSHIELD_SOURCE_INTEGRITY_DEEP=1     Deep source/checksum consistency checks
  YSHIELD_SYMLINK_SCAN=1              Detect symlink escape/path shadowing risks
  YSHIELD_ARCHIVE_RISK_SCAN=1         Detect traversal/metacharacter filename risks
  YSHIELD_LOCKFILE_SCAN=1             Inspect npm/yarn/pnpm lockfiles
  YSHIELD_HANDOFF_ARG_GUARD=1         Reject dangerous yay handoff overrides
  YSHIELD_BASH_EAGER_DECODE=1         Decode Bash ANSI-C $'...' strings before scanning
  YSHIELD_PARAM_TRANSFORM_TRACK=1     Resolve/fail-closed Bash parameter transforms
  YSHIELD_ARRAY_INDEX_TRACK=1         Track simple indexed Bash array reconstruction
  YSHIELD_FILE_TAINT_TRACK=1          Preserve taint through file write/read laundering
  YSHIELD_DOWNSTREAM_SCRIPT_CRAWL=1   Crawl build.rs/setup.py/lifecycle build hooks
  YSHIELD_INSTALL_UNIFORM_SCAN=1      Uniformly scan all .install lifecycle functions
  YSHIELD_OFFICIAL_ALT_PROMPT=1       Offer official repo package alternatives for AUR variants
  YSHIELD_WEAK_ADVISORIES=0           Include very low-confidence advisory findings

  Requires bwrap for YSHIELD_SANDBOX, strace for sandbox tracing,
  strings for YSHIELD_BINARY_STRINGS, binwalk for YSHIELD_STEGANOGRAPHY.
""")

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main(argv: List[str]) -> int:
    if len(argv) > 1 and argv[1] in {"--help", "-h"}:
        usage()
        return 0
    if len(argv) > 1 and argv[1] in {"--version", "-V"}:
        print("yay-shield 12 (v12 hardened codebase)")
        return 0

    ensure_required_commands()

    yay_argv = argv[1:]

    if is_yay_passthrough_mode(yay_argv):
        return call_yay(yay_argv)

    targets = extract_sync_targets(yay_argv)
    if not targets:
        if any(re.search(r"(?i)(?:^|[ \t])-S.*u|--sysupgrade", arg) for arg in yay_argv):
            warn("System upgrade (-Syu) detected. yay-shield cannot pre-scan all update targets.")
            warn("Run 'yay -Qu' first to review AUR packages queued for update,")
            warn("then install them individually through yay-shield for full inspection.")
        return call_yay(yay_argv)

    yay_argv, targets = offer_official_repo_alternatives(targets, yay_argv)

    # Feature status summary
    optional_status: List[str] = []
    for feat, env_val, cmd in [
        ("sandbox",    YSHIELD_SANDBOX,        "bwrap"),
        ("strace",     YSHIELD_SANDBOX,        "strace"),
        ("shellcheck", YSHIELD_SHELLCHECK,     "shellcheck"),
        ("strings",    YSHIELD_BINARY_STRINGS, "strings"),
        ("binwalk",    YSHIELD_STEGANOGRAPHY,  "binwalk"),
        ("gpg",        YSHIELD_GPG_VERIFY,     "gpg"),
    ]:
        if env_val and not command_exists(cmd):
            optional_status.append(f"{cmd}(missing)")
        elif env_val:
            optional_status.append(f"{cmd}(active)")
    if optional_status:
        print(f"{C['dim']}Optional features: {', '.join(optional_status)}{C['nc']}")

    print(f"\n{C['blue']}🛡️  yay-shield v12 — scanning {len(targets)} package(s){C['nc']}")

    # Warm popular-package cache in background
    bg = threading.Thread(target=_load_official_packages, daemon=True)
    bg.start()

    scans:      List[PackageScan] = []
    failures:   Dict[str, bool]   = {}
    commit_map: Dict[str, str]    = {}

    if YSHIELD_PARALLEL and len(targets) > 1:
        def worker(pkg: str) -> Tuple[PackageScan, bool, str, str]:
            buf = io.StringIO()
            with redirect_stdout(buf):
                sc, ok, commit = scan_package(pkg)
            return sc, ok, commit, buf.getvalue()

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(8, len(targets))
        ) as ex:
            futs = {ex.submit(worker, pkg): pkg for pkg in targets}
            results: Dict[str, Tuple[PackageScan, bool, str, str]] = {}
            for fut in concurrent.futures.as_completed(futs):
                pkg = futs[fut]
                try:
                    results[pkg] = fut.result()
                except Exception as exc:
                    error(f"Scan failed for {pkg!r}: {exc}")
                    failures[pkg] = True
            for pkg in targets:
                if pkg in results:
                    sc, ok, commit, out = results[pkg]
                    if out:
                        with OUTPUT_LOCK:
                            print(out, end="")
                    scans.append(sc)
                    commit_map[pkg] = commit
                    failures[pkg]   = not ok
    else:
        for pkg in targets:
            sc, ok, commit = scan_package(pkg)
            scans.append(sc)
            commit_map[pkg] = commit
            failures[pkg]   = not ok

    for pkg, failed in failures.items():
        if failed:
            error(f"Scan failed for {pkg!r}. Refusing to continue.")
            return 1

    return summarize_and_decide(scans, commit_map, yay_argv)


if __name__ == "__main__":
    try:
        code = main(sys.argv)
    finally:
        shutil.rmtree(TEMP_DIR, ignore_errors=True)
    raise SystemExit(code)
