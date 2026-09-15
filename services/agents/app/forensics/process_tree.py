"""Process tree builder: constructs process ancestry from event-level parent-child relationships.

Ported from sxsecurityinvestigator: builds per-host process ancestry from
PID->PPID relationships, process names, and command lines across events.
Populates process_ancestors and detects suspicious parent-child lineages.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any


# Known suspicious parent -> child process pairings
SUSPICIOUS_PAIRS = frozenset({
    ("w3wp.exe", "cmd.exe"),
    ("w3wp.exe", "powershell.exe"),
    ("nginx", "bash"),
    ("nginx", "sh"),
    ("apache2", "bash"),
    ("apache2", "sh"),
    ("httpd", "bash"),
    ("httpd", "sh"),
    ("tomcat", "bash"),
    ("tomcat", "sh"),
    ("sqlservr.exe", "cmd.exe"),
    ("sqlservr.exe", "powershell.exe"),
    ("mysqld", "bash"),
    ("mysqld", "sh"),
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("sshd", "sh"),
})


def _get_field(item: Any, *keys: str, default: Any = "") -> Any:
    """Extract a field from dict or object by checking candidate keys."""
    if isinstance(item, dict):
        for k in keys:
            if k in item and item[k] is not None:
                return item[k]
        raw = item.get("raw")
        if isinstance(raw, dict):
            for k in keys:
                if k in raw and raw[k] is not None:
                    return raw[k]
    else:
        for k in keys:
            val = getattr(item, k, None)
            if val is not None:
                return val
        raw = getattr(item, "raw", None)
        if isinstance(raw, dict):
            for k in keys:
                if k in raw and raw[k] is not None:
                    return raw[k]
    return default


def _normalize_proc_name(proc: str) -> str:
    """Normalize process path/binary to lower-cased executable name."""
    if not proc:
        return ""
    proc = str(proc).strip().lower().replace("\\", "/")
    return proc.split("/")[-1]


def build_process_trees(events: list[Any], max_depth: int = 10) -> dict[str, list[dict[str, Any]]]:
    """Build process ancestry and attach lineage to each event.

    Scans all events on the same host to build parent->child tree (by PID->PPID and process name),
    then walks backward from each process to build full lineage.
    Returns a dictionary of per-host process trees.
    """
    # Per-host: process_name -> parent_process_name
    parent_map: dict[str, dict[str, str]] = defaultdict(dict)
    # Per-host: pid -> process_name
    pid_to_proc: dict[str, dict[str, str]] = defaultdict(dict)
    # Per-host: pid -> ppid
    pid_to_ppid: dict[str, dict[str, str]] = defaultdict(dict)
    # Per-host: pid -> command_line
    pid_to_cmd: dict[str, dict[str, str]] = defaultdict(dict)

    for event in events:
        host = str(_get_field(event, "host", "hostname", "affected_host", "device_name", default="")).lower()
        if not host:
            continue

        proc = _normalize_proc_name(_get_field(event, "process", "process_name", "image", "comm"))
        parent = _normalize_proc_name(_get_field(event, "parent_process", "parent_process_name", "pproc", "parent_image"))
        pid = str(_get_field(event, "pid", "process_id", default="")).strip()
        ppid = str(_get_field(event, "ppid", "parent_process_id", default="")).strip()
        cmd = str(_get_field(event, "cmdline", "command_line", "process_command_line", default="")).strip()

        if pid and proc:
            pid_to_proc[host][pid] = proc
            if cmd:
                pid_to_cmd[host][pid] = cmd
        if pid and ppid and pid != ppid:
            pid_to_ppid[host][pid] = ppid
        if proc and parent and proc != parent:
            parent_map[host].setdefault(proc, parent)

    # Backfill missing parent_process from PID->PPID relationships
    for event in events:
        host = str(_get_field(event, "host", "hostname", "affected_host", default="")).lower()
        if not host:
            continue
        proc = _normalize_proc_name(_get_field(event, "process", "process_name", "image"))
        parent = _normalize_proc_name(_get_field(event, "parent_process", "parent_process_name"))
        ppid = str(_get_field(event, "ppid", "parent_process_id", default="")).strip()

        if not parent and ppid and host in pid_to_proc:
            resolved_parent = pid_to_proc[host].get(ppid)
            if resolved_parent and resolved_parent != proc:
                parent = resolved_parent
                if isinstance(event, dict):
                    event["parent_process"] = parent
                else:
                    try:
                        setattr(event, "parent_process", parent)
                    except Exception:
                        pass

        if proc and parent and proc != parent:
            parent_map[host].setdefault(proc, parent)

    # Build ancestry chains and attach to events
    for event in events:
        host = str(_get_field(event, "host", "hostname", "affected_host", default="")).lower()
        if not host:
            continue

        proc = _normalize_proc_name(_get_field(event, "process", "process_name", "image"))
        if not proc:
            continue

        pid = str(_get_field(event, "pid", "process_id", default="")).strip()
        ancestors: list[str] = []
        visited_pids: set[str] = {pid} if pid else set()
        current_pid = pid
        current_proc = proc
        visited_procs: set[str] = {current_proc}
        host_parents = parent_map.get(host, {})
        host_ppids = pid_to_ppid.get(host, {})
        host_pids = pid_to_proc.get(host, {})

        for _ in range(max_depth):
            parent_proc = None
            if current_pid and current_pid in host_ppids:
                ppid = host_ppids[current_pid]
                if ppid not in visited_pids:
                    visited_pids.add(ppid)
                    current_pid = ppid
                    parent_proc = host_pids.get(ppid)
            if not parent_proc:
                parent_proc = host_parents.get(current_proc)
                current_pid = ""
            if not parent_proc or parent_proc in visited_procs:
                break
            ancestors.append(parent_proc)
            visited_procs.add(parent_proc)
            current_proc = parent_proc

        if ancestors:
            if isinstance(event, dict):
                event["process_ancestors"] = ancestors
                if "raw" in event and isinstance(event["raw"], dict):
                    event["raw"]["process_ancestors"] = ancestors
            else:
                try:
                    setattr(event, "process_ancestors", ancestors)
                except Exception:
                    pass

    # Build per-host process trees structure for report and analysis
    host_trees: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for host, pids in pid_to_proc.items():
        for pid, proc in pids.items():
            ppid = pid_to_ppid[host].get(pid, "")
            parent_name = pid_to_proc[host].get(ppid, parent_map[host].get(proc, "unknown"))
            is_suspicious = (parent_name, proc) in SUSPICIOUS_PAIRS
            host_trees[host].append({
                "pid": pid,
                "ppid": ppid,
                "process": proc,
                "parent_process": parent_name,
                "cmdline": pid_to_cmd[host].get(pid, ""),
                "suspicious": is_suspicious,
            })

    return dict(host_trees)
