from __future__ import annotations

import json
import heapq
import ipaddress
import os
import platform
import subprocess
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from c2trace.execution import ToolResult
from c2trace.models import (
    AuditDecision,
    AuditVerdict,
    NodeType,
    StrategyNode,
    STRATEGY_READ_ONLY_TOOLS,
    STRATEGY_RESPONSE_TOOLS,
)


READ_ONLY_TOOLS = set(STRATEGY_READ_ONLY_TOOLS)
DESTRUCTIVE_TOOLS = set(STRATEGY_RESPONSE_TOOLS)

RESPONSE_TOOLS = DESTRUCTIVE_TOOLS
SUPPORTED_TOOLS = READ_ONLY_TOOLS | RESPONSE_TOOLS


@dataclass(frozen=True, slots=True)
class _ResponseAuthorization:
    token: str
    decision_id: str
    node_id: str
    tool: str
    params_fingerprint: str


class WindowsToolBackend:
    """Deterministic Windows implementation owned by the MCP server.

    It is deliberately not an agent.  ``SystemToolRunner`` remains as a
    compatibility alias during the migration, but the production C2Trace path
    reaches this backend only through MCP.
    """

    def __init__(self, *, execute_response: bool = False) -> None:
        self.execute_response = execute_response
        self._active_response_token: ContextVar[str | None] = ContextVar(
            f"c2trace_response_authorization_{id(self)}",
            default=None,
        )
        self._response_authorizations: dict[str, _ResponseAuthorization] = {}

    @contextmanager
    def audited_response(
        self,
        *,
        decision: AuditDecision,
        node: StrategyNode,
        params: dict[str, Any],
    ) -> Iterator[str]:
        """Issue a one-shot capability bound to an approved node and arguments.

        The capability is held in a context variable rather than ordinary tool
        parameters, so it cannot accidentally leak into findings or reports.
        Every destructive method consumes it before invoking PowerShell.
        """
        if decision.verdict != AuditVerdict.APPROVED:
            raise PermissionError("response authorization requires an approved audit decision")
        if decision.node_id != node.node_id or node.audit_decision_id != decision.decision_id:
            raise PermissionError("audit decision is not bound to the response node")
        if node.type != NodeType.RESPONSE or node.tool not in RESPONSE_TOOLS:
            raise PermissionError("audit authorization is valid only for a response node/tool")

        token = uuid4().hex
        self._response_authorizations[token] = _ResponseAuthorization(
            token=token,
            decision_id=decision.decision_id,
            node_id=node.node_id,
            tool=node.tool,
            params_fingerprint=self._params_fingerprint(params),
        )
        context_token = self._active_response_token.set(token)
        try:
            yield token
        finally:
            self._active_response_token.reset(context_token)
            self._response_authorizations.pop(token, None)

    @contextmanager
    def mcp_authorized_response(
        self,
        *,
        tool: str,
        params: dict[str, Any],
    ) -> Iterator[str]:
        """Install a one-shot backend capability after MCP-side verification.

        The MCP server performs the cryptographic, case, target-lock, expiry,
        and replay checks.  This backend-local capability prevents an
        accidental direct method call from bypassing that verified server
        path.
        """
        if not self.execute_response:
            raise PermissionError("response backend is running in read-only mode")
        if tool not in RESPONSE_TOOLS:
            raise PermissionError("MCP response capability requires a response tool")
        token = uuid4().hex
        self._response_authorizations[token] = _ResponseAuthorization(
            token=token,
            decision_id="mcp-server-verified",
            node_id="mcp-server-verified",
            tool=tool,
            params_fingerprint=self._params_fingerprint(params),
        )
        context_token = self._active_response_token.set(token)
        try:
            yield token
        finally:
            self._active_response_token.reset(context_token)
            self._response_authorizations.pop(token, None)

    def run(self, tool: str, params: dict[str, Any] | None = None) -> ToolResult:
        params = params or {}
        start = time.time()
        if tool not in SUPPORTED_TOOLS:
            return ToolResult(False, error=f"unsupported tool: {tool}")
        if tool in RESPONSE_TOOLS and not self.execute_response:
            return ToolResult(
                True,
                data={"dry_run": True, "tool": tool, "params": params},
                elapsed_ms=(time.time() - start) * 1000,
            )
        try:
            method = getattr(self, tool)
            result = method(**params)
            result.elapsed_ms = (time.time() - start) * 1000
            return result
        except TypeError as exc:
            return ToolResult(False, error=f"bad params for {tool}: {exc}", elapsed_ms=(time.time() - start) * 1000)
        except Exception as exc:
            return ToolResult(False, error=str(exc), elapsed_ms=(time.time() - start) * 1000)

    def check_network(
        self,
        remote_ip: str = "",
        remote_port: str | int = "",
        target_ip: str = "",
        target_port: str | int = "",
        local_port: str | int = "",
        network_mode: str = "outbound_active_flow",
        local_ip: str = "",
    ) -> ToolResult:
        if platform.system().lower() != "windows":
            return ToolResult(False, error="check_network requires a Windows host")
        mode = str(network_mode or "outbound_active_flow").strip().lower()
        if mode not in {"outbound_active_flow", "inbound_listener"}:
            return ToolResult(False, error=f"invalid network_mode: {network_mode}")
        if mode == "inbound_listener":
            try:
                local_port_number = int(local_port or 0)
            except ValueError:
                return ToolResult(False, error=f"invalid local_port: {local_port}")
            if not 1 <= local_port_number <= 65535:
                return ToolResult(False, error="inbound_listener requires a valid local_port")
            normalized_local_ip = ""
            if local_ip:
                try:
                    normalized_local_ip = str(ipaddress.ip_address(str(local_ip).strip()))
                except ValueError:
                    return ToolResult(False, error=f"invalid local_ip: {local_ip}")
            filters = [
                f"$_.LocalPort -eq {local_port_number}",
                "$_.State -eq 'Listen'",
                "$_.OwningProcess -gt 0",
            ]
            if normalized_local_ip:
                filters.append(
                    "($_.LocalAddress -eq "
                    f"{self._ps_sq(normalized_local_ip)} -or "
                    "$_.LocalAddress -eq '0.0.0.0' -or "
                    "$_.LocalAddress -eq '::')"
                )
            filter_expr = f" | Where-Object {{ {' -and '.join(filters)} }}"
            script = f"""
$items = Get-NetTCPConnection -ErrorAction Stop{filter_expr} | ForEach-Object {{
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{{
        local_address = $_.LocalAddress
        local_port = $_.LocalPort
        remote_address = $_.RemoteAddress
        remote_port = $_.RemotePort
        state = "$($_.State)"
        pid = $_.OwningProcess
        process_name = if ($proc) {{ $proc.ProcessName }} else {{ "" }}
        process_path = if ($proc) {{ $proc.Path }} else {{ "" }}
    }}
}}
ConvertTo-Json -Depth 4 @{{ connections = @($items) }}
"""
            return self._run_ps_json(script, default={"connections": []})

        ip = remote_ip or target_ip
        if not ip:
            return ToolResult(False, error="remote_ip is required; domain/url-only seeds cannot be attributed safely")
        try:
            ip = str(ipaddress.ip_address(str(ip).strip()))
        except ValueError:
            return ToolResult(False, error=f"invalid remote_ip: {ip}")
        port = str(remote_port or target_port or "")
        # C2Trace attributes and verifies live C2 ownership. Closed TCP rows
        # such as TimeWait have no live owning process and must not become an
        # attribution target or make post-response cleanup fail.
        filters = [
            f"$_.RemoteAddress -eq {self._ps_sq(ip)}",
            "$_.State -eq 'Established'",
            "$_.OwningProcess -gt 0",
        ]
        if port:
            try:
                port_number = int(port)
            except ValueError:
                return ToolResult(False, error=f"invalid remote_port: {port}")
            if not 1 <= port_number <= 65535:
                return ToolResult(False, error=f"invalid remote_port: {port}")
            filters.append(f"$_.RemotePort -eq {port_number}")
        if local_port:
            try:
                local_port_number = int(local_port)
            except ValueError:
                return ToolResult(False, error=f"invalid local_port: {local_port}")
            if not 1 <= local_port_number <= 65535:
                return ToolResult(False, error=f"invalid local_port: {local_port}")
            filters.append(f"$_.LocalPort -eq {local_port_number}")
        filter_expr = f" | Where-Object {{ {' -and '.join(filters)} }}" if filters else ""
        script = f"""
$items = Get-NetTCPConnection -ErrorAction Stop{filter_expr} | ForEach-Object {{
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{{
        local_address = $_.LocalAddress
        local_port = $_.LocalPort
        remote_address = $_.RemoteAddress
        remote_port = $_.RemotePort
        state = "$($_.State)"
        pid = $_.OwningProcess
        process_name = if ($proc) {{ $proc.ProcessName }} else {{ "" }}
        process_path = if ($proc) {{ $proc.Path }} else {{ "" }}
    }}
}}
ConvertTo-Json -Depth 4 @{{ connections = @($items) }}
"""
        return self._run_ps_json(script, default={"connections": []})

    def check_process(self, pid: int = 0, process_name: str = "") -> ToolResult:
        if platform.system().lower() != "windows":
            return ToolResult(False, error="check_process requires a Windows host")
        if pid:
            filter_clause = f"ProcessId = {int(pid)}"
        elif process_name:
            escaped = str(process_name).replace("'", "''")
            names = [escaped]
            if not escaped.lower().endswith(".exe"):
                names.append(f"{escaped}.exe")
            filter_clause = " OR ".join(f"Name = '{name}'" for name in names)
        else:
            return ToolResult(False, error="pid or process_name required")
        script = f"""
$items = Get-CimInstance Win32_Process -Filter {self._ps_sq(filter_clause)} -ErrorAction Stop | ForEach-Object {{
    [PSCustomObject]@{{
        pid = $_.ProcessId
        name = $_.Name
        path = $_.ExecutablePath
        command_line = $_.CommandLine
        parent_pid = $_.ParentProcessId
        creation_date = "$($_.CreationDate)"
        creation_time_utc = if ($_.CreationDate) {{ $_.CreationDate.ToUniversalTime().ToString("o") }} else {{ "" }}
    }}
}}
ConvertTo-Json -Depth 4 @{{ processes = @($items) }}
"""
        return self._run_ps_json(script, default={"processes": []})

    def check_process_tree(self, pid: int = 0, process_name: str = "") -> ToolResult:
        if platform.system().lower() != "windows":
            return ToolResult(False, error="check_process_tree requires a Windows host")
        if pid:
            root_query = f"Get-CimInstance Win32_Process -Filter \"ProcessId = {int(pid)}\" -ErrorAction Stop"
        elif process_name:
            name = process_name if process_name.lower().endswith(".exe") else f"{process_name}.exe"
            root_query = f"Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {{ $_.Name -eq {self._ps_sq(name)} }}"
        else:
            return ToolResult(False, error="pid or process_name required")
        script = f"""
function Convert-Proc($p) {{
    if (-not $p) {{ return $null }}
    [PSCustomObject]@{{
        pid = $p.ProcessId
        name = $p.Name
        path = $p.ExecutablePath
        command_line = $p.CommandLine
        parent_pid = $p.ParentProcessId
        creation_date = "$($p.CreationDate)"
        creation_time_utc = if ($p.CreationDate) {{ $p.CreationDate.ToUniversalTime().ToString("o") }} else {{ "" }}
    }}
}}
$roots = @({root_query})
$trees = @()
foreach ($root in $roots) {{
    $chain = @()
    $current = $root
    for ($i = 0; $i -lt 8 -and $current; $i++) {{
        $chain += Convert-Proc $current
        $parentId = [int]($current.ParentProcessId)
        if (-not $parentId -or $parentId -eq $current.ProcessId) {{ break }}
        $current = Get-CimInstance Win32_Process -Filter "ProcessId = $parentId" -ErrorAction Stop
    }}
    $trees += [PSCustomObject]@{{ root = Convert-Proc $root; chain = @($chain) }}
}}
ConvertTo-Json -Depth 6 @{{ trees = @($trees) }}
"""
        return self._run_ps_json(script, default={"trees": []})

    def check_file_metadata(self, file_path: str = "") -> ToolResult:
        if not file_path:
            return ToolResult(True, data={"file": {"exists": False, "path": "", "note": "file_path not available"}})
        if platform.system().lower() != "windows":
            return ToolResult(False, error="check_file_metadata requires a Windows host")
        path_value = self._ps_sq(file_path)
        script = f"""
$path = {path_value}
$item = if (Test-Path -LiteralPath $path -ErrorAction Stop) {{ Get-Item -LiteralPath $path -Force -ErrorAction Stop }} else {{ $null }}
if ($item) {{
    $hash = $null
    $sig = $null
    if (-not $item.PSIsContainer) {{
        $hash = Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop
        $sig = Get-AuthenticodeSignature -LiteralPath $item.FullName -ErrorAction Stop
    }}
    $file = [PSCustomObject]@{{
        exists = $true
        path = $item.FullName
        name = $item.Name
        length = if ($item.PSIsContainer) {{ $null }} else {{ $item.Length }}
        creation_time_utc = $item.CreationTimeUtc.ToString("o")
        last_write_time_utc = $item.LastWriteTimeUtc.ToString("o")
        sha256 = if ($hash) {{ $hash.Hash }} else {{ "" }}
        signature_status = if ($sig) {{ "$($sig.Status)" }} else {{ "" }}
        signer = if ($sig -and $sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ "" }}
    }}
}} else {{
    $file = [PSCustomObject]@{{ exists = $false; path = $path }}
}}
ConvertTo-Json -Depth 5 @{{ file = $file }}
"""
        return self._run_ps_json(script, default={"file": {"exists": False, "path": file_path}})

    def check_recent_files(
        self,
        since_utc: str = "",
        until_utc: str = "",
        root_aliases: list[str] | None = None,
        max_depth: int = 4,
        max_results: int = 64,
        max_file_size: int = 4 * 1024 * 1024,
    ) -> ToolResult:
        """Collect bounded metadata for recently modified files in safe roots.

        This is deliberately a discovery tool, not a caller-supplied path walk.
        Callers may select only named roots from a fixed allowlist.  The walk is
        read-only, does not invoke a shell, never follows reparse points, and
        applies hard bounds to time, depth, entry count, duration, result count,
        and bytes hashed.
        """
        if platform.system().lower() != "windows":
            return ToolResult(False, error="check_recent_files requires a Windows host")

        try:
            selected_aliases = self._validate_recent_file_aliases(root_aliases)
            since, until = self._recent_file_window(since_utc, until_utc)
            depth = self._bounded_int("max_depth", max_depth, minimum=0, maximum=8)
            result_limit = self._bounded_int("max_results", max_results, minimum=1, maximum=128)
            file_size_limit = self._bounded_int(
                "max_file_size",
                max_file_size,
                minimum=1,
                maximum=16 * 1024 * 1024,
            )
            allowed_roots = self._recent_file_allowed_roots()
        except (TypeError, ValueError, OSError) as exc:
            return ToolResult(False, error=str(exc))

        roots = [(alias, allowed_roots[alias]) for alias in selected_aliases]
        # These bounds are not caller-controlled.  They keep a damaged or very
        # large profile from turning a host investigation into an unbounded walk.
        max_directories = 4096
        max_entries = 50000
        max_seconds = 12.0
        deadline = time.monotonic() + max_seconds
        scanned_directories = 0
        scanned_entries = 0
        matching_file_count = 0
        skipped_reparse_points = 0
        truncated_reasons: set[str] = set()
        scan_errors: list[dict[str, str]] = []
        root_status: list[dict[str, Any]] = []
        # Keep only the newest N candidates while walking.  Path is a stable
        # tie-breaker, so output ordering is deterministic for equal mtimes.
        candidates: list[tuple[int, str, Path, os.stat_result, str]] = []

        for alias, root in roots:
            root_record: dict[str, Any] = {
                "alias": alias,
                "path": str(root),
                "exists": False,
            }
            root_status.append(root_record)
            try:
                canonical_root = root.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                root_record["error"] = str(exc)
                continue
            if not canonical_root.is_dir():
                root_record["error"] = "allowed root is not a directory"
                continue
            root_record["exists"] = True
            queue: list[tuple[Path, int]] = [(canonical_root, 0)]
            cursor = 0
            while cursor < len(queue):
                if time.monotonic() >= deadline:
                    truncated_reasons.add("duration_limit")
                    break
                if scanned_directories >= max_directories:
                    truncated_reasons.add("directory_limit")
                    break
                directory, current_depth = queue[cursor]
                cursor += 1
                scanned_directories += 1
                try:
                    entries = os.scandir(directory)
                except OSError as exc:
                    if len(scan_errors) < 32:
                        scan_errors.append({"path": str(directory), "error": str(exc)})
                    continue
                with entries:
                    for entry in entries:
                        if time.monotonic() >= deadline:
                            truncated_reasons.add("duration_limit")
                            break
                        if scanned_entries >= max_entries:
                            truncated_reasons.add("entry_limit")
                            break
                        scanned_entries += 1
                        try:
                            entry_stat = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            if len(scan_errors) < 32:
                                scan_errors.append({"path": entry.path, "error": str(exc)})
                            continue
                        if int(getattr(entry_stat, "st_file_attributes", 0)) & 0x400:
                            skipped_reparse_points += 1
                            continue
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if current_depth < depth:
                                    child = Path(entry.path)
                                    if self._path_is_within(child, canonical_root):
                                        queue.append((child, current_depth + 1))
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                        except OSError as exc:
                            if len(scan_errors) < 32:
                                scan_errors.append({"path": entry.path, "error": str(exc)})
                            continue

                        modified = datetime.fromtimestamp(entry_stat.st_mtime, UTC)
                        if modified < since or modified > until:
                            continue
                        path = Path(entry.path)
                        if not self._path_is_within(path, canonical_root):
                            continue
                        matching_file_count += 1
                        path_key = os.path.normcase(str(path.resolve(strict=False)))
                        candidate = (
                            int(getattr(entry_stat, "st_mtime_ns", int(entry_stat.st_mtime * 1e9))),
                            path_key,
                            path,
                            entry_stat,
                            alias,
                        )
                        if len(candidates) < result_limit:
                            heapq.heappush(candidates, candidate)
                        elif candidate[:2] > candidates[0][:2]:
                            heapq.heapreplace(candidates, candidate)
                            truncated_reasons.add("result_limit")
                        else:
                            truncated_reasons.add("result_limit")
                    if truncated_reasons & {"duration_limit", "entry_limit"}:
                        break
                if truncated_reasons & {"duration_limit", "directory_limit", "entry_limit"}:
                    break
            if truncated_reasons & {"duration_limit", "directory_limit", "entry_limit"}:
                break

        unavailable_roots = [
            item for item in root_status if item.get("exists") is not True
        ]
        if unavailable_roots:
            return ToolResult(
                False,
                data={
                    "roots": root_status,
                    "unavailable_root_aliases": [item["alias"] for item in unavailable_roots],
                },
                error="one or more selected recent-file roots is unavailable",
            )

        files: list[dict[str, Any]] = []
        for _, _, path, initial_stat, alias in sorted(candidates, reverse=True):
            digest, hash_status = self._bounded_file_sha256(path, file_size_limit)
            size = int(initial_stat.st_size)
            files.append({
                "exists": True,
                "path": str(path.resolve(strict=False)),
                "name": path.name,
                "root_alias": alias,
                "size": size,
                "length": size,
                "creation_time_utc": self._timestamp_utc(initial_stat.st_ctime),
                "last_write_time_utc": self._timestamp_utc(initial_stat.st_mtime),
                "sha256": digest,
                "sha256_status": hash_status,
            })

        return ToolResult(True, data={
            "files": files,
            "query": {
                "since_utc": self._datetime_utc(since),
                "until_utc": self._datetime_utc(until),
                "root_aliases": selected_aliases,
                "max_depth": depth,
                "max_results": result_limit,
                "max_file_size": file_size_limit,
            },
            "scan": {
                "roots": root_status,
                "scanned_directories": scanned_directories,
                "scanned_entries": scanned_entries,
                "matching_file_count": matching_file_count,
                "skipped_reparse_points": skipped_reparse_points,
                "truncated": bool(truncated_reasons),
                "truncated_reasons": sorted(truncated_reasons),
                "errors": scan_errors,
            },
        })

    @staticmethod
    def _validate_recent_file_aliases(root_aliases: list[str] | None) -> list[str]:
        allowed = ("users_public", "appdata")
        if root_aliases is None:
            return list(allowed)
        if not isinstance(root_aliases, list) or not root_aliases:
            raise TypeError("root_aliases must be a non-empty list of fixed root aliases")
        normalized = [str(item).strip().lower() for item in root_aliases]
        unknown = sorted(set(normalized) - set(allowed))
        if unknown:
            raise ValueError(f"unsupported recent-file root alias(es): {unknown}")
        return list(dict.fromkeys(normalized))

    @staticmethod
    def _recent_file_allowed_roots() -> dict[str, Path]:
        user_profile = str(os.environ.get("USERPROFILE") or "").strip()
        appdata = str(os.environ.get("APPDATA") or "").strip()
        if not user_profile:
            raise ValueError("USERPROFILE is required to bind the current-user APPDATA root")
        expected_appdata = Path(user_profile) / "AppData" / "Roaming"
        selected_appdata = Path(appdata) if appdata else expected_appdata
        if os.path.normcase(os.path.abspath(selected_appdata)) != os.path.normcase(
            os.path.abspath(expected_appdata)
        ):
            raise ValueError("APPDATA is outside the current USERPROFILE AppData\\Roaming root")
        return {
            "users_public": Path(r"C:\Users\Public"),
            "appdata": selected_appdata,
        }

    @staticmethod
    def _recent_file_window(since_utc: str, until_utc: str) -> tuple[datetime, datetime]:
        now = datetime.now(UTC)
        until = WindowsToolBackend._parse_utc(until_utc, "until_utc") if until_utc else now
        since = (
            WindowsToolBackend._parse_utc(since_utc, "since_utc")
            if since_utc
            else until - timedelta(minutes=30)
        )
        if since >= until:
            raise ValueError("since_utc must be earlier than until_utc")
        if until - since > timedelta(hours=2):
            raise ValueError("recent-file UTC window cannot exceed 2 hours")
        if until > now + timedelta(minutes=5):
            raise ValueError("until_utc cannot be more than 5 minutes in the future")
        return since, until

    @staticmethod
    def _parse_utc(value: str, name: str) -> datetime:
        text = str(value or "").strip()
        try:
            parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
        except ValueError as exc:
            raise ValueError(f"{name} must be an ISO-8601 UTC timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValueError(f"{name} must include the UTC offset Z or +00:00")
        return parsed.astimezone(UTC)

    @staticmethod
    def _bounded_int(name: str, value: Any, *, minimum: int, maximum: int) -> int:
        if isinstance(value, bool):
            raise TypeError(f"{name} must be an integer")
        try:
            normalized = int(value)
        except (TypeError, ValueError) as exc:
            raise TypeError(f"{name} must be an integer") from exc
        if normalized < minimum or normalized > maximum:
            raise ValueError(f"{name} must be between {minimum} and {maximum}")
        return normalized

    @staticmethod
    def _path_is_within(path: Path, root: Path) -> bool:
        try:
            canonical_path = path.resolve(strict=False)
            canonical_root = root.resolve(strict=False)
            return os.path.commonpath((canonical_path, canonical_root)) == str(canonical_root)
        except (OSError, RuntimeError, ValueError):
            return False

    @staticmethod
    def _bounded_file_sha256(path: Path, max_bytes: int) -> tuple[str, str]:
        try:
            with path.open("rb") as handle:
                before = os.fstat(handle.fileno())
                if before.st_size > max_bytes:
                    return "", "skipped_size_limit"
                digest = sha256()
                remaining = int(before.st_size)
                while remaining:
                    chunk = handle.read(min(1024 * 1024, remaining))
                    if not chunk:
                        return "", "skipped_file_changed"
                    digest.update(chunk)
                    remaining -= len(chunk)
                after = os.fstat(handle.fileno())
                if (
                    after.st_size != before.st_size
                    or getattr(after, "st_mtime_ns", 0) != getattr(before, "st_mtime_ns", 0)
                ):
                    return "", "skipped_file_changed"
                return digest.hexdigest(), "hashed"
        except OSError:
            return "", "unreadable"

    @staticmethod
    def _timestamp_utc(timestamp: float) -> str:
        return WindowsToolBackend._datetime_utc(datetime.fromtimestamp(timestamp, UTC))

    @staticmethod
    def _datetime_utc(value: datetime) -> str:
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    def check_persistence_all(
        self,
        process_path: str = "",
        registry_targets: list[dict[str, Any]] | None = None,
        task_targets: list[dict[str, Any]] | None = None,
        service_targets: list[dict[str, Any]] | None = None,
    ) -> ToolResult:
        if platform.system().lower() != "windows":
            return ToolResult(False, error="check_persistence_all requires a Windows host")
        targeted_registry: list[str] = []
        for target in registry_targets or []:
            if not isinstance(target, dict):
                return ToolResult(False, error="registry target must be an object")
            hive = str(target.get("hive") or "").upper()
            if hive not in {"HKCU", "HKLM"}:
                return ToolResult(False, error=f"unsupported registry hive: {hive}")
            key_path = str(target.get("key_path") or "").strip().lstrip("\\")
            value_name = str(target.get("value_name") or "")
            if not key_path or not value_name:
                return ToolResult(False, error="registry target requires key_path and value_name")
            ps_path = f"{hive}:\\{key_path}"
            targeted_registry.append(
                f"""
$targetPath = {self._ps_sq(ps_path)}
$targetName = {self._ps_sq(value_name)}
if (Test-Path -LiteralPath $targetPath -ErrorAction Stop) {{
  $targetProps = Get-ItemProperty -LiteralPath $targetPath -Name $targetName -ErrorAction SilentlyContinue
  if ($null -ne $targetProps) {{
    $targetReg += [PSCustomObject]@{{
      hive = {self._ps_sq(hive)}
      key_path = {self._ps_sq(key_path)}
      value_name = $targetName
      value_data = "$($targetProps.$targetName)"
    }}
  }}
}}
"""
            )
        targeted_tasks: list[str] = []
        for target in task_targets or []:
            if not isinstance(target, dict):
                return ToolResult(False, error="task target must be an object")
            name = str(target.get("task_name") or target.get("name") or "").strip()
            task_path = str(target.get("task_path") or "\\")
            if not name:
                return ToolResult(False, error="task target requires task_name")
            targeted_tasks.append(
                f"""
$targetTask = Get-ScheduledTask -TaskName {self._ps_sq(name)} -TaskPath {self._ps_sq(task_path)} -ErrorAction SilentlyContinue
if ($null -ne $targetTask) {{
  $targetTasks += [PSCustomObject]@{{
    name = $targetTask.TaskName
    path = $targetTask.TaskPath
    actions = @($targetTask.Actions | ForEach-Object {{ "$($_.Execute) $($_.Arguments)" }})
  }}
}}
"""
            )
        targeted_services: list[str] = []
        for target in service_targets or []:
            if not isinstance(target, dict):
                return ToolResult(False, error="service target must be an object")
            name = str(target.get("service_name") or target.get("name") or "").strip()
            if not name:
                return ToolResult(False, error="service target requires service_name")
            targeted_services.append(
                f"""
$targetService = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {{ $_.Name -eq {self._ps_sq(name)} }}
if ($null -ne $targetService) {{
  $targetServices += [PSCustomObject]@{{
    name = $targetService.Name
    display_name = $targetService.DisplayName
    path = $targetService.PathName
    state = $targetService.State
  }}
}}
"""
            )
        script = """
$reg = @()
foreach ($p in @(
  "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
  "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
)) {
  $props = if (Test-Path -Path $p -ErrorAction Stop) { Get-ItemProperty -Path $p -ErrorAction Stop } else { $null }
  if ($props) {
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      $reg += [PSCustomObject]@{ path=$p; name=$_.Name; value="$($_.Value)" }
    }
  }
}
$tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
  $_.TaskPath -notlike "\\Microsoft\\*"
} | ForEach-Object {
  [PSCustomObject]@{ name=$_.TaskName; path=$_.TaskPath; actions=@($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) }
} | Where-Object { $_ -and $_.name })
$services = Get-CimInstance Win32_Service -Filter "StartMode = 'Auto'" -ErrorAction Stop | Where-Object {
  $_.PathName -and $_.PathName -notlike "C:\\Windows\\System32*" -and $_.PathName -notmatch "svchost"
} | ForEach-Object {
  [PSCustomObject]@{ name=$_.Name; display_name=$_.DisplayName; path=$_.PathName; state=$_.State }
}
$targetReg = @()
""" + "\n".join(targeted_registry) + """
$targetTasks = @()
""" + "\n".join(targeted_tasks) + """
$targetServices = @()
""" + "\n".join(targeted_services) + """
ConvertTo-Json -Depth 5 @{
  registry_run_keys=@($reg)
  scheduled_tasks=@($tasks)
  services=@($services)
  registry_values=@($targetReg)
  targeted_tasks=@($targetTasks)
  targeted_services=@($targetServices)
}
"""
        return self._run_ps_json(
            script,
            default={
                "registry_run_keys": [],
                "scheduled_tasks": [],
                "services": [],
                "registry_values": [],
                "targeted_tasks": [],
                "targeted_services": [],
            },
        )

    def check_powershell_history(self, pattern: str = "", max_lines: int = 80) -> ToolResult:
        if platform.system().lower() != "windows":
            return ToolResult(False, error="check_powershell_history requires a Windows host")
        script = f"""
$pattern = {self._ps_sq(pattern)}
$maxLines = {int(max_lines)}
$paths = @(
    "$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
    "$env:USERPROFILE\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
) | Select-Object -Unique
$items = @()
foreach ($path in $paths) {{
    if (Test-Path -LiteralPath $path) {{
        $lines = Get-Content -LiteralPath $path -ErrorAction Stop | Select-Object -Last $maxLines
        $index = 0
        foreach ($line in $lines) {{
            $index += 1
            if (-not $pattern -or $line -like "*$pattern*") {{
                $items += [PSCustomObject]@{{ path = $path; line_number = $index; command = $line }}
            }}
        }}
    }}
}}
ConvertTo-Json -Depth 4 @{{ history = @($items) }}
"""
        return self._run_ps_json(script, default={"history": []})

    def check_dns_cache(self, domain_filter: str = "") -> ToolResult:
        if platform.system().lower() != "windows":
            return ToolResult(False, error="check_dns_cache requires a Windows host")
        variables = ""
        where = ""
        if domain_filter:
            variables = f"$domainFilter = {self._ps_sq(domain_filter)}\n"
            where = ' | Where-Object { $_.Entry -like "*$domainFilter*" }'
        script = f"""
{variables}
$items = Get-DnsClientCache -ErrorAction Stop{where} | ForEach-Object {{
    [PSCustomObject]@{{ name = $_.Entry; type = $_.Type; data = $_.Data; ttl = $_.TimeToLive }}
}}
ConvertTo-Json -Depth 4 @{{ entries = @($items) }}
"""
        result = self._run_ps_json(script, default={"entries": []})
        if result.success and isinstance(result.data, dict):
            entries = result.data.get("entries", [])
            if isinstance(entries, list):
                filtered = [
                    e for e in entries
                    if isinstance(e, dict)
                    and not _is_benign_dns_entry(e.get("name", ""))
                ]
                result.data["entries"] = filtered
        return result

    def verify_cleanup(
        self,
        remote_ip: str = "",
        remote_port: str | int = "",
        file_path: str = "",
        process_name: str = "",
        pid: int = 0,
        local_port: str | int = "",
        response_actions: list[dict[str, Any]] | None = None,
    ) -> ToolResult:
        errors: list[str] = []
        network: Any = {}
        network_checked = False
        network_clean = False
        if not remote_ip:
            errors.append("network verification requires an exact remote_ip")
        else:
            network_result = self.check_network(
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=local_port,
            )
            if not network_result.success:
                errors.append(f"network verification failed: {network_result.error or 'unknown error'}")
            else:
                network = network_result.data
                network_checked = True
                connections = network.get("connections") if isinstance(network, dict) else None
                if not isinstance(connections, list):
                    errors.append("network verification returned no explicit connections list")
                else:
                    network_clean = not connections

        actions = [item for item in (response_actions or []) if isinstance(item, dict)]
        if not actions:
            if pid or process_name:
                actions.append({"result_id": "", "tool": "kill_process", "arguments": {"pid": pid, "process_name": process_name}})
            if file_path:
                actions.append({"result_id": "", "tool": "remove_file", "arguments": {"file_path": file_path}})

        persistence_tools = {"remove_registry", "remove_scheduled_task", "remove_service"}
        persistence: Any = {}
        persistence_checked = False
        if any(str(item.get("tool") or "") in persistence_tools for item in actions):
            persistence_result = self.check_persistence_all()
            if not persistence_result.success:
                errors.append(f"persistence verification failed: {persistence_result.error or 'unknown error'}")
            elif not isinstance(persistence_result.data, dict):
                errors.append("persistence verification returned malformed data")
            else:
                persistence = persistence_result.data
                persistence_checked = True

        action_checks: list[dict[str, Any]] = []
        all_processes: list[dict[str, Any]] = []
        legacy_file_exists: bool | None = None
        for action in actions:
            tool = str(action.get("tool") or "")
            result_id = str(action.get("result_id") or "")
            arguments = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
            check: dict[str, Any] = {
                "response_result_id": result_id,
                "tool": tool,
                "arguments": dict(arguments),
                "checked": False,
                "clean": False,
            }
            if tool == "kill_process":
                target_pid = int(arguments.get("pid") or 0)
                target_name = str(arguments.get("process_name") or "")
                if not (target_pid or target_name):
                    errors.append(f"process verification target missing for response {result_id or '<legacy>'}")
                else:
                    process_result = self.check_process(pid=target_pid, process_name=target_name)
                    if not process_result.success:
                        errors.append(f"process verification failed: {process_result.error or 'unknown error'}")
                    elif not isinstance(process_result.data, dict) or not isinstance(process_result.data.get("processes"), list):
                        errors.append("process verification returned no explicit processes list")
                    else:
                        processes = [item for item in process_result.data["processes"] if isinstance(item, dict)]
                        all_processes.extend(processes)
                        check.update(checked=True, clean=not processes)
            elif tool == "remove_file":
                target_path = str(arguments.get("file_path") or "")
                if not target_path:
                    errors.append(f"file verification target missing for response {result_id or '<legacy>'}")
                else:
                    file_result = self.check_file_metadata(file_path=target_path)
                    file_data = file_result.data.get("file") if file_result.success and isinstance(file_result.data, dict) else None
                    if not file_result.success:
                        errors.append(f"file verification failed: {file_result.error or 'unknown error'}")
                    elif not isinstance(file_data, dict) or not isinstance(file_data.get("exists"), bool):
                        errors.append("file verification returned no explicit exists flag")
                    else:
                        legacy_file_exists = bool(file_data["exists"])
                        check.update(checked=True, clean=not legacy_file_exists)
            elif tool in persistence_tools:
                if not persistence_checked:
                    # The failed/malformed persistence query is already in errors.
                    pass
                elif not self._valid_persistence_target(tool, arguments):
                    errors.append(f"persistence verification target missing for response {result_id or '<legacy>'}")
                else:
                    check.update(
                        checked=True,
                        clean=not self._persistence_target_present(persistence, tool, arguments),
                    )
            else:
                errors.append(f"unsupported response action in verification: {tool or '<empty>'}")
            action_checks.append(check)

        return ToolResult(not errors, data={
            "network": network,
            "network_checked": network_checked,
            "network_clean": network_clean,
            "file_exists": legacy_file_exists,
            "processes": all_processes,
            "persistence": persistence,
            "persistence_checked": persistence_checked,
            "action_checks": action_checks,
        }, error="; ".join(errors) or None)

    def kill_process(self, process_name: str = "", pid: int = 0, expected_path: str = "") -> ToolResult:
        denied = self._consume_response_authorization(
            "kill_process",
            {"process_name": process_name, "pid": pid, "expected_path": expected_path},
        )
        if denied:
            return denied
        script = f"""
$pidValue = {int(pid)}
$processName = {self._ps_sq(process_name.removesuffix(".exe"))}
$expectedPath = {self._ps_sq(expected_path)}
if ($pidValue) {{
    $procs = @(Get-CimInstance Win32_Process -Filter "ProcessId = $pidValue" -ErrorAction SilentlyContinue)
}} elseif ($processName) {{
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -eq "$processName.exe" -or $_.Name -eq $processName }})
}} else {{
    throw "pid or process_name required"
}}
if ($expectedPath) {{
    $procs = @($procs | Where-Object {{ $_.ExecutablePath -and ($_.ExecutablePath -ieq $expectedPath) }})
}}
if ($procs.Count -ne 1) {{
    throw "kill_process requires exactly one matching process; found $($procs.Count)"
}}
$target = $procs[0]
Stop-Process -Id $target.ProcessId -Force -ErrorAction Stop
ConvertTo-Json @{{ killed=$true; pid=$target.ProcessId; process_name=$target.Name; path=$target.ExecutablePath }}
"""
        return self._run_ps_json(script, default={"killed": False})

    def remove_file(self, file_path: str) -> ToolResult:
        denied = self._consume_response_authorization("remove_file", {"file_path": file_path})
        if denied:
            return denied
        script = f"""
$path = {self._ps_sq(file_path)}
$existed = Test-Path -LiteralPath $path
if ($existed) {{
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
}}
ConvertTo-Json @{{ removed=$existed; file_path=$path; existed=$existed }}
"""
        return self._run_ps_json(script, default={"removed": False})

    def remove_registry(self, reg_path: str, value_name: str, expected_value: str = "") -> ToolResult:
        denied = self._consume_response_authorization(
            "remove_registry",
            {"reg_path": reg_path, "value_name": value_name, "expected_value": expected_value},
        )
        if denied:
            return denied
        script = f"""
$regPath = {self._ps_sq(reg_path)}
$valueName = {self._ps_sq(value_name)}
$expectedValue = {self._ps_sq(expected_value)}
$props = Get-ItemProperty -Path $regPath -ErrorAction Stop
$current = "$($props.$valueName)"
if ($expectedValue -and $current -ne $expectedValue) {{
    throw "registry value mismatch"
}}
Remove-ItemProperty -Path $regPath -Name $valueName -Force -ErrorAction Stop
ConvertTo-Json @{{ removed=$true; reg_path=$regPath; value_name=$valueName; previous_value=$current }}
"""
        return self._run_ps_json(script, default={"removed": False})

    def remove_scheduled_task(self, task_name: str, task_path: str = "") -> ToolResult:
        denied = self._consume_response_authorization(
            "remove_scheduled_task",
            {"task_name": task_name, "task_path": task_path},
        )
        if denied:
            return denied
        path_arg = f" -TaskPath {self._ps_sq(task_path)}" if task_path else ""
        script = (
            f"Unregister-ScheduledTask -TaskName {self._ps_sq(task_name)}{path_arg} "
            f"-Confirm:$false -ErrorAction Stop; "
            f"ConvertTo-Json @{{ removed=$true; task_name={self._ps_sq(task_name)}; task_path={self._ps_sq(task_path)} }}"
        )
        return self._run_ps_json(script, default={"removed": False})

    def remove_service(self, service_name: str) -> ToolResult:
        denied = self._consume_response_authorization("remove_service", {"service_name": service_name})
        if denied:
            return denied
        script = f"""
$serviceName = {self._ps_sq(service_name)}
$output = & sc.exe delete $serviceName 2>&1
if ($LASTEXITCODE -ne 0) {{
    throw "sc.exe delete failed with exit $LASTEXITCODE: $($output -join ' ')"
}}
ConvertTo-Json @{{ removed=$true; service_name=$serviceName }}
"""
        return self._run_ps_json(script, default={"removed": False})

    @staticmethod
    def _valid_persistence_target(tool: str, arguments: dict[str, Any]) -> bool:
        if tool == "remove_registry":
            return bool(arguments.get("reg_path") and arguments.get("value_name"))
        if tool == "remove_scheduled_task":
            return bool(arguments.get("task_name"))
        if tool == "remove_service":
            return bool(arguments.get("service_name"))
        return False

    @classmethod
    def _persistence_target_present(cls, data: dict[str, Any], tool: str, arguments: dict[str, Any]) -> bool:
        if tool == "remove_registry":
            category = "registry_run_keys"
            expected_name = cls._normalize_text(arguments.get("value_name"))
            expected_path = cls._normalize_path(arguments.get("reg_path"))
        elif tool == "remove_scheduled_task":
            category = "scheduled_tasks"
            expected_name = cls._normalize_text(arguments.get("task_name"))
            expected_path = cls._normalize_path(arguments.get("task_path"))
        else:
            category = "services"
            expected_name = cls._normalize_text(arguments.get("service_name"))
            expected_path = ""
        items = data.get(category) if isinstance(data.get(category), list) else []
        for item in items:
            if not isinstance(item, dict) or cls._normalize_text(item.get("name")) != expected_name:
                continue
            if expected_path and cls._normalize_path(item.get("path")) != expected_path:
                continue
            return True
        return False

    @staticmethod
    def _normalize_text(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _normalize_path(value: Any) -> str:
        return str(value or "").strip().lower().replace("/", "\\").replace("\\\\", "\\")

    def _consume_response_authorization(self, tool: str, params: dict[str, Any]) -> ToolResult | None:
        if not self.execute_response:
            return ToolResult(
                False,
                error="direct destructive invocation is disabled; use run() for an explicit dry-run",
            )
        token = self._active_response_token.get()
        authorization = self._response_authorizations.pop(token, None) if token else None
        if authorization is None:
            return ToolResult(False, error="destructive response requires a valid audit authorization")
        if authorization.tool != tool:
            return ToolResult(False, error="audit authorization tool mismatch")
        if authorization.params_fingerprint != self._params_fingerprint(params):
            return ToolResult(False, error="audit authorization argument mismatch")
        return None

    @staticmethod
    def _params_fingerprint(params: dict[str, Any]) -> str:
        normalized = {
            key: value
            for key, value in params.items()
            if value not in ("", None, 0)
        }
        serialized = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return sha256(serialized.encode("utf-8")).hexdigest()

    def _run_ps_json(self, script: str, *, default: dict[str, Any]) -> ToolResult:
        if platform.system().lower() != "windows":
            return ToolResult(False, error="PowerShell host tools require Windows")
        utf8_script = (
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); "
            "$OutputEncoding = [System.Text.UTF8Encoding]::new(); "
            "$ErrorActionPreference = 'Stop';\n"
            f"{script}"
        )
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", utf8_script],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            text=True,
            timeout=45,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        if completed.returncode != 0:
            detail = stderr.strip() or stdout.strip()
            return ToolResult(False, error=detail or f"exit {completed.returncode}")
        text = stdout.strip()
        if not text:
            return ToolResult(False, error="PowerShell returned no JSON result")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            return ToolResult(False, error=f"invalid PowerShell JSON output: {exc}")
        if not isinstance(parsed, dict):
            return ToolResult(False, error="PowerShell JSON result must be an object")
        return ToolResult(True, data=parsed)

    @staticmethod
    def _ps_sq(value: Any) -> str:
        return "'" + str(value).replace("'", "''") + "'"




_BENIGN_DNS_SUFFIXES = frozenset({
    "api.deepseek.com",
    "chat.openai.com",
    "chatgpt.com",
    "api.openai.com",
    "platform.openai.com",
    "oaiusercontent.com",
    "oss-cn-hangzhou.aliyuncs.com",
    "dashscope.aliyuncs.com",
    "bigmodel.cn",
    "open.bigmodel.cn",
})


def _is_benign_dns_entry(name: str) -> bool:
    lower = str(name or "").strip().casefold()
    if not lower:
        return True
    if lower.endswith(".in-addr.arpa"):
        return True
    for suffix in _BENIGN_DNS_SUFFIXES:
        if lower == suffix or lower.endswith("." + suffix):
            return True
    return False

class SystemToolRunner(WindowsToolBackend):
    """Deprecated compatibility name; production execution uses MCP."""
