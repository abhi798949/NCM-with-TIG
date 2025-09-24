from __future__ import annotations
from typing import Optional, Dict, Any
from netmiko import ConnectHandler
from netmiko.scp_functions import file_transfer
import os


def xr_restore_config(
    host: str,
    username: str,
    password: str,
    *,
    method: str,                             # 'file' or 'rollback'
    # --- file/merge/replace options ---
    local_file: Optional[str] = None,        # path to local config file (optional)
    remote_filename: Optional[str] = None,   # e.g. 'restore.cfg' on the device
    file_system: str = "disk0:",             # e.g. 'disk0:' | 'bootflash:' | 'harddisk:'
    replace: bool = False,                   # True -> 'commit replace'
    commit_label: str = "",                  # label for normal (merge) commit
    commit_comment: str = "",                # comment for normal (merge) commit
    confirm_delay: Optional[int] = None,     # seconds for 'commit confirmed'
    # --- rollback options ---
    rollback_to: Optional[str] = None,       # numeric commit ID, e.g. '1000000042'
    rollback_last: Optional[int] = None,     # rollback last N commits
    # --- connection options ---
    port: int = 22,
    fast_cli: bool = True,
    session_log: Optional[str] = None,       # path to capture full session if desired
) -> Dict[str, Any]:
    """
    Restore IOS XR configuration via Netmiko.

    method='file':
        - If local_file is given, SCP it to <file_system>:<remote_filename or basename(local_file)>
        - load <file_system:filename> into target config
        - commit (merge) or 'commit replace' (full replace)

    method='rollback':
        - 'rollback configuration to <commit-id>' OR 'rollback configuration last <N>'

    Returns dict with keys: ok(bool), method(str), log(str), result(str), remote_file(str)
    """
    device = {
        "device_type": "cisco_xr",
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "fast_cli": fast_cli,
    }
    if session_log:
        device["session_log"] = session_log

    conn = ConnectHandler(**device)
    logs = []

    try:
        if method == "file":
            if not (local_file or remote_filename):
                raise ValueError("Provide local_file and/or remote_filename for method='file'.")

            dest_name = remote_filename or os.path.basename(local_file)  # filename on device
            remote_ref_for_load = f"{file_system}{dest_name}"             # e.g. 'disk0:restore.cfg'

            # 1) Optional SCP of the file to the device
            if local_file:
                xfer = file_transfer(
                    conn,
                    source_file=local_file,
                    dest_file=dest_name,
                    file_system=file_system,
                    direction="put",
                    verify_file=True,
                    overwrite_file=True,
                )
                logs.append(f"SCP result: {xfer}")

            # 2) Load the file into the target config
            conn.config_mode()
            out = conn.send_command(
                f"load {remote_ref_for_load}",
                expect_string=r"[)#]",
                strip_prompt=False,
                strip_command=False,
            )
            logs.append(out)

            # 3) Commit
            if replace:
                # Full replace: this will prompt "Do you wish to proceed? [no]"
                out = conn.send_command_timing("commit replace")
                if ("proceed" in out.lower()) or ("confirm" in out.lower()):
                    out += conn.send_command_timing("y")
                logs.append(out)
            else:
                # Merge commit with optional label/comment/confirmed timer
                out = conn.commit(
                    confirm=bool(confirm_delay),
                    confirm_delay=confirm_delay,
                    label=commit_label or "",
                    comment=commit_comment or "",
                )
                logs.append(out)

            # Exit config mode
            conn.exit_config_mode()
            return {
                "ok": True,
                "method": "file",
                "remote_file": remote_ref_for_load,
                "log": "\n".join(logs),
                "result": out,
            }

        elif method == "rollback":
            # Ensure EXEC mode, then perform rollback (auto-commits)
            conn.exit_config_mode()
            if rollback_to:
                cmd = f"rollback configuration to {rollback_to}"
            elif rollback_last is not None:
                cmd = f"rollback configuration last {int(rollback_last)}"
            else:
                raise ValueError("For method='rollback', set rollback_to=<commit-id> or rollback_last=<N>.")

            out = conn.send_command(
                cmd, expect_string=r"#", strip_prompt=False, strip_command=False
            )
            logs.append(out)
            return {"ok": True, "method": "rollback", "log": "\n".join(logs), "result": out}

        else:
            raise ValueError("method must be 'file' or 'rollback'.")

    finally:
        conn.disconnect()
