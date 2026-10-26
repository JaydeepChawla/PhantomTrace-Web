"""
=====================================================================
PHANTOMTRACE WINDOWS AGENT - AUTOSTART CONFIGURATION MANAGER
=====================================================================
Manages optional Windows Startup configuration for PhantomTrace Agent.

GUARANTEES:
1. Disabled by default. Zero automatic startup entries on default install.
2. Explicit user opt-in only.
3. Clean removal when toggled off or during uninstallation.
4. Safe cross-platform fallbacks for test environments.
=====================================================================
"""

import os
import sys
import subprocess
from pathlib import Path
from typing import Tuple, Dict, Any, Optional

from .logging_service import logger

STARTUP_SHORTCUT_NAME = "PhantomTrace.lnk"
LEGACY_SHORTCUT_NAME = "PhantomTrace Windows Agent.lnk"
REGISTRY_RUN_KEYS = ["PhantomTrace", "PhantomTraceAgent", "PhantomTrace Windows Agent"]

def get_startup_folder() -> Path:
    """Returns the current Windows user's Startup directory."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    return Path.home() / ".config" / "autostart"

def get_startup_shortcut_path() -> Path:
    """Returns the canonical path to the PhantomTrace Startup shortcut."""
    return get_startup_folder() / STARTUP_SHORTCUT_NAME

def is_autostart_enabled() -> bool:
    """Checks whether automatic Windows startup is currently configured."""
    if sys.platform != "win32":
        return False

    startup_dir = get_startup_folder()
    # 1. Check Startup folder shortcuts
    if (startup_dir / STARTUP_SHORTCUT_NAME).is_file():
        return True
    if (startup_dir / LEGACY_SHORTCUT_NAME).is_file():
        return True

    # 2. Check Registry Run keys
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_READ
        ) as key:
            for val_name in REGISTRY_RUN_KEYS:
                try:
                    val, _ = winreg.QueryValueEx(key, val_name)
                    if val:
                        return True
                except FileNotFoundError:
                    continue
    except Exception:
        pass

    return False

def enable_autostart(target_path: Optional[str] = None) -> Tuple[bool, str]:
    """
    Explicitly enables automatic Windows startup.
    Creates a shortcut in the current user's Startup folder.
    """
    if sys.platform != "win32":
        return False, "Automatic Windows startup is only supported on Windows."

    startup_dir = get_startup_folder()
    try:
        startup_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return False, f"Could not create startup directory: {e}"

    shortcut_file = startup_dir / STARTUP_SHORTCUT_NAME

    if not target_path:
        if getattr(sys, "frozen", False):
            target_path = sys.executable
        else:
            # Check for start_agent.bat in LOCALAPPDATA
            local_appdata = os.environ.get("LOCALAPPDATA", "")
            bat_candidate = Path(local_appdata) / "PhantomTraceAgent" / "start_agent.bat"
            if bat_candidate.is_file():
                target_path = str(bat_candidate)
            else:
                target_path = sys.executable

    work_dir = str(Path(target_path).parent)
    logger.info(f"Configuring automatic startup shortcut at: {shortcut_file} -> {target_path}")

    # Use PowerShell COM WScript.Shell to create valid Windows .lnk shortcut
    ps_cmd = (
        f"$ws = New-Object -ComObject WScript.Shell; "
        f"$s = $ws.CreateShortcut('{shortcut_file}'); "
        f"$s.TargetPath = '{target_path}'; "
        f"$s.WorkingDirectory = '{work_dir}'; "
        f"$s.Description = 'Launch PhantomTrace Windows Agent'; "
        f"$s.Save()"
    )
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        res = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            creationflags=flags
        )
        if res.returncode == 0 and shortcut_file.is_file():
            msg = f"Automatic startup enabled. Shortcut created: {shortcut_file}"
            logger.info(msg)
            return True, msg
        else:
            err = res.stderr.strip() or f"Process exited with code {res.returncode}"
            logger.warning(f"Failed to create startup shortcut: {err}")
            return False, f"Failed to create startup shortcut: {err}"
    except Exception as e:
        logger.error(f"Error configuring automatic startup: {e}")
        return False, str(e)

def disable_autostart() -> Tuple[bool, str]:
    """
    Explicitly disables automatic Windows startup.
    Removes Startup folder shortcuts and any Registry Run entries.
    """
    if sys.platform != "win32":
        return True, "Disabled (non-Windows platform)."

    removed_items = []
    startup_dir = get_startup_folder()

    # 1. Clean Startup folder shortcuts
    for name in [STARTUP_SHORTCUT_NAME, LEGACY_SHORTCUT_NAME]:
        path = startup_dir / name
        if path.is_file():
            try:
                path.unlink()
                removed_items.append(str(path))
            except Exception as e:
                logger.warning(f"Could not remove startup shortcut {path}: {e}")

    # 2. Clean Registry Run keys if present
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        ) as key:
            for val_name in REGISTRY_RUN_KEYS:
                try:
                    winreg.DeleteValue(key, val_name)
                    removed_items.append(f"HKCU\\Run\\{val_name}")
                except FileNotFoundError:
                    continue
                except Exception as e:
                    logger.warning(f"Could not remove registry key {val_name}: {e}")
    except Exception:
        pass

    msg = "Automatic Windows startup is disabled."
    if removed_items:
        msg += f" Removed: {', '.join(removed_items)}"
    logger.info(msg)
    return True, msg

def get_autostart_info() -> Dict[str, Any]:
    """Returns detailed startup configuration state."""
    enabled = is_autostart_enabled()
    return {
        "enabled": enabled,
        "default": False,
        "mechanism": "Startup Folder Shortcut / Registry Run Key",
        "shortcutPath": str(get_startup_shortcut_path()),
        "status": "enabled" if enabled else "disabled",
        "message": (
            "Automatic startup is disabled by default. PhantomTrace runs only when launched explicitly."
            if not enabled
            else "Automatic startup is enabled. PhantomTrace will launch when the Windows user logs in."
        )
    }
