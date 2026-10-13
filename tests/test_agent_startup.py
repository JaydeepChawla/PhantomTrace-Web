"""
=====================================================================
PHANTOMTRACE - AGENT WINDOWLESS STARTUP & LIFECYCLE TESTS
=====================================================================
Validates that:
1. PyInstaller specs configure windowless mode (console=False).
2. Logging service safely handles None stdio and captures uncaught errors.
3. Startup banner is preserved in log files.
4. Single-instance mutex prevents duplicate background processes.
5. Lifecycle operations (--stop, --status) function correctly.
=====================================================================
"""

import os
import sys
import unittest
import logging
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "phantomtrace-agent") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "phantomtrace-agent"))

from agent_service.config import HOST, PORT, AGENT_VERSION, LOG_FILE
from agent_service.logging_service import (
    SafeStreamWrapper,
    setup_logger,
    install_exception_hook,
)
from agent_service.main import (
    acquire_single_instance_mutex,
    log_banner,
    check_status,
    stop_agent,
)

class TestAgentStartupAndWindowless(unittest.TestCase):
    def test_specs_configured_windowless(self):
        """Verifies PyInstaller specs have console=False to prevent command prompt window on startup."""
        spec1 = PROJECT_ROOT / "PhantomTraceAgent.spec"
        spec2 = PROJECT_ROOT / "PhantomTrace-Agent.spec"

        self.assertTrue(spec1.is_file(), "PhantomTraceAgent.spec must exist")
        self.assertTrue(spec2.is_file(), "PhantomTrace-Agent.spec must exist")

        content1 = spec1.read_text(encoding="utf-8")
        content2 = spec2.read_text(encoding="utf-8")

        self.assertIn("console=False", content1, "PhantomTraceAgent.spec must specify console=False")
        self.assertIn("console=False", content2, "PhantomTrace-Agent.spec must specify console=False")
        self.assertNotIn("console=True", content1, "PhantomTraceAgent.spec must not have console=True")
        self.assertNotIn("console=True", content2, "PhantomTrace-Agent.spec must not have console=True")

    def test_safe_stream_wrapper_captures_output(self):
        """Verifies SafeStreamWrapper routes writes to logger without failing."""
        mock_logger = MagicMock()
        wrapper = SafeStreamWrapper(mock_logger, logging.INFO)

        wrapper.write("First line\n")
        mock_logger.log.assert_called_with(logging.INFO, "First line")

        wrapper.write("Partial ")
        wrapper.write("message\n")
        mock_logger.log.assert_called_with(logging.INFO, "Partial message")

        wrapper.write("Trailing without newline")
        wrapper.flush()
        mock_logger.log.assert_called_with(logging.INFO, "Trailing without newline")

    def test_exception_hook_logs_critical_error(self):
        """Verifies uncaught exceptions are forwarded to logger.critical to avoid silent suppression."""
        mock_logger = MagicMock()
        install_exception_hook(mock_logger)

        try:
            raise RuntimeError("Test simulation error")
        except RuntimeError:
            exc_type, exc_val, exc_tb = sys.exc_info()
            assert exc_type is not None
            assert exc_val is not None
            sys.excepthook(exc_type, exc_val, exc_tb)

        mock_logger.critical.assert_called_once()
        call_args = mock_logger.critical.call_args
        self.assertIn("Uncaught exception in agent service:", call_args[0][0])

    def test_log_banner_records_essential_info(self):
        """Verifies startup banner writes version, security model, and localhost binding to logs."""
        with patch("agent_service.main.logger") as mock_logger:
            log_banner()
            mock_logger.info.assert_called_once()
            banner_text = mock_logger.info.call_args[0][0]
            self.assertIn(f"PHANTOMTRACE WINDOWS AGENT v{AGENT_VERSION}", banner_text)
            self.assertIn("100% Read-Only Passive Inspection", banner_text)
            self.assertIn(f"http://{HOST}:{PORT}", banner_text)

    def test_single_instance_mutex_prevents_duplicates(self):
        """Verifies single instance mutex detects an already running instance."""
        if sys.platform != "win32":
            self.skipTest("Single instance mutex test is Windows-specific")

        test_mutex_name = "Local\\TestPhantomTraceMutexUnique_12345"
        first_acq = acquire_single_instance_mutex(test_mutex_name)
        self.assertTrue(first_acq, "First acquisition should succeed")

        second_acq = acquire_single_instance_mutex(test_mutex_name)
        self.assertFalse(second_acq, "Second acquisition of the same mutex must fail to prevent duplicates")

    def test_check_status_returns_failure_when_stopped(self):
        """Verifies check_status returns 1 when localhost service is not listening on non-existent port."""
        with patch("agent_service.main.PORT", 59999):
            status = check_status()
            self.assertEqual(status, 1)

    def test_stop_agent_returns_zero(self):
        """Verifies stop_agent executes cleanly."""
        status = stop_agent()
        self.assertEqual(status, 0)

    def test_inno_setup_scripts_disable_startup_by_default(self):
        """Verifies Inno Setup installer scripts permanently remove autostart option and preserve desktop icon and branding."""
        iss_files = [
            PROJECT_ROOT / "installer" / "PhantomTrace_Agent_Setup.iss",
            PROJECT_ROOT / "phantomtrace-agent" / "installer" / "PhantomTrace_Agent_Setup.iss",
        ]

        for iss_file in iss_files:
            self.assertTrue(iss_file.is_file(), f"{iss_file} must exist")
            content = iss_file.read_text(encoding="utf-8")

            # 1. Desktop shortcut enabled by default (no 'Flags: unchecked')
            self.assertRegex(
                content,
                r'Name:\s*"desktopicon";[^\r\n]*GroupDescription:[^\r\n]*(?!Flags:\s*unchecked)',
                f"{iss_file.name} desktopicon task must not have 'Flags: unchecked' (should default to checked)",
            )

            # 2. Autostart task permanently removed from installer [Tasks]
            self.assertNotIn(
                'Name: "autostart"',
                content,
                f"{iss_file.name} must not contain 'autostart' task definition",
            )
            self.assertNotIn(
                'Start PhantomTrace Agent automatically when Windows starts',
                content,
                f"{iss_file.name} must not display automatic startup option to user",
            )
            self.assertNotIn(
                'Startup Options:',
                content,
                f"{iss_file.name} must not contain 'Startup Options:' group",
            )

            # 3. Desktop shortcut created in {autodesktop}
            self.assertIn('{autodesktop}', content, f"{iss_file.name} must define desktop shortcut in {{autodesktop}}")
            self.assertIn('Tasks: desktopicon', content, f"{iss_file.name} desktop icon must link to desktopicon task")

            # 4. Start Menu shortcuts configured
            self.assertIn('{autoprograms}\\PhantomTrace', content, f"{iss_file.name} must define Start Menu group")

            # 5. Startup shortcut permanently removed from [Icons]
            icons_section = content.split('[Icons]')[1].split('[InstallDelete]')[0] if '[Icons]' in content else ""
            self.assertNotIn(
                '{userstartup}',
                icons_section,
                f"{iss_file.name} [Icons] must not create any startup shortcut",
            )
            self.assertNotIn(
                'Tasks: autostart',
                content,
                f"{iss_file.name} must not reference 'Tasks: autostart'",
            )

            # 6. Run section must not auto-execute unconditionally
            self.assertNotIn(
                'Flags: nowait runhidden',
                content,
                f"{iss_file.name} [Run] must not contain 'Flags: nowait runhidden' (unconditional background auto-run)",
            )
            # Postinstall must be unchecked
            self.assertIn(
                'postinstall skipifsilent unchecked',
                content,
                f"{iss_file.name} [Run] must be unchecked postinstall so installer finish does not launch agent automatically",
            )

            # 7. Upgrade cleanup in [InstallDelete] removes stale startup shortcuts unconditionally
            self.assertIn('[InstallDelete]', content, f"{iss_file.name} must have [InstallDelete] section")
            self.assertIn('{userstartup}\\{#MyAppDesktopName}.lnk', content, f"{iss_file.name} must clean user startup shortcut on upgrade")
            self.assertNotIn('Check: not IsAutostartTaskChecked', content, f"{iss_file.name} must not gate startup cleanup on removed task")
            self.assertNotIn('IsAutostartTaskChecked', content, f"{iss_file.name} must not contain IsAutostartTaskChecked")

            # 8. Uninstaller and installer clean up shortcuts and registry run entries
            self.assertIn('[UninstallDelete]', content, f"{iss_file.name} must have [UninstallDelete]")
            self.assertIn('dontcreatekey uninsdeletevalue', content, f"{iss_file.name} must clean Run registry entries on uninstall")
            self.assertIn('deletevalue', content, f"{iss_file.name} must purge legacy Run registry entries on install/upgrade")

            # 9. Tasks section contains only desktopicon
            tasks_section = content.split('[Tasks]')[1].split('[')[0] if '[Tasks]' in content else ""
            task_lines = [line.strip() for line in tasks_section.splitlines() if line.strip() and not line.strip().startswith(';')]
            self.assertEqual(len(task_lines), 1, f"{iss_file.name} must only define desktopicon task in [Tasks]")
            self.assertIn('desktopicon', task_lines[0], f"{iss_file.name} single task must be desktopicon")

            # 10. User data in {localappdata} protected from deletion on uninstall
            self.assertIn('Flags: uninsneveruninstall', content, f"{iss_file.name} must protect user data on uninstall")

            # 11. Official branding configuration
            self.assertIn('SetupIconFile=phantomtrace.ico', content, f"{iss_file.name} must configure official icon")
            self.assertIn('UninstallDisplayIcon={app}\\phantomtrace.ico', content, f"{iss_file.name} must configure uninstaller icon")
            self.assertIn('WizardImageFile=wizard.bmp', content, f"{iss_file.name} must configure wizard branding banner")
            self.assertIn('WizardSmallImageFile=wizardsmall.bmp', content, f"{iss_file.name} must configure wizard header image")

    def test_install_agent_ps1_script_defaults(self):
        """Verifies install_agent.ps1 defaults to stopped state, creates desktop shortcut, and disables startup."""
        ps1_file = PROJECT_ROOT / "phantomtrace-agent" / "installer" / "install_agent.ps1"
        self.assertTrue(ps1_file.is_file(), "install_agent.ps1 must exist")
        content = ps1_file.read_text(encoding="utf-8")

        # 1. StartNow defaults to false
        self.assertIn('[bool]$StartNow = $false', content, "install_agent.ps1 must default $StartNow to $false")

        # 2. EnableAutoStart is removed
        self.assertNotIn('$EnableAutoStart', content, "install_agent.ps1 must not have $EnableAutoStart parameter")

        # 3. Creates Desktop shortcut
        self.assertIn('GetFolderPath("Desktop")', content, "install_agent.ps1 must target user Desktop")
        self.assertIn('PhantomTrace.lnk', content, "install_agent.ps1 must create PhantomTrace.lnk")

        # 4. Creates Start Menu shortcut
        self.assertIn('GetFolderPath("Programs")', content, "install_agent.ps1 must target user Start Menu Programs")

        # 5. Cleans up stale startup shortcuts unconditionally
        self.assertIn('GetFolderPath("Startup")', content, "install_agent.ps1 must inspect Startup folder")
        self.assertIn('Remove-Item -Path $startupLnk', content, "install_agent.ps1 must remove startup shortcut")
        self.assertIn('Remove-Item -Path $legacyStartupLnk', content, "install_agent.ps1 must remove legacy startup shortcut")

    def test_uninstall_agent_ps1_preserves_data(self):
        """Verifies uninstall_agent.ps1 removes shortcuts and preserves user data by default."""
        uninst_file = PROJECT_ROOT / "phantomtrace-agent" / "installer" / "uninstall_agent.ps1"
        self.assertTrue(uninst_file.is_file(), "uninstall_agent.ps1 must exist")
        content = uninst_file.read_text(encoding="utf-8")

        self.assertIn('Stop-Process', content, "uninstall_agent.ps1 must terminate active processes")
        self.assertIn('Remove-Item', content, "uninstall_agent.ps1 must clean up shortcuts")
        self.assertIn('PurgeUserData', content, "uninstall_agent.ps1 must require explicit PurgeUserData to delete scans")

    def test_autostart_manager_module(self):
        """Verifies autostart manager logic and default state."""
        from agent_service.autostart import (
            is_autostart_enabled,
            get_autostart_info,
            get_startup_folder,
            disable_autostart,
        )

        info = get_autostart_info()
        self.assertFalse(info["default"], "Auto-start default must be False")
        self.assertIn("disabled", info["status"], "Initial status should reflect disabled state")
        self.assertTrue(isinstance(get_startup_folder(), Path))

        # Disable autostart should cleanly succeed
        success, msg = disable_autostart()
        self.assertTrue(success)

    def test_cli_autostart_arguments_registered(self):
        """Verifies that main.py CLI argument parser includes startup management flags."""
        main_file = PROJECT_ROOT / "phantomtrace-agent" / "agent_service" / "main.py"
        content = main_file.read_text(encoding="utf-8")

        self.assertIn("--enable-autostart", content, "main.py must support --enable-autostart")
        self.assertIn("--disable-autostart", content, "main.py must support --disable-autostart")
        self.assertIn("--autostart-status", content, "main.py must support --autostart-status")

    def test_local_api_autostart_route_registered(self):
        """Verifies local API supports GET and POST /api/autostart."""
        api_file = PROJECT_ROOT / "phantomtrace-agent" / "agent_service" / "local_api.py"
        content = api_file.read_text(encoding="utf-8")

        self.assertIn('/api/autostart', content, "local_api.py must handle /api/autostart")
        self.assertIn('autostartEnabled', content, "local_api.py status must report autostartEnabled")

if __name__ == "__main__":
    unittest.main()
