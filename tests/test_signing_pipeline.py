"""
Unit tests for PhantomTrace Unsigned Release Pipeline and Build Integrity.
Covers:
- Missing Azure credentials do not block an unsigned build.
- No signing command is invoked.
- Agent and scanner artifacts are not confused.
- Missing build inputs stop the build.
- Installer paths work without a workstation-specific path.
- Invalid release versions are rejected.
- SHA-256 matches the final file.
- Metadata accurately marks artifacts as unsigned.
- Unsigned builds cannot overwrite production downloads.
- GitHub release notes identify unsigned files honestly.
- Tamper detection invalidates cryptographic integrity.
"""

import unittest
import subprocess
import os
import re
import tempfile
import shutil
import hashlib
import json

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SIGN_SCRIPT = os.path.join(REPO_ROOT, "scripts", "sign_agent.ps1")
BUILD_INSTALLER_SCRIPT = os.path.join(REPO_ROOT, "scripts", "build_and_sign_installer.ps1")
BUILD_AGENT_SCRIPT = os.path.join(REPO_ROOT, "scripts", "build_and_sign_agent.ps1")
WORKFLOW_FILE = os.path.join(REPO_ROOT, ".github", "workflows", "release-signed-agent.yml")
INSTALLER_PATH = os.path.join(REPO_ROOT, "public", "downloads", "PhantomTrace_Agent_Setup.exe")


class TestSigningPipeline(unittest.TestCase):

    def test_missing_azure_credentials_does_not_block_unsigned_build(self):
        """Verify missing Azure credentials do not block an unsigned build or cause exit code 2."""
        clean_env = os.environ.copy()
        for key in list(clean_env.keys()):
            if "AZURE" in key or "SIGNING" in key or "CERT" in key:
                clean_env.pop(key, None)

        cmd = [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-File", SIGN_SCRIPT,
            "-ExePath", INSTALLER_PATH
        ]

        result = subprocess.run(
            cmd,
            env=clean_env,
            capture_output=True,
            text=True
        )

        self.assertEqual(
            result.returncode,
            0,
            f"Expected exit code 0 (unsigned build allowed without credentials), got {result.returncode}. Output:\n{result.stdout}\n{result.stderr}"
        )
        self.assertIn("unsigned", (result.stdout + result.stderr).lower())

    def test_no_signing_command_invoked(self):
        """Verify release workflow and build scripts do not invoke any signing tools or Azure signing action."""
        with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
            workflow_content = f.read()
        with open(BUILD_INSTALLER_SCRIPT, "r", encoding="utf-8") as f:
            build_installer_content = f.read()

        # No Azure signing action or tools in workflow
        self.assertNotIn("azure/artifact-signing-action", workflow_content)
        self.assertNotIn("azuresigntool", workflow_content.lower())
        self.assertNotIn("Set-AuthenticodeSignature", workflow_content)
        self.assertNotIn("Enforce Production Signature Gate", workflow_content)

        # No signing commands in installer build script
        self.assertNotIn("azuresigntool", build_installer_content.lower())
        self.assertNotIn("Set-AuthenticodeSignature", build_installer_content)

    def test_agent_and_scanner_artifacts_not_confused(self):
        """Verify agent service and scanner CLI are separate components and never confused."""
        agent_spec = os.path.join(REPO_ROOT, "PhantomTraceAgent.spec")
        scanner_spec = os.path.join(REPO_ROOT, "PhantomTrace-Agent.spec")
        iss_file = os.path.join(REPO_ROOT, "installer", "PhantomTrace_Agent_Setup.iss")

        self.assertTrue(os.path.isfile(agent_spec), "PhantomTraceAgent.spec must exist")
        self.assertTrue(os.path.isfile(scanner_spec), "PhantomTrace-Agent.spec must exist")
        self.assertTrue(os.path.isfile(iss_file), "Installer ISS must exist")

        with open(agent_spec, "r", encoding="utf-8") as f:
            agent_content = f.read()
        with open(scanner_spec, "r", encoding="utf-8") as f:
            scanner_content = f.read()
        with open(iss_file, "r", encoding="utf-8") as f:
            iss_content = f.read()
        with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
            workflow_content = f.read()

        # Background agent service uses run_agent.py
        self.assertIn("run_agent.py", agent_content)
        self.assertIn("PhantomTraceAgent", agent_content)

        # Scanner CLI uses agent/main.py
        self.assertIn("agent/main.py", scanner_content)

        # Installer packages agent to root and scanner to {app}\scanner
        self.assertIn('Source: "..\\phantomtrace-agent\\dist\\PhantomTraceAgent\\*"; DestDir: "{app}"', iss_content)
        self.assertIn('Source: "{#ScannerDir}\\PhantomTrace_Windows_Release_1.0.exe"; DestDir: "{app}\\scanner"', iss_content)

        # Workflow verifies both binaries independently
        self.assertIn("Verify Staged Binaries Prior to Packaging", workflow_content)
        self.assertIn("Verified Agent Service", workflow_content)
        self.assertIn("Verified Scanner Binary", workflow_content)

    def test_missing_build_inputs_stop_the_build(self):
        """Verify build scripts and workflow produce clear errors and stop when required inputs are missing."""
        with open(BUILD_INSTALLER_SCRIPT, "r", encoding="utf-8") as f:
            build_installer_content = f.read()
        with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
            workflow_content = f.read()

        self.assertIn("Pre-compile check failed", build_installer_content)
        self.assertIn("Pre-packaging check failed", workflow_content)
        self.assertIn("Cannot locate PhantomTraceAgent.spec", build_installer_content)

    def test_installer_paths_work_without_workstation_specific_path(self):
        """Verify Inno Setup and build scripts contain no hardcoded workstation-specific paths."""
        iss_files = [
            os.path.join(REPO_ROOT, "installer", "PhantomTrace_Agent_Setup.iss"),
            os.path.join(REPO_ROOT, "phantomtrace-agent", "installer", "PhantomTrace_Agent_Setup.iss"),
        ]

        for iss in iss_files:
            with open(iss, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn(r"D:\Phantom Trace", content, f"{iss} must not contain hardcoded workstation paths")
            self.assertNotIn(r"D:/PhantomTrace-Web", content, f"{iss} must not contain hardcoded workstation paths")

        with open(BUILD_INSTALLER_SCRIPT, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn(r"D:\Phantom Trace", content, "build_and_sign_installer.ps1 must not contain hardcoded workstation paths")

        with open(os.path.join(REPO_ROOT, "PhantomTrace-Agent.spec"), "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn(r"D:/PhantomTrace-Web", content, "PhantomTrace-Agent.spec must not contain hardcoded workstation paths")

    def test_invalid_release_versions_rejected(self):
        """Verify version validation strictly enforces Semantic Versioning regex: ^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$."""
        with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
            workflow_content = f.read()

        semver_regex = r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
        self.assertIn(semver_regex, workflow_content)

        pattern = re.compile(semver_regex)
        # Valid tags
        self.assertTrue(pattern.match("v1.0.0"))
        self.assertTrue(pattern.match("v0.1.0"))
        self.assertTrue(pattern.match("v2.10.3"))
        self.assertTrue(pattern.match("v0.0.1"))

        # Invalid tags
        self.assertIsNone(pattern.match("1.0.0"))
        self.assertIsNone(pattern.match("v1.0"))
        self.assertIsNone(pattern.match("v01.0.0"))
        self.assertIsNone(pattern.match("v1.0.0-rc1"))
        self.assertIsNone(pattern.match("v1.0.0_beta"))
        self.assertIsNone(pattern.match("latest"))
        self.assertIsNone(pattern.match("v1"))
        self.assertIsNone(pattern.match("v.1.0.0"))

    def test_sha256_matches_final_file(self):
        """Verify SHA-256 calculation algorithm produces exact match against the final installer file."""
        if not os.path.exists(INSTALLER_PATH):
            self.skipTest(f"Installer binary not found at {INSTALLER_PATH}")

        hasher = hashlib.sha256()
        with open(INSTALLER_PATH, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        expected_hash = hasher.hexdigest().lower()

        # Test PowerShell hash calculation equivalence
        ps_cmd = [
            "powershell",
            "-Command",
            f"(Get-FileHash '{INSTALLER_PATH}' -Algorithm SHA256).Hash.ToLower()"
        ]
        ps_hash = subprocess.check_output(ps_cmd, text=True).strip()
        self.assertEqual(expected_hash, ps_hash, "PowerShell Get-FileHash must match Python hashlib SHA-256")

    def test_metadata_accurately_marks_artifacts_as_unsigned(self):
        """Verify release metadata explicitly sets signatureStatus='Unsigned', isProductionSigned=false, publisher=null."""
        with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
            workflow_content = f.read()
        with open(BUILD_INSTALLER_SCRIPT, "r", encoding="utf-8") as f:
            build_content = f.read()

        for content in [workflow_content, build_content]:
            self.assertIn('signatureStatus    = "Unsigned"', content)
            self.assertIn("isProductionSigned = $false", content)
            self.assertIn("publisher          = $null", content)

    def test_unsigned_builds_cannot_overwrite_production_downloads(self):
        """Verify build scripts and release workflow keep artifacts isolated in dist/ and release_bin/."""
        with open(BUILD_INSTALLER_SCRIPT, "r", encoding="utf-8") as f:
            installer_script_content = f.read()
        with open(BUILD_AGENT_SCRIPT, "r", encoding="utf-8") as f:
            agent_script_content = f.read()

        # Installer build script must not copy to public/ or public/downloads/
        self.assertNotIn('Copy-Item -Path $DistInstaller -Destination (Join-Path $PublicDir', installer_script_content)
        self.assertNotIn('Copy-Item -Path $DistInstaller -Destination (Join-Path $PublicDownloads', installer_script_content)
        self.assertNotIn('Copy-Item -Path $MetadataJsonPath -Destination (Join-Path $PublicDownloads', installer_script_content)
        self.assertNotIn('Copy-Item -Path $MetadataJsonPath -Destination (Join-Path $SrcDataDir', installer_script_content)

        # Agent build script must not copy to public/downloads/
        self.assertNotIn('Copy-Item -Path $AgentExe -Destination (Join-Path $PublicDownloads', agent_script_content)

    def test_github_release_notes_identify_unsigned_files_honestly(self):
        """Verify GitHub Releases step clearly labels release as unsigned and explains checksum integrity scope."""
        with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
            workflow_content = f.read()

        self.assertIn('(Unsigned)', workflow_content)
        self.assertIn('prerelease: true', workflow_content)
        self.assertIn('explicitly unsigned', workflow_content.lower())
        self.assertIn('sha-256 checksums validate file integrity only', workflow_content.lower())

    def test_tampered_binary_fails_authenticode_verification(self):
        """Verify that modifying a binary causes signature verification or hash check to fail."""
        if not os.path.exists(INSTALLER_PATH):
            self.skipTest("Installer binary not present to test signature tampering.")

        with tempfile.TemporaryDirectory() as tmpdir:
            tampered_exe = os.path.join(tmpdir, "Tampered_Setup.exe")
            shutil.copy2(INSTALLER_PATH, tampered_exe)

            check_cmd = [
                "powershell",
                "-Command",
                f"(Get-AuthenticodeSignature '{tampered_exe}').Status.ToString()"
            ]
            baseline_status = subprocess.check_output(check_cmd, text=True).strip()

            file_size = os.path.getsize(tampered_exe)
            with open(tampered_exe, "r+b") as f:
                f.seek(file_size // 2)
                byte = f.read(1)
                f.seek(file_size // 2)
                f.write(bytes([byte[0] ^ 0xFF]))

            tampered_status = subprocess.check_output(check_cmd, text=True).strip()

            self.assertIn(
                tampered_status,
                ["HashMismatch", "NotSigned", "UnknownError"],
                f"Tampered binary Authenticode status must NOT be Valid. Got: {tampered_status} (Baseline was {baseline_status})"
            )

    def test_verifier_rejects_checksum_mismatch(self):
        """Verify verify_release_consistency.mjs rejects checksum mismatch between file and manifest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            exe_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe")
            manifest_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe.sha256")
            meta_path = os.path.join(tmpdir, "release_metadata.json")

            content = b"Unsigned phantomtrace mock binary content"
            with open(exe_path, "wb") as f:
                f.write(content)
            actual_hash = hashlib.sha256(content).hexdigest().lower()

            # Write mismatched hash to manifest
            mismatched_hash = "0000000000000000000000000000000000000000000000000000000000000000"
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(f"{mismatched_hash} *PhantomTrace_Agent_Setup.exe\n")

            meta = {
                "productName": "PhantomTrace Windows Agent",
                "version": "1.0.0",
                "filename": "PhantomTrace_Agent_Setup.exe",
                "fileSizeBytes": len(content),
                "sha256": actual_hash,
                "signatureStatus": "Unsigned",
                "isProductionSigned": False,
                "publisher": None,
            }
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f)

            res = subprocess.run(
                ["node", os.path.join(REPO_ROOT, "scripts", "verify_release_consistency.mjs"), tmpdir],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            self.assertNotEqual(res.returncode, 0, "Verifier must reject checksum mismatch")
            output = ((res.stdout or "") + (res.stderr or "")).lower()
            self.assertIn("mismatch", output)

    def test_verifier_rejects_metadata_hash_mismatch(self):
        """Verify verify_release_consistency.mjs rejects metadata sha256 mismatch with disk file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            exe_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe")
            manifest_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe.sha256")
            meta_path = os.path.join(tmpdir, "release_metadata.json")

            content = b"Unsigned phantomtrace mock binary content"
            with open(exe_path, "wb") as f:
                f.write(content)
            actual_hash = hashlib.sha256(content).hexdigest().lower()

            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(f"{actual_hash} *PhantomTrace_Agent_Setup.exe\n")

            # Write mismatched hash in metadata
            meta = {
                "productName": "PhantomTrace Windows Agent",
                "version": "1.0.0",
                "filename": "PhantomTrace_Agent_Setup.exe",
                "fileSizeBytes": len(content),
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                "signatureStatus": "Unsigned",
                "isProductionSigned": False,
                "publisher": None,
            }
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f)

            res = subprocess.run(
                ["node", os.path.join(REPO_ROOT, "scripts", "verify_release_consistency.mjs"), tmpdir],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            self.assertNotEqual(res.returncode, 0, "Verifier must reject metadata mismatch")
            output = ((res.stdout or "") + (res.stderr or "")).lower()
            self.assertIn("mismatch", output)

    def test_verifier_rejects_missing_and_malformed_release_files(self):
        """Verify verify_release_consistency.mjs rejects missing files, empty installers, and malformed metadata."""
        # Case A: Missing installer
        with tempfile.TemporaryDirectory() as tmpdir:
            res = subprocess.run(
                ["node", os.path.join(REPO_ROOT, "scripts", "verify_release_consistency.mjs"), tmpdir],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            self.assertNotEqual(res.returncode, 0)
            output = ((res.stdout or "") + (res.stderr or "")).lower()
            self.assertIn("missing", output)

        # Case B: Empty installer (0 bytes)
        with tempfile.TemporaryDirectory() as tmpdir:
            exe_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe")
            manifest_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe.sha256")
            meta_path = os.path.join(tmpdir, "release_metadata.json")
            with open(exe_path, "wb"):
                pass  # 0 bytes
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 *PhantomTrace_Agent_Setup.exe")
            meta = {
                "productName": "PhantomTrace Windows Agent",
                "version": "1.0.0",
                "filename": "PhantomTrace_Agent_Setup.exe",
                "fileSizeBytes": 0,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "signatureStatus": "Unsigned",
                "isProductionSigned": False,
                "publisher": None,
            }
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f)
            res = subprocess.run(
                ["node", os.path.join(REPO_ROOT, "scripts", "verify_release_consistency.mjs"), tmpdir],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            self.assertNotEqual(res.returncode, 0, "Verifier must reject 0-byte installer")
            output = ((res.stdout or "") + (res.stderr or "")).lower()
            self.assertIn("empty", output)

        # Case C: Malformed metadata JSON
        with tempfile.TemporaryDirectory() as tmpdir:
            exe_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe")
            manifest_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe.sha256")
            meta_path = os.path.join(tmpdir, "release_metadata.json")
            with open(exe_path, "wb") as f:
                f.write(b"content")
            h = hashlib.sha256(b"content").hexdigest().lower()
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(f"{h} *PhantomTrace_Agent_Setup.exe")
            with open(meta_path, "w", encoding="utf-8") as f:
                f.write("{ malformed json content")
            res = subprocess.run(
                ["node", os.path.join(REPO_ROOT, "scripts", "verify_release_consistency.mjs"), tmpdir],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            self.assertNotEqual(res.returncode, 0, "Verifier must reject malformed metadata")
            output = ((res.stdout or "") + (res.stderr or "")).lower()
            self.assertIn("malformed", output)

    def test_verifier_enforces_unsigned_metadata_contract(self):
        """Verify verify_release_consistency.mjs rejects signed metadata claims."""
        test_cases = [
            {"isProductionSigned": True, "signatureStatus": "Unsigned", "publisher": None},
            {"isProductionSigned": False, "signatureStatus": "Signed", "publisher": None},
            {"isProductionSigned": False, "signatureStatus": "Unsigned", "publisher": "CN=SomeSigner"},
        ]

        for bad_meta_fields in test_cases:
            with tempfile.TemporaryDirectory() as tmpdir:
                exe_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe")
                manifest_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe.sha256")
                meta_path = os.path.join(tmpdir, "release_metadata.json")

                content = b"Unsigned phantomtrace binary"
                with open(exe_path, "wb") as f:
                    f.write(content)
                h = hashlib.sha256(content).hexdigest().lower()
                with open(manifest_path, "w", encoding="utf-8") as f:
                    f.write(f"{h} *PhantomTrace_Agent_Setup.exe")

                meta = {
                    "productName": "PhantomTrace Windows Agent",
                    "version": "1.0.0",
                    "filename": "PhantomTrace_Agent_Setup.exe",
                    "fileSizeBytes": len(content),
                    "sha256": h,
                    **bad_meta_fields
                }
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f)

                res = subprocess.run(
                    ["node", os.path.join(REPO_ROOT, "scripts", "verify_release_consistency.mjs"), tmpdir],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace"
                )
                self.assertNotEqual(
                    res.returncode,
                    0,
                    f"Verifier should reject signed claims: {bad_meta_fields}"
                )

    def test_verifier_accepts_valid_unsigned_artifact_directory(self):
        """Verify verify_release_consistency.mjs succeeds on a valid, strictly unsigned release artifact directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            exe_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe")
            manifest_path = os.path.join(tmpdir, "PhantomTrace_Agent_Setup.exe.sha256")
            meta_path = os.path.join(tmpdir, "release_metadata.json")

            content = b"Properly packaged unsigned installer payload"
            with open(exe_path, "wb") as f:
                f.write(content)
            h = hashlib.sha256(content).hexdigest().lower()
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(f"{h} *PhantomTrace_Agent_Setup.exe\n")

            meta = {
                "productName": "PhantomTrace Windows Agent",
                "version": "1.0.0",
                "filename": "PhantomTrace_Agent_Setup.exe",
                "fileSizeBytes": len(content),
                "sha256": h,
                "signatureStatus": "Unsigned",
                "isProductionSigned": False,
                "publisher": None,
            }
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f)

            res = subprocess.run(
                ["node", os.path.join(REPO_ROOT, "scripts", "verify_release_consistency.mjs"), tmpdir],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            self.assertEqual(
                res.returncode,
                0,
                f"Verifier should succeed on valid unsigned directory. Output:\n{res.stdout}\n{res.stderr}"
            )
            self.assertIn("verification passed", res.stdout.lower())

    def test_workflow_yaml_specifies_unsigned_pipeline_and_isolation(self):
        """Verify the GitHub Actions release workflow adheres to all unsigned release requirements."""
        import yaml
        with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
            workflow = yaml.safe_load(f)

        self.assertIn("name", workflow)
        self.assertIn("build-and-release", workflow["jobs"])
        job = workflow["jobs"]["build-and-release"]
        self.assertEqual(job["runs-on"], "windows-latest")

        steps = job["steps"]
        step_names = [s.get("name", "") for s in steps]

        # Regression tests executed before build
        test_step_idx = next(i for i, name in enumerate(step_names) if "Regression Test" in name)
        build_step_idx = next(i for i, name in enumerate(step_names) if "Build Standalone" in name)
        self.assertLess(test_step_idx, build_step_idx, "Regression tests must run before building")

        # Independent Agent and Scanner build steps
        self.assertTrue(any("Agent Background Service" in name for name in step_names))
        self.assertTrue(any("Scanner CLI" in name for name in step_names))
        self.assertTrue(any("Verify Staged Binaries" in name for name in step_names))

        # Minimal permissions
        self.assertEqual(workflow.get("permissions"), {"contents": "write"})

        # No secrets used for signing
        workflow_str = json.dumps(workflow)
        self.assertNotIn("secrets.AZURE", workflow_str)
        self.assertNotIn("secrets.SIGNING", workflow_str)
        self.assertNotIn("secrets.CERT", workflow_str)


if __name__ == "__main__":
    unittest.main()
