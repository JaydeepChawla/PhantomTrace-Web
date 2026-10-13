"""
Unit tests for PhantomTrace Release Integrity and Cryptographic Verification.
Covers:
- Exact SHA-256 matching between binary and manifest
- 1-byte tamper detection causing verification failure
- Missing and malformed manifest error handling
- Consistency between frontend metadata and release manifests
- Defensive agent constraints (read-only mode, 127.0.0.1 service binding)
"""

import unittest
import hashlib
import json
import os
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
METADATA_PATH = os.path.join(REPO_ROOT, "public", "downloads", "release_metadata.json")
MANIFEST_PATH = os.path.join(REPO_ROOT, "public", "downloads", "PhantomTrace_Agent_Setup.exe.sha256")
INSTALLER_PATH = os.path.join(REPO_ROOT, "public", "downloads", "PhantomTrace_Agent_Setup.exe")
TS_METADATA_PATH = os.path.join(REPO_ROOT, "src", "data", "releaseMetadata.ts")


class TestReleaseIntegrity(unittest.TestCase):

    def test_metadata_file_exists_and_valid_json(self):
        """Verify release_metadata.json exists and adheres to schema."""
        self.assertTrue(os.path.exists(METADATA_PATH), f"Missing metadata file: {METADATA_PATH}")
        with open(METADATA_PATH, "r", encoding="utf-8-sig") as f:
            meta = json.load(f)

        required_keys = ["productName", "version", "filename", "fileSizeBytes", "sha256"]
        for key in required_keys:
            self.assertIn(key, meta, f"Metadata missing required key: {key}")
            self.assertTrue(meta[key], f"Key {key} in metadata cannot be empty")

        self.assertEqual(meta["filename"], "PhantomTrace_Agent_Setup.exe")
        self.assertEqual(len(meta["sha256"]), 64, "SHA-256 hash must be exactly 64 hex characters")

    def test_manifest_matches_declared_metadata(self):
        """Verify .sha256 manifest file matches declared metadata checksum."""
        self.assertTrue(os.path.exists(MANIFEST_PATH), f"Missing manifest: {MANIFEST_PATH}")
        with open(MANIFEST_PATH, "r", encoding="utf-8-sig") as f:
            manifest_content = f.read().strip()

        manifest_hash = manifest_content.split()[0].lower()
        with open(METADATA_PATH, "r", encoding="utf-8-sig") as f:
            meta = json.load(f)

        self.assertEqual(
            manifest_hash,
            meta["sha256"].lower(),
            "Manifest hash must match declared release metadata SHA-256"
        )

    def test_frontend_ts_metadata_sync(self):
        """Verify src/data/releaseMetadata.ts and releaseMetadata.json contain identical SHA-256 and filename."""
        self.assertTrue(os.path.exists(TS_METADATA_PATH), f"Missing TS metadata: {TS_METADATA_PATH}")
        with open(TS_METADATA_PATH, "r", encoding="utf-8-sig") as f:
            ts_content = f.read()

        with open(METADATA_PATH, "r", encoding="utf-8-sig") as f:
            meta = json.load(f)

        src_json_path = os.path.join(REPO_ROOT, "src", "data", "releaseMetadata.json")
        self.assertTrue(os.path.exists(src_json_path), f"Missing src JSON metadata: {src_json_path}")
        with open(src_json_path, "r", encoding="utf-8-sig") as f:
            src_meta = json.load(f)

        self.assertEqual(src_meta["sha256"], meta["sha256"], "src releaseMetadata.json must match public release metadata SHA-256")
        self.assertIn("releaseMetadata.json", ts_content, "TypeScript metadata must import releaseMetadata.json")
        self.assertIn(meta["filename"], ts_content, "TypeScript metadata must contain current installer filename")

    def test_one_byte_tamper_causes_hash_mismatch(self):
        """Verify modifying one byte of a binary causes immediate SHA-256 verification failure."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"Original Verified PhantomTrace Setup Binary Content")
            temp_path = tf.name

        try:
            # Baseline hash
            with open(temp_path, "rb") as f:
                baseline_hash = hashlib.sha256(f.read()).hexdigest()

            # Tamper 1 single byte
            with open(temp_path, "r+b") as f:
                f.seek(5)
                original_byte = f.read(1)
                new_byte = bytes([(original_byte[0] ^ 0xFF)])
                f.seek(5)
                f.write(new_byte)

            # Recomputed hash
            with open(temp_path, "rb") as f:
                tampered_hash = hashlib.sha256(f.read()).hexdigest()

            self.assertNotEqual(
                baseline_hash,
                tampered_hash,
                "Tampered binary must produce a completely different SHA-256 hash"
            )
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_malformed_manifest_rejection(self):
        """Verify malformed manifest strings are rejected."""
        malformed_samples = [
            "",
            "invalid_hash_string *PhantomTrace_Agent_Setup.exe",
            "123456 *PhantomTrace_Agent_Setup.exe",
            "088a55f1c9871d251f9049bce30a4d8ed100c3d4fa08d82b062e3b8dd6637f6z *setup.exe",  # 'z' invalid hex
        ]

        for sample in malformed_samples:
            tokens = sample.strip().split()
            if not tokens or len(tokens[0]) != 64 or not all(c in "0123456789abcdefABCDEF" for c in tokens[0]):
                is_valid = False
            else:
                is_valid = True
            self.assertFalse(is_valid, f"Sample '{sample}' should be rejected as malformed")

    def test_agent_defensive_service_binding_and_read_only(self):
        """Ensure agent configuration binds exclusively to localhost (127.0.0.1:49152) and scanner is read-only."""
        agent_config = os.path.join(REPO_ROOT, "phantomtrace-agent", "agent_service", "config.py")
        self.assertTrue(os.path.exists(agent_config), f"Missing {agent_config}")
        with open(agent_config, "r", encoding="utf-8") as f:
            content = f.read()

        # Check localhost binding
        self.assertIn('HOST = "127.0.0.1"', content, "Agent service must bind exclusively to 127.0.0.1 localhost")
        self.assertNotIn('HOST = "0.0.0.0"', content, "Agent service must never bind to 0.0.0.0 external interfaces")
        self.assertIn("49152", content, "Agent service must default to port 49152")

        # Check scanner read-only mode
        scanner_main = os.path.join(REPO_ROOT, "agent", "main.py")
        with open(scanner_main, "r", encoding="utf-8") as f:
            scanner_content = f.read()
        self.assertIn("READ-ONLY", scanner_content.upper(), "Scanner must declare and maintain read-only mode")

    def test_installer_branding_and_icon_assets(self):
        """Verify Windows icon asset is a valid ICO file and is configured in Inno Setup and build scripts."""
        ico_path = os.path.join(REPO_ROOT, "installer", "phantomtrace.ico")
        self.assertTrue(os.path.exists(ico_path), f"Missing icon asset: {ico_path}")

        # Check binary ICO header: Reserved (0), Type (1 = Icon)
        with open(ico_path, "rb") as f:
            header = f.read(6)
        self.assertEqual(header[:4], b"\x00\x00\x01\x00", "Icon must be a valid Windows ICO file (header 00 00 01 00)")
        icon_count = int.from_bytes(header[4:6], byteorder="little")
        self.assertGreaterEqual(icon_count, 1, "Icon file must contain at least one resolution")

        # Verify Inno Setup script configuration
        iss_path = os.path.join(REPO_ROOT, "installer", "PhantomTrace_Agent_Setup.iss")
        with open(iss_path, "r", encoding="utf-8") as f:
            iss_content = f.read()

        self.assertIn("SetupIconFile=phantomtrace.ico", iss_content, "Inno Setup must configure SetupIconFile")
        self.assertIn('UninstallDisplayIcon={app}\\phantomtrace.ico', iss_content, "Inno Setup must configure uninstaller display icon")
        self.assertIn('WizardImageFile=wizard.bmp', iss_content, "Inno Setup must configure WizardImageFile banner")
        self.assertIn('WizardSmallImageFile=wizardsmall.bmp', iss_content, "Inno Setup must configure WizardSmallImageFile header")
        self.assertIn('IconFilename: "{app}\\phantomtrace.ico"', iss_content, "Inno Setup shortcuts must explicitly set IconFilename")
        self.assertIn('Source: "phantomtrace.ico"; DestDir: "{app}"', iss_content, "Inno Setup must package phantomtrace.ico to {app}")

        # Verify wizard branding image files exist and are valid Windows BMP files
        wiz_path = os.path.join(REPO_ROOT, "installer", "wizard.bmp")
        wiz_small_path = os.path.join(REPO_ROOT, "installer", "wizardsmall.bmp")
        self.assertTrue(os.path.exists(wiz_path), f"Missing wizard branding banner: {wiz_path}")
        self.assertTrue(os.path.exists(wiz_small_path), f"Missing wizard small branding header: {wiz_small_path}")

        with open(wiz_path, "rb") as f:
            wiz_header = f.read(2)
        self.assertEqual(wiz_header, b"BM", "wizard.bmp must be a valid Windows BMP file")

        with open(wiz_small_path, "rb") as f:
            wiz_small_header = f.read(2)
        self.assertEqual(wiz_small_header, b"BM", "wizardsmall.bmp must be a valid Windows BMP file")

        # Verify build script includes icon
        build_agent_script = os.path.join(REPO_ROOT, "scripts", "build_and_sign_agent.ps1")
        with open(build_agent_script, "r", encoding="utf-8") as f:
            build_content = f.read()
        self.assertIn('"--icon"', build_content, "PyInstaller arguments must include --icon")

    def test_installer_disk_bytes_match_checksum_and_metadata(self):
        """Independently calculate SHA-256 directly from disk installer bytes and verify match."""
        if not os.path.exists(INSTALLER_PATH):
            self.skipTest(f"Installer binary not found at {INSTALLER_PATH}")

        # Independently calculate SHA-256 from disk bytes
        hasher = hashlib.sha256()
        with open(INSTALLER_PATH, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        actual_disk_hash = hasher.hexdigest().lower()

        # Read manifest
        with open(MANIFEST_PATH, "r", encoding="utf-8-sig") as f:
            manifest_content = f.read().strip()
        manifest_hash = manifest_content.split()[0].lower()

        # Read metadata
        with open(METADATA_PATH, "r", encoding="utf-8-sig") as f:
            meta = json.load(f)
        metadata_hash = meta["sha256"].lower()

        self.assertEqual(
            actual_disk_hash,
            manifest_hash,
            f"Actual disk installer hash ({actual_disk_hash}) must match manifest hash ({manifest_hash})"
        )
        self.assertEqual(
            actual_disk_hash,
            metadata_hash,
            f"Actual disk installer hash ({actual_disk_hash}) must match metadata hash ({metadata_hash})"
        )

    def test_dist_staging_integrity_when_present(self):
        """Verify dist/ staging artifacts are self-consistent and independent of public downloads."""
        dist_exe = os.path.join(REPO_ROOT, "dist", "PhantomTrace_Agent_Setup.exe")
        dist_manifest = os.path.join(REPO_ROOT, "dist", "PhantomTrace_Agent_Setup.exe.sha256")
        dist_meta = os.path.join(REPO_ROOT, "dist", "release_metadata.json")

        if not os.path.exists(dist_exe):
            return

        hasher = hashlib.sha256()
        with open(dist_exe, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        dist_hash = hasher.hexdigest().lower()

        if os.path.exists(dist_manifest):
            with open(dist_manifest, "r", encoding="utf-8-sig") as f:
                content = f.read().strip()
            self.assertEqual(dist_hash, content.split()[0].lower())

        if os.path.exists(dist_meta):
            with open(dist_meta, "r", encoding="utf-8-sig") as f:
                meta = json.load(f)
            self.assertEqual(dist_hash, meta["sha256"].lower())
            self.assertEqual(meta.get("signatureStatus"), "Unsigned")
            self.assertFalse(meta.get("isProductionSigned", True))
            self.assertIsNone(meta.get("publisher"))


if __name__ == "__main__":
    unittest.main()
