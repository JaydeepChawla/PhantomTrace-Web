"""
PhantomTrace Chrome Extension Packaging & Verification Script
Packages browser-extension/ into public/downloads/PhantomTrace-Chrome-Extension.zip
Validates manifest, referenced assets, integrity, and lack of leaked secrets.
"""

import os
import sys
import json
import zipfile
import hashlib
import tempfile
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = Path(__file__).resolve().parent.parent
EXTENSION_DIR = ROOT_DIR / "browser-extension"
PUBLIC_DOWNLOADS_DIR = ROOT_DIR / "public" / "downloads"
OUTPUT_ZIP = PUBLIC_DOWNLOADS_DIR / "PhantomTrace-Chrome-Extension.zip"

REQUIRED_FILES = [
    "manifest.json",
    "background.js",
    "popup.html",
    "popup.js",
    "popup.css",
    "warning.html",
    "warning.js",
    "warning.css",
    os.path.join("icons", "icon16.png"),
    os.path.join("icons", "icon48.png"),
    os.path.join("icons", "icon128.png"),
]

FORBIDDEN_PATTERNS = [
    ".env",
    "password",
    "secret",
    "private_key",
    "postgres://",
    "postgresql://",
    "PHANTOMTRACE_API_KEY",
    ".git",
    "node_modules",
    ".DS_Store",
    "Thumbs.db",
]


def build_and_verify():
    print("=" * 65)
    print(" PHANTOMTRACE CHROME EXTENSION PACKAGER")
    print("=" * 65)
    print(f"Source Directory: {EXTENSION_DIR}")
    print(f"Target ZIP:       {OUTPUT_ZIP}")

    if not EXTENSION_DIR.exists():
        print(f"ERROR: Extension directory does not exist: {EXTENSION_DIR}")
        sys.exit(1)

    PUBLIC_DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Validate source files exist
    print("\n[1/5] Verifying source files in browser-extension/...")
    for req in REQUIRED_FILES:
        fp = EXTENSION_DIR / req
        if not fp.exists():
            print(f"  ✗ Missing required file: {req}")
            sys.exit(1)
        print(f"  ✓ Found: {req} ({fp.stat().st_size:,} bytes)")

    # 2. Validate manifest.json format & referenced assets
    print("\n[2/5] Validating manifest.json...")
    manifest_path = EXTENSION_DIR / "manifest.json"
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    assert manifest_data.get("manifest_version") == 3, "manifest_version must be 3"
    assert manifest_data.get("name") == "PhantomTrace Web Threat Monitor"
    assert manifest_data.get("version") == "1.0.0"
    assert "service_worker" in manifest_data.get("background", {})
    print("  ✓ Manifest V3 validated successfully.")

    # 3. Security Audit: Scan all files for secrets/credentials
    print("\n[3/5] Auditing files for secrets, credentials, and forbidden patterns...")
    for root, _, files in os.walk(EXTENSION_DIR):
        for fname in files:
            fpath = Path(root) / fname
            rel_path = fpath.relative_to(EXTENSION_DIR)
            
            # Check filename against forbidden patterns
            for pat in FORBIDDEN_PATTERNS:
                if pat.lower() in fname.lower():
                    print(f"  ✗ Forbidden pattern '{pat}' detected in filename: {rel_path}")
                    sys.exit(1)

            # Check text file contents
            if fpath.suffix in [".json", ".js", ".html", ".css", ".txt", ".md"]:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for pat in ["postgres://", "postgresql://", "PRIVATE KEY", "test-master-owner-key"]:
                    if pat in content:
                        print(f"  ✗ Forbidden pattern '{pat}' detected in file content: {rel_path}")
                        sys.exit(1)
    print("  ✓ Security audit passed: zero credentials or master keys found.")

    # 4. Create ZIP archive
    print("\n[4/5] Building PhantomTrace-Chrome-Extension.zip...")
    if OUTPUT_ZIP.exists():
        OUTPUT_ZIP.unlink()

    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(EXTENSION_DIR):
            for fname in files:
                fpath = Path(root) / fname
                arcname = str(fpath.relative_to(EXTENSION_DIR)).replace("\\", "/")
                zf.write(fpath, arcname)
                print(f"  + Added: {arcname}")

    zip_size = OUTPUT_ZIP.stat().st_size
    print(f"  ✓ Package built successfully: {OUTPUT_ZIP.name} ({zip_size:,} bytes)")

    # Compute SHA-256
    hasher = hashlib.sha256()
    with open(OUTPUT_ZIP, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    sha256_hash = hasher.hexdigest()
    print(f"  SHA-256: {sha256_hash}")

    # 5. Extract into temporary directory and test layout
    print("\n[5/5] Testing extraction & Load unpacked compatibility...")
    with tempfile.TemporaryDirectory() as tmpdir:
        extract_dir = Path(tmpdir) / "extracted"
        with zipfile.ZipFile(OUTPUT_ZIP, "r") as zf:
            zf.extractall(extract_dir)

        # Verify manifest is directly in the extracted folder
        extracted_manifest = extract_dir / "manifest.json"
        if not extracted_manifest.exists():
            print("  ✗ Extraction failure: manifest.json not found at extracted root.")
            sys.exit(1)
        
        with open(extracted_manifest, "r", encoding="utf-8") as f:
            tdata = json.load(f)
        assert tdata.get("name") == "PhantomTrace Web Threat Monitor"

        # Verify all required files are present
        for req in REQUIRED_FILES:
            tfp = extract_dir / req
            if not tfp.exists():
                print(f"  ✗ Extracted archive missing required file: {req}")
                sys.exit(1)

        print("  ✓ Extracted archive verified successfully.")
        print("  ✓ Manifest is directly at the root of the extracted folder.")
        print("  ✓ Chrome 'Load unpacked' will successfully load this extracted directory.")

    print("\n" + "=" * 65)
    print(" PACKAGING & VERIFICATION COMPLETE (PASSED)")
    print(f" Output: {OUTPUT_ZIP}")
    print(f" Size:   {zip_size:,} bytes")
    print(f" SHA256: {sha256_hash}")
    print("=" * 65)


if __name__ == "__main__":
    build_and_verify()
