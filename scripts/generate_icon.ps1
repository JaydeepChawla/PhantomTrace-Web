<#
.SYNOPSIS
    Generates official multi-resolution Windows ICO and Inno Setup branding bitmaps
    directly from the official PhantomTrace website logo assets.
.DESCRIPTION
    1. Extracts and prepares the official PT shield logo with anti-aliased transparent corners.
    2. Generates standard multi-resolution Windows .ico (256x256, 128x128, 64x64, 48x48, 32x32, 16x16)
       with full 32-bit ARGB alpha transparency.
    3. Generates Inno Setup wizard branding images (wizard.bmp and wizardsmall.bmp) with
       cybersecurity dark aesthetic and clean modern dialog headers.
    4. Distributes branding assets to installer/, phantomtrace-agent/installer/, and public/.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$DashboardPng = Join-Path $RootDir "public\PhantomTrace_Logo_Assets\phantomtrace-dashboard-icon.png"
if (-not (Test-Path $DashboardPng)) {
    $DashboardPng = Join-Path $RootDir "public\PhantomTrace_Logo_Assets\phantomtrace-windows-icon.png"
}

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE - OFFICIAL WINDOWS BRANDING GENERATOR" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Source website asset: $DashboardPng" -ForegroundColor Cyan

$csharp = @"
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Collections.Generic;

public class PhantomBranding {
    // 1. Create Master 256x256 App Icon with Anti-Aliased Transparent Corners
    public static Bitmap CreateMasterCleanIcon(string sourcePath) {
        using (Bitmap src = new Bitmap(sourcePath)) {
            Bitmap master = new Bitmap(256, 256, PixelFormat.Format32bppArgb);
            
            using (Bitmap scaled = new Bitmap(256, 256, PixelFormat.Format32bppArgb)) {
                using (Graphics gScale = Graphics.FromImage(scaled)) {
                    gScale.InterpolationMode = InterpolationMode.HighQualityBicubic;
                    gScale.SmoothingMode = SmoothingMode.HighQuality;
                    gScale.PixelOffsetMode = PixelOffsetMode.HighQuality;
                    gScale.DrawImage(src, new Rectangle(0, 0, 256, 256), new Rectangle(0, 0, src.Width, src.Height), GraphicsUnit.Pixel);
                }

                // Smooth squircle path with rounded corner radius of 54px at 256x256
                float cornerRadius = 54f;
                using (GraphicsPath path = new GraphicsPath()) {
                    path.AddArc(0, 0, cornerRadius * 2, cornerRadius * 2, 180, 90);
                    path.AddArc(256 - cornerRadius * 2, 0, cornerRadius * 2, cornerRadius * 2, 270, 90);
                    path.AddArc(256 - cornerRadius * 2, 256 - cornerRadius * 2, cornerRadius * 2, cornerRadius * 2, 0, 90);
                    path.AddArc(0, 256 - cornerRadius * 2, cornerRadius * 2, cornerRadius * 2, 90, 90);
                    path.CloseFigure();

                    using (Graphics g = Graphics.FromImage(master)) {
                        g.Clear(Color.Transparent);
                        g.SmoothingMode = SmoothingMode.AntiAlias;
                        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                        
                        using (TextureBrush tb = new TextureBrush(scaled)) {
                            g.FillPath(tb, path);
                        }
                    }
                }
            }
            return master;
        }
    }

    // 2. Build multi-resolution Windows ICO (256, 128, 64, 48, 32, 16)
    public static void SaveMultiResolutionIco(Bitmap master, string destPath) {
        int[] sizes = new int[] { 256, 128, 64, 48, 32, 16 };
        List<byte[]> pngList = new List<byte[]>();

        foreach (int s in sizes) {
            using (Bitmap resized = new Bitmap(s, s, PixelFormat.Format32bppArgb)) {
                using (Graphics g = Graphics.FromImage(resized)) {
                    g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                    g.SmoothingMode = SmoothingMode.HighQuality;
                    g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                    g.Clear(Color.Transparent);
                    g.DrawImage(master, 0, 0, s, s);
                }

                using (MemoryStream ms = new MemoryStream()) {
                    resized.Save(ms, ImageFormat.Png);
                    pngList.Add(ms.ToArray());
                }
            }
        }

        using (FileStream fs = new FileStream(destPath, FileMode.Create, FileAccess.Write))
        using (BinaryWriter bw = new BinaryWriter(fs)) {
            // ICONDIR
            bw.Write((ushort)0); // Reserved
            bw.Write((ushort)1); // Type 1 = Icon
            bw.Write((ushort)pngList.Count); // Image count

            int offset = 6 + (16 * pngList.Count);
            for (int i = 0; i < sizes.Length; i++) {
                int s = sizes[i];
                byte[] data = pngList[i];
                byte wByte = (s >= 256) ? (byte)0 : (byte)s;
                byte hByte = (s >= 256) ? (byte)0 : (byte)s;

                bw.Write(wByte);
                bw.Write(hByte);
                bw.Write((byte)0); // Color count
                bw.Write((byte)0); // Reserved
                bw.Write((ushort)1); // Color planes
                bw.Write((ushort)32); // Bits per pixel
                bw.Write((uint)data.Length); // Image size in bytes
                bw.Write((uint)offset); // Image offset in file

                offset += data.Length;
            }

            foreach (byte[] data in pngList) {
                bw.Write(data);
            }
        }
    }

    // 3. Generate Inno Setup WizardImage (164x314 24bpp BMP)
    public static void SaveWizardBanner(Bitmap cleanIcon, string destPath) {
        using (Bitmap wiz = new Bitmap(164, 314, PixelFormat.Format24bppRgb)) {
            using (Graphics g = Graphics.FromImage(wiz)) {
                g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                g.SmoothingMode = SmoothingMode.HighQuality;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;

                // Deep cyber background gradient: #070B14 to #0E1A32 matching website
                Rectangle fullRect = new Rectangle(0, 0, 164, 314);
                using (LinearGradientBrush bgBrush = new LinearGradientBrush(
                    fullRect,
                    Color.FromArgb(7, 11, 20),
                    Color.FromArgb(14, 26, 50),
                    LinearGradientMode.Vertical)) {
                    g.FillRectangle(bgBrush, fullRect);
                }

                // Ambient cyan glow behind PT shield
                Rectangle glowRect = new Rectangle(14, 45, 136, 136);
                using (GraphicsPath glowPath = new GraphicsPath()) {
                    glowPath.AddEllipse(glowRect);
                    using (PathGradientBrush pgb = new PathGradientBrush(glowPath)) {
                        pgb.CenterColor = Color.FromArgb(45, 0, 229, 255);
                        pgb.SurroundColors = new Color[] { Color.FromArgb(0, 7, 11, 20) };
                        g.FillEllipse(pgb, glowRect);
                    }
                }

                // Draw clean PT shield icon centered in upper portion
                int iconW = 104;
                int iconH = 104;
                int iconX = (164 - iconW) / 2;
                int iconY = 62;
                g.DrawImage(cleanIcon, iconX, iconY, iconW, iconH);

                // Draw "PHANTOMTRACE" text in cyan
                using (Font fontBrand = new Font("Segoe UI", 9.5f, FontStyle.Bold))
                using (SolidBrush textBrush = new SolidBrush(Color.FromArgb(0, 229, 255)))
                using (StringFormat sf = new StringFormat { Alignment = StringAlignment.Center }) {
                    g.DrawString("PHANTOMTRACE", fontBrand, textBrush, 82, 178, sf);
                }

                // Draw subtitle "ENDPOINT AGENT"
                using (Font fontSub = new Font("Segoe UI", 7.5f, FontStyle.Regular))
                using (SolidBrush subBrush = new SolidBrush(Color.FromArgb(148, 163, 184)))
                using (StringFormat sf = new StringFormat { Alignment = StringAlignment.Center }) {
                    g.DrawString("ENDPOINT AGENT", fontSub, subBrush, 82, 198, sf);
                }

                // Subtle neon divider line
                using (Pen pen = new Pen(Color.FromArgb(60, 0, 229, 255), 1.0f)) {
                    g.DrawLine(pen, 24, 220, 140, 220);
                }

                // Tagline
                using (Font fontTag = new Font("Segoe UI", 6.5f, FontStyle.Italic))
                using (SolidBrush tagBrush = new SolidBrush(Color.FromArgb(100, 116, 139)))
                using (StringFormat sf = new StringFormat { Alignment = StringAlignment.Center }) {
                    g.DrawString("Memory Threat Detection", fontTag, tagBrush, 82, 230, sf);
                }
            }
            wiz.Save(destPath, ImageFormat.Bmp);
        }
    }

    // 4. Generate Inno Setup WizardSmallImage (55x58 24bpp BMP)
    public static void SaveWizardSmallHeader(Bitmap cleanIcon, string destPath) {
        using (Bitmap small = new Bitmap(55, 58, PixelFormat.Format24bppRgb)) {
            using (Graphics g = Graphics.FromImage(small)) {
                g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                g.SmoothingMode = SmoothingMode.HighQuality;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;

                // Match Inno Setup modern white header background
                g.Clear(Color.White);

                // Draw clean PT shield icon centered (46x46)
                int targetSize = 46;
                int x = (55 - targetSize) / 2;
                int y = (58 - targetSize) / 2;
                g.DrawImage(cleanIcon, x, y, targetSize, targetSize);
            }
            small.Save(destPath, ImageFormat.Bmp);
        }
    }
}
"@

Add-Type -TypeDefinition $csharp -ReferencedAssemblies System.Drawing

# Step 1: Create Master Clean Icon (256x256 ARGB with transparent corners)
Write-Host "[1/4] Generating master 256x256 clean icon with transparent corners..." -ForegroundColor Cyan
$masterClean = [PhantomBranding]::CreateMasterCleanIcon($DashboardPng)

# Update phantomtrace-windows-icon.png with the clean version
$WindowsIconPng = Join-Path $RootDir "public\PhantomTrace_Logo_Assets\phantomtrace-windows-icon.png"
$masterClean.Save($WindowsIconPng, [System.Drawing.Imaging.ImageFormat]::Png)
Write-Host "      Updated: $WindowsIconPng" -ForegroundColor Green

# Step 2: Generate multi-resolution Windows ICO
Write-Host "[2/4] Generating multi-resolution Windows .ico (256, 128, 64, 48, 32, 16)..." -ForegroundColor Cyan
$icoDestinations = @(
    (Join-Path $RootDir "installer\phantomtrace.ico"),
    (Join-Path $RootDir "phantomtrace-agent\installer\phantomtrace.ico"),
    (Join-Path $RootDir "public\favicon.ico")
)

foreach ($dest in $icoDestinations) {
    $parent = Split-Path $dest
    if (-not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [PhantomBranding]::SaveMultiResolutionIco($masterClean, $dest)
    $size = (Get-Item $dest).Length
    Write-Host "      Generated: $dest ($size bytes)" -ForegroundColor Green
}

# Step 3: Generate WizardImage banner (164x314 BMP)
Write-Host "[3/4] Generating Inno Setup wizard banner (164x314)..." -ForegroundColor Cyan
$wizDestinations = @(
    (Join-Path $RootDir "installer\wizard.bmp"),
    (Join-Path $RootDir "phantomtrace-agent\installer\wizard.bmp")
)

foreach ($dest in $wizDestinations) {
    $parent = Split-Path $dest
    if (-not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [PhantomBranding]::SaveWizardBanner($masterClean, $dest)
    $size = (Get-Item $dest).Length
    Write-Host "      Generated: $dest ($size bytes)" -ForegroundColor Green
}

# Step 4: Generate WizardSmallImage header (55x58 BMP)
Write-Host "[4/4] Generating Inno Setup wizard small header (55x58)..." -ForegroundColor Cyan
$smallDestinations = @(
    (Join-Path $RootDir "installer\wizardsmall.bmp"),
    (Join-Path $RootDir "phantomtrace-agent\installer\wizardsmall.bmp")
)

foreach ($dest in $smallDestinations) {
    $parent = Split-Path $dest
    if (-not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [PhantomBranding]::SaveWizardSmallHeader($masterClean, $dest)
    $size = (Get-Item $dest).Length
    Write-Host "      Generated: $dest ($size bytes)" -ForegroundColor Green
}

$masterClean.Dispose()
Write-Host "====================================================" -ForegroundColor Green
Write-Host " All PhantomTrace Windows branding assets successfully created!" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
