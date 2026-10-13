import rawMetadata from './releaseMetadata.json';

export interface ReleaseMetadata {
  productName: string;
  version: string;
  filename: string;
  fileSizeBytes: number;
  fileSizeFormatted: string;
  sha256: string;
  releaseTag: string;
  releaseUrl: string;
  downloadUrl: string;
  backendDownloadUrl: string;
  signatureStatus: string;
  publisher: string | null;
  hashAlgorithm: string;
  powershellVerifyCommand: string;
  cmdVerifyCommand: string;
}

const formatBytes = (bytes: number): string => {
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
};

const meta = rawMetadata as {
  productName?: string;
  version?: string;
  filename?: string;
  fileSizeBytes?: number;
  sha256?: string;
  downloadUrl?: string;
  signatureStatus?: string;
  publisher?: string | null;
};

const fileSizeBytes = meta.fileSizeBytes || 14349205;
const filename = meta.filename || 'PhantomTrace_Agent_Setup.exe';

export const releaseMetadata: ReleaseMetadata = {
  productName: meta.productName || 'PhantomTrace Windows Agent',
  version: meta.version || '1.0.0',
  filename,
  fileSizeBytes,
  fileSizeFormatted: formatBytes(fileSizeBytes),
  sha256: meta.sha256 || 'ba47f3c2554216d8e56d40b7f359628d35b451b6a81e8ea2b638657644186f94',
  releaseTag: 'v1.0.0',
  releaseUrl: 'https://github.com/JaydeepChawla/PhantomTrace-Web/releases/tag/v1.0.0',
  downloadUrl: meta.downloadUrl || '/downloads/PhantomTrace_Agent_Setup.exe',
  backendDownloadUrl: 'https://phantomtrace-web.onrender.com/api/agent/download?installer=true',
  signatureStatus: meta.signatureStatus || 'Unsigned',
  publisher: meta.publisher !== undefined ? meta.publisher : null,
  hashAlgorithm: 'SHA-256',
  powershellVerifyCommand: `Get-FileHash .\\${filename} -Algorithm SHA256`,
  cmdVerifyCommand: `certutil -hashfile ${filename} SHA256`
};
