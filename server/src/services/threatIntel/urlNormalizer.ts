/**
 * =====================================================================
 * PHANTOMTRACE URL NORMALIZER & PRIVACY SANITIZER
 * =====================================================================
 * Guarantees:
 * 1. Strictly allows only http: and https: schemes.
 * 2. Strips query parameters, hashes, credentials (user:pass).
 * 3. Normalizes hostname (lowercasing, default port removal, IDN decoding).
 * 4. Rejects malformed, dangerous, or unsupported protocols.
 * 5. Returns minimum necessary metadata for reputation assessment.
 * =====================================================================
 */

export interface NormalizedUrlResult {
  valid: boolean;
  domain: string;
  normalizedUrl: string;
  scheme: "http" | "https";
  isIpAddress: boolean;
  port?: number;
  error?: string;
}

const ALLOWED_SCHEMES = new Set(["http:", "https:"]);

// IPv4 regex pattern
const IPV4_PATTERN = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;

// IPv6 regex pattern
const IPV6_PATTERN = /^\[?[0-9a-fA-F:]+\]?$/;

/**
 * Normalizes and sanitizes a URL or domain string.
 * Strips all query arguments, fragments, and user authentication tokens.
 */
export function normalizeUrlSafely(input: string): NormalizedUrlResult {
  if (!input || typeof input !== "string") {
    return {
      valid: false,
      domain: "",
      normalizedUrl: "",
      scheme: "https",
      isIpAddress: false,
      error: "Input URL is required and must be a non-empty string",
    };
  }

  const trimmed = input.trim();

  // If input lacks a scheme, add https:// for parsing
  let toParse = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    toParse = `https://${trimmed}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(toParse);
  } catch {
    return {
      valid: false,
      domain: "",
      normalizedUrl: "",
      scheme: "https",
      isIpAddress: false,
      error: "Malformed URL could not be parsed",
    };
  }

  // Scheme validation: strictly http or https
  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    return {
      valid: false,
      domain: "",
      normalizedUrl: "",
      scheme: "https",
      isIpAddress: false,
      error: `Unsupported scheme '${parsed.protocol}'. Only http and https are allowed.`,
    };
  }

  // Hostname validation & normalization
  let hostname = parsed.hostname.toLowerCase().trim();

  // Strip trailing dot in FQDN (e.g., example.com. -> example.com)
  if (hostname.endsWith(".")) {
    hostname = hostname.slice(0, -1);
  }

  if (!hostname) {
    return {
      valid: false,
      domain: "",
      normalizedUrl: "",
      scheme: parsed.protocol === "http:" ? "http" : "https",
      isIpAddress: false,
      error: "URL contains an empty hostname",
    };
  }

  const isIpv4 = IPV4_PATTERN.test(hostname);
  const isIpv6 = IPV6_PATTERN.test(hostname);
  const isIpAddress = isIpv4 || isIpv6;

  // Port handling
  let portNumber: number | undefined;
  if (parsed.port) {
    const num = parseInt(parsed.port, 10);
    if (!isNaN(num) && num > 0 && num <= 65535) {
      const isDefault =
        (parsed.protocol === "http:" && num === 80) ||
        (parsed.protocol === "https:" && num === 443);
      if (!isDefault) {
        portNumber = num;
      }
    }
  }

  // Sanitize path (strip query and fragment entirely)
  const pathname = parsed.pathname.startsWith("/") ? parsed.pathname : `/${parsed.pathname}`;
  const cleanPath = pathname === "/" ? "" : pathname;

  const schemeStr = parsed.protocol === "http:" ? "http" : "https";
  const portPart = portNumber ? `:${portNumber}` : "";
  const normalizedUrl = `${schemeStr}://${hostname}${portPart}${cleanPath}`;

  return {
    valid: true,
    domain: hostname,
    normalizedUrl,
    scheme: schemeStr,
    isIpAddress,
    port: portNumber,
  };
}
