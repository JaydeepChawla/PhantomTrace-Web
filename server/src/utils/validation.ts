/**
 * Input validation helpers for API parameters and identifiers.
 */
export function isValidIdentifier(id: unknown): id is string {
  if (typeof id !== "string") return false;
  const trimmed = id.trim();
  if (trimmed.length === 0 || trimmed.length > 128) return false;
  // Disallow path traversal characters (slashes, null bytes, backslashes)
  return /^[a-zA-Z0-9_\-.:]+$/.test(trimmed);
}
