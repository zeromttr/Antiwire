/** True when the summary has a filesystem path usable for firewall rules. */
export function hasApplicationPath(path: string): boolean {
  const trimmed = path.trim();
  if (!trimmed || trimmed === '—') return false;
  return trimmed.includes('/') || trimmed.includes('\\') || /^[A-Za-z]:/.test(trimmed);
}
