/** Synchronous copy — must run directly inside a click/keydown handler. */
export function copyTextSync(value: string): boolean {
  if (!value) return false;

  try {
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    textarea.style.top = '0';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textarea);
    if (ok) return true;
  } catch {
    // Fall through to async paths.
  }

  return false;
}

/** Best-effort copy; prefers sync path when called from a user gesture. */
export async function copyText(value: string): Promise<boolean> {
  if (!value) return false;

  if (copyTextSync(value)) return true;

  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch {
      // Fall through.
    }
  }

  return copyTextSync(value);
}
