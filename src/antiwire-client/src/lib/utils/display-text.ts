/**
 * Formats untrusted names and paths for visible UI text.
 *
 * Keep the original value for keys, URLs, commands, rules, and icon lookup;
 * this helper is only for the copy rendered to a person.
 */
export function displayText(value: string | null | undefined): string {
  if (!value) return '';

  let rendered = '';
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (isControl(codePoint)) continue;
    if (isUnicodeFormatControl(codePoint)) {
      rendered += `\\u{${codePoint.toString(16).toUpperCase().padStart(4, '0')}}`;
    } else {
      rendered += character;
    }
  }
  return rendered;
}

function isControl(codePoint: number): boolean {
  return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
}

function isUnicodeFormatControl(codePoint: number): boolean {
  return (
    codePoint === 0x00ad ||
    (codePoint >= 0x0600 && codePoint <= 0x0605) ||
    codePoint === 0x061c ||
    codePoint === 0x06dd ||
    codePoint === 0x070f ||
    (codePoint >= 0x0890 && codePoint <= 0x0891) ||
    codePoint === 0x08e2 ||
    codePoint === 0x180e ||
    (codePoint >= 0x200b && codePoint <= 0x200f) ||
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2060 && codePoint <= 0x2064) ||
    (codePoint >= 0x2066 && codePoint <= 0x206f) ||
    codePoint === 0xfeff ||
    (codePoint >= 0xfff9 && codePoint <= 0xfffb) ||
    codePoint === 0x110bd ||
    codePoint === 0x110cd ||
    (codePoint >= 0x13430 && codePoint <= 0x1343f) ||
    (codePoint >= 0x1bca0 && codePoint <= 0x1bca3) ||
    (codePoint >= 0x1d173 && codePoint <= 0x1d17a) ||
    codePoint === 0xe0001 ||
    (codePoint >= 0xe0020 && codePoint <= 0xe007f)
  );
}
