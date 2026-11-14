/**
 * Parsing for the bundled `country-ip-blocks` data files.
 *
 * Kept separate from `country-cidrs.ts` because that module runs
 * `import.meta.glob` at import time, which only exists under Vite — so
 * anything importing it cannot be unit-tested. This file is pure.
 */

/**
 * Extracts CIDRs from one `*-aggregated.txt` file.
 *
 * Every file opens with a comment header (`# Country: …`, `# Address family: …`
 * and so on). Those lines must be dropped: leaving them in sends
 * `"# Country: North Korea (KP)"` to the daemon as if it were a network, which
 * it rejects.
 */
export function parseCidrText(text: string): string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}
