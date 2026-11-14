import countryIndex from '../assets/country-index.json';

export type CountryEntry = {
  code: string;
  name: string;
};

const regionNames =
  typeof Intl !== 'undefined' ? new Intl.DisplayNames(['en'], { type: 'region' }) : null;

function countryName(code: string): string {
  const label = regionNames?.of(code);
  return label && label !== code ? label : code;
}

const countryCodes = countryIndex as string[];

export const COUNTRY_ENTRIES: CountryEntry[] = countryCodes
  .map((code) => ({
    code,
    name: countryName(code),
  }))
  .sort((a, b) => a.name.localeCompare(b.name));

const knownCodes = new Set(countryCodes);

/**
 * One country's networks, fetched only when the user picks it in the rule dialog. Each country
 * is its own JSON asset (`assets/country-cidrs/<code>.json`), so a pick reads a few KB instead
 * of parsing the whole 4 MB table and keeping it in memory. A plain JSON asset rather than an
 * imported module: `Response.json()` goes through the browser's JSON parser, several times
 * faster than compiling the same data as a JavaScript chunk. Vite emits every file matching
 * this template and rewrites the URL; under bun it is a `file:` URL.
 */
function cidrsUrl(code: string): URL {
  return new URL(`../assets/country-cidrs/${code}.json`, import.meta.url);
}

const cidrsByCountry = new Map<string, Promise<string[]>>();

async function fetchCidrs(code: string): Promise<string[]> {
  const response = await fetch(cidrsUrl(code));
  if (!response.ok) throw new Error(`country-cidrs/${code}.json: HTTP ${response.status}`);
  return (await response.json()) as string[];
}

/**
 * Returns every IPv4 and IPv6 network allocated to `code`, or none for a code the index does
 * not list. Only a listed code becomes a path. There is no network access here, just a fetch
 * of the app's own bundled asset.
 */
export function getCountryCidrs(code: string): Promise<string[]> {
  const normalized = code.trim().toUpperCase();
  if (!knownCodes.has(normalized)) return Promise.resolve([]);
  let pending = cidrsByCountry.get(normalized);
  if (!pending) {
    pending = fetchCidrs(normalized);
    cidrsByCountry.set(normalized, pending);
    // A failed fetch must not poison later calls: forget it so the next call retries.
    pending.catch(() => cidrsByCountry.delete(normalized));
  }
  return pending;
}
