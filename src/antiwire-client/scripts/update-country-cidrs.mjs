import { mkdir, rm, writeFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';

const RELEASE_URL =
  'https://github.com/ipverse/country-ip-blocks/releases/download/latest/country-ip-blocks.tar.gz';
// One file per country, so picking a country loads only its networks (a few KB, 0.8 MB for
// the largest) rather than the whole table. The app builds a path only from a code in the index.
const OUTPUT_DIR_URL = new URL('../src/lib/assets/country-cidrs/', import.meta.url);
// Tiny eager index (codes only, ~2 KB). The firewall route bundles this.
const INDEX_URL = new URL('../src/lib/assets/country-index.json', import.meta.url);

console.log(`Downloading country CIDR data from ${RELEASE_URL}...`);
const response = await fetch(RELEASE_URL);
if (!response.ok) {
  throw new Error(`Download failed: ${response.status} ${response.statusText}`);
}

const buffer = Buffer.from(await response.arrayBuffer());
const tar = gunzipSync(buffer);

const countryCidrs = {};
let totalCidrs = 0;
let offset = 0;

while (offset + 512 <= tar.length) {
  const header = tar.subarray(offset, offset + 512);
  offset += 512;
  if (header.every((b) => b === 0)) break;

  const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '').trim();
  const sizeStr = header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
  const size = parseInt(sizeStr, 8) || 0;
  const content = tar.subarray(offset, offset + size).toString('utf8');
  offset += Math.ceil(size / 512) * 512;

  if (name.endsWith('/aggregated.json')) {
    try {
      const data = JSON.parse(content);
      const code = (data.countryCode || '').toUpperCase();
      if (code) {
        const v4 = data.prefixes?.ipv4 || [];
        const v6 = data.prefixes?.ipv6 || [];
        const combined = [...v4, ...v6];
        countryCidrs[code] = combined;
        totalCidrs += combined.length;
      }
    } catch (e) {
      console.error(`Failed to parse ${name}:`, e);
    }
  }
}

// Sort keys alphabetically for deterministic output
const sortedCountryCidrs = Object.keys(countryCidrs)
  .sort()
  .reduce((acc, code) => {
    acc[code] = countryCidrs[code];
    return acc;
  }, {});

const countryCount = Object.keys(sortedCountryCidrs).length;
// Start from an empty directory, so a country that is no longer listed loses its file.
await rm(OUTPUT_DIR_URL, { recursive: true, force: true });
await mkdir(OUTPUT_DIR_URL, { recursive: true });
for (const [code, cidrs] of Object.entries(sortedCountryCidrs)) {
  // Pretty-printed so an update reads as a diff; the build compacts it (compactJsonAssets).
  const file = new URL(`${code}.json`, OUTPUT_DIR_URL);
  await writeFile(file, `${JSON.stringify(cidrs, null, 2)}\n`, 'utf8');
}
await writeFile(INDEX_URL, `${JSON.stringify(Object.keys(sortedCountryCidrs))}\n`, 'utf8');

console.log(
  `Wrote ${totalCidrs} CIDRs across ${countryCount} countries to ${OUTPUT_DIR_URL.pathname}`,
);
