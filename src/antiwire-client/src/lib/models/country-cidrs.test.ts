import { describe, expect, it } from 'bun:test';
import { parseCidrText } from './country-cidr-parse';

// The exact header every `*-aggregated.txt` in `country-ip-blocks` opens with.
const IPV4_FIXTURE = `# Country: North Korea (KP)
# Address family: IPv4
# Delegation status: Allocated || Assigned
# Export mode: Aggregated
#
175.45.176.0/22
210.52.109.0/24
77.94.35.0/24
`;

const IPV6_FIXTURE = `# Country: Germany (DE)
# Address family: IPv6
# Delegation status: Allocated || Assigned
# Export mode: Aggregated
#
2001:608::/32
2001:638::/29
`;

describe('parseCidrText', () => {
  it('drops the comment header', () => {
    // Leaving these in made the first "network" sent to the daemon
    // `"# Country: North Korea (KP)"`, which it rejected — this is the reason
    // country blocking failed outright.
    const cidrs = parseCidrText(IPV4_FIXTURE);

    expect(cidrs).toEqual(['175.45.176.0/22', '210.52.109.0/24', '77.94.35.0/24']);
    expect(cidrs.some((entry) => entry.startsWith('#'))).toBe(false);
  });

  it('parses IPv6 files the same way', () => {
    expect(parseCidrText(IPV6_FIXTURE)).toEqual(['2001:608::/32', '2001:638::/29']);
  });

  it('ignores blank lines and surrounding whitespace', () => {
    expect(parseCidrText('\n  10.0.0.0/8  \n\n   \n192.168.0.0/16\n')).toEqual([
      '10.0.0.0/8',
      '192.168.0.0/16',
    ]);
  });

  it('returns nothing for a header-only file', () => {
    expect(parseCidrText('# Country: Nowhere (ZZ)\n#\n')).toEqual([]);
  });

  it('handles CRLF line endings', () => {
    expect(parseCidrText('# Country: X (XX)\r\n10.0.0.0/8\r\n')).toEqual(['10.0.0.0/8']);
  });
});

describe('country-cidrs', () => {
  it('loads country entries from bundled asset', async () => {
    const { COUNTRY_ENTRIES, getCountryCidrs } = await import('./country-cidrs');
    expect(COUNTRY_ENTRIES.length).toBeGreaterThan(200);

    const kp = COUNTRY_ENTRIES.find((entry) => entry.code === 'KP');
    expect(kp).toBeDefined();
    expect(kp?.name).toBeDefined();

    const cidrs = await getCountryCidrs('KP');
    expect(cidrs.length).toBeGreaterThan(0);
    expect(cidrs.some((cidr) => cidr.includes('/'))).toBe(true);
  });

  it('reads one country, accepts any case, and never builds a path from an unknown code', async () => {
    const { getCountryCidrs } = await import('./country-cidrs');
    expect(await getCountryCidrs(' de ')).toEqual(await getCountryCidrs('DE'));
    expect(await getCountryCidrs('ZZ')).toEqual([]);
    expect(await getCountryCidrs('../country-index')).toEqual([]);
  });

  it('has a data file for every country in the index, and no others', async () => {
    const { readdirSync } = await import('node:fs');
    const index = (await import('../assets/country-index.json')).default as string[];
    const files = readdirSync(new URL('../assets/country-cidrs/', import.meta.url))
      .map((name) => name.replace(/\.json$/, ''))
      .sort();
    expect(files).toEqual([...index].sort());
  });
});
