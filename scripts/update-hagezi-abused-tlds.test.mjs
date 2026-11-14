import { describe, expect, test } from 'bun:test';
import {
  fileHash,
  mergeAlwaysInclude,
  normalizeName,
  parseHageziList,
  parseHashFile,
  renderHashFile,
  renderList,
} from './update-hagezi-abused-tlds.mjs';

describe('update-hagezi-abused-tlds', () => {
  test('keeps HaGeZi public suffixes and two-letter names, drops infrastructure zones', () => {
    expect(normalizeName('Christmas.')).toBe('christmas');
    expect(normalizeName('COM.')).toBeNull();
    expect(normalizeName('gq')).toBe('gq');
    expect(normalizeName('co.com')).toBe('co.com');
    expect(normalizeName('dpdns.org')).toBe('dpdns.org');
    expect(normalizeName('xn--p1ai.')).toBe('xn--p1ai');
  });

  test('parses Adblock TLD rules and ignores comments', () => {
    const names = parseHageziList(`
[Adblock Plus]
! Title: HaGeZi's The World's Most Abused TLDs
||actor^
||co.com^
||gq^
||COM^
`);
    expect(names).toEqual(['actor', 'co.com', 'gq']);
  });

  test('pins .christmas .mov .zip even when HaGeZi omits them', () => {
    expect(mergeAlwaysInclude(['actor', 'gq'])).toEqual([
      'actor',
      'gq',
      'christmas',
      'mov',
      'zip',
    ]);
    expect(mergeAlwaysInclude(['zip', 'christmas'])).toEqual(['zip', 'christmas', 'mov']);
  });

  test('formats a hosts-style list with HaGeZi attribution', () => {
    const text = renderList({
      names: mergeAlwaysInclude(['actor', 'christmas']),
      homepage: 'https://github.com/example/antiwire',
    });
    expect(text).toContain('# Source: https://github.com/hagezi/dns-blocklists');
    expect(text).toContain('# Homepage: https://github.com/example/antiwire\n');
    expect(text).toContain('\nactor\n');
    expect(text).toContain('\nchristmas\n');
    expect(text).toContain('\nmov\n');
    expect(text).toContain('\nzip\n');
    expect(text).not.toContain('\ncom\n');
  });

  test('hashes the published file and stays stable for the same names', () => {
    const body = renderList({ names: ['actor', 'zip'] });
    const hex = fileHash(body);
    expect(hex).toMatch(/^[0-9a-f]{64}$/u);
    expect(fileHash(body)).toBe(hex);
    expect(fileHash(renderList({ names: ['actor', 'boats'] }))).not.toBe(hex);

    const sidecar = renderHashFile(hex);
    expect(parseHashFile(sidecar)).toBe(hex);
    expect(parseHashFile(`# note\n${hex}  hagezi-abused-tlds.txt\n`)).toBe(hex);
    expect(parseHashFile('not-a-hash')).toBeNull();
  });
});
