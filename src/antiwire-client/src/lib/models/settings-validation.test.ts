import { describe, expect, it } from 'bun:test';
import {
  isValidOptionalHostname,
  isValidOptionalHttpUrl,
  isValidPort,
} from './settings-validation';

describe('settings validation', () => {
  it('accepts empty optional http urls and rejects non-http schemes', () => {
    expect(isValidOptionalHttpUrl('')).toBe(true);
    expect(isValidOptionalHttpUrl('https://dns.example.com/dns-query')).toBe(true);
    expect(isValidOptionalHttpUrl('ftp://dns.example.com/dns-query')).toBe(false);
    expect(isValidOptionalHttpUrl('not-a-url')).toBe(false);
  });

  it('accepts hostnames and IP addresses, rejects urls', () => {
    expect(isValidOptionalHostname('')).toBe(true);
    expect(isValidOptionalHostname('siem.internal')).toBe(true);
    expect(isValidOptionalHostname('10.0.0.8')).toBe(true);
    expect(isValidOptionalHostname('[::1]')).toBe(true);
    expect(isValidOptionalHostname('https://siem.internal')).toBe(false);
    expect(isValidOptionalHostname('host/path')).toBe(false);
  });

  it('accepts TCP/UDP ports in the 1-65535 range', () => {
    expect(isValidPort(1)).toBe(true);
    expect(isValidPort(514)).toBe(true);
    expect(isValidPort(65535)).toBe(true);
    expect(isValidPort(0)).toBe(false);
    expect(isValidPort(65536)).toBe(false);
    expect(isValidPort(1.5)).toBe(false);
  });
});
