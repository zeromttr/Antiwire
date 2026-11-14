import { describe, expect, test } from 'bun:test';
import { isValidCidr, isValidDomain, isValidIp, isValidIpv4, isValidIpv6 } from './network-target';

describe('network-target', () => {
  test('validates ipv4 hosts', () => {
    expect(isValidIpv4('10.0.0.1')).toBe(true);
    expect(isValidIpv4('10.0.0.1/24')).toBe(false);
    expect(isValidIpv4('999.0.0.1')).toBe(false);
  });

  test('validates cidr ranges', () => {
    expect(isValidCidr('192.168.1.0/24')).toBe(true);
    expect(isValidCidr('10.0.0.1')).toBe(false);
    expect(isValidCidr('10.0.0.0/33')).toBe(false);
  });

  test('validates ipv6 hosts the same way the daemon does', () => {
    expect(isValidIpv6('::1')).toBe(true);
    expect(isValidIpv6('2001:db8::1')).toBe(true);
    expect(isValidIpv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true);
    expect(isValidIpv6('::ffff:192.0.2.1')).toBe(true);
    expect(isValidIpv6('foo:bar')).toBe(false);
    expect(isValidIpv6(':')).toBe(false);
    expect(isValidIpv6('::')).toBe(true);
    expect(isValidIp('10.0.0.1')).toBe(true);
    expect(isValidIp('fe80::1')).toBe(true);
    expect(isValidIp('foo:bar')).toBe(false);
  });

  test('validates domains', () => {
    expect(isValidDomain('example.com')).toBe(true);
    expect(isValidDomain('api.example.co.uk')).toBe(true);
    expect(isValidDomain('*.example.com')).toBe(true);
    expect(isValidDomain('*.ads.example.co.uk')).toBe(true);
    expect(isValidDomain('not a domain')).toBe(false);
    expect(isValidDomain('*.com')).toBe(true);
    expect(isValidDomain('.com')).toBe(true);
    expect(isValidDomain('.co.uk')).toBe(true);
    expect(isValidDomain('*.рф')).toBe(true);
    expect(isValidDomain('пример.рф')).toBe(true);
    expect(isValidDomain('*example.com')).toBe(false);
    expect(isValidDomain('foo.*.example.com')).toBe(false);
  });
});
