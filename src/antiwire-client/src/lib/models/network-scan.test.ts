import { describe, expect, test } from 'bun:test';
import { privateNetworkClass, scanSuggestions } from './network-scan';

describe('network scan suggestions', () => {
  test('identifies the private Class A, B, and C address families', () => {
    expect(privateNetworkClass('10.24.0.0/16')).toBe('A');
    expect(privateNetworkClass('172.20.4.0/24')).toBe('B');
    expect(privateNetworkClass('192.168.68.0/24')).toBe('C');
  });

  test('does not label invalid or public ranges as private classes', () => {
    expect(privateNetworkClass('8.8.8.0/24')).toBeNull();
    expect(privateNetworkClass('not-a-range')).toBeNull();
  });

  test('keeps interface details and supplies a friendly fallback label', () => {
    expect(
      scanSuggestions([
        { id: 1, adapterId: 'Wi-Fi', cidr: '192.168.1.0/24' },
        { id: 2, adapterId: '', cidr: '10.0.0.0/24' },
      ]),
    ).toEqual([
      {
        id: 1,
        adapterId: 'Wi-Fi',
        cidr: '192.168.1.0/24',
        networkClass: 'C',
        interfaceLabel: 'Wi-Fi',
      },
      {
        id: 2,
        adapterId: '',
        cidr: '10.0.0.0/24',
        networkClass: 'A',
        interfaceLabel: 'Network interface 2',
      },
    ]);
  });
});
