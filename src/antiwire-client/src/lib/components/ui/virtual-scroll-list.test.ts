import { describe, expect, it } from 'bun:test';
import { resolveVirtualItemKey } from './virtual-scroll-list';

describe('resolveVirtualItemKey', () => {
  it('falls back to index when no key function is provided', () => {
    expect(resolveVirtualItemKey(2, [{ id: 'a' }, { id: 'b' }, { id: 'c' }])).toBe(2);
  });

  it('falls back to index when the item is missing', () => {
    expect(resolveVirtualItemKey(5, [{ id: 'a' }], (item) => item.id)).toBe(5);
  });

  it('uses the caller key for objects', () => {
    const items = [
      { path: 'C:\\a.exe', name: 'A' },
      { path: 'C:\\b.exe', name: 'B' },
    ];
    expect(resolveVirtualItemKey(1, items, (item) => `${item.name}::${item.path}`)).toBe(
      'B::C:\\b.exe',
    );
  });

  it('accepts 0 as a valid numeric key', () => {
    expect(resolveVirtualItemKey(0, [{ id: 0 }], (item) => item.id)).toBe(0);
  });

  it('rejects empty string keys', () => {
    expect(resolveVirtualItemKey(3, [{ id: '' }], (item) => item.id)).toBe(3);
  });
});
