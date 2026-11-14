import { describe, expect, test } from 'bun:test';
import {
  APP_ICON_CACHE_MAX,
  APP_ICON_MISSING_CACHE_MAX,
  IconSrcLru,
  isIconDataUrl,
} from './app-icon-cache';

describe('IconSrcLru', () => {
  test('evicts the least recently touched key past the cap', () => {
    const lru = new IconSrcLru(2);
    lru.touch('a');
    lru.touch('b');
    lru.touch('c');
    expect(lru.evict()).toEqual(['a']);
    expect(lru.keys()).toEqual(['b', 'c']);
  });

  test('touching a key makes it newest', () => {
    const lru = new IconSrcLru(2);
    lru.touch('a');
    lru.touch('b');
    lru.touch('a');
    lru.touch('c');
    expect(lru.evict()).toEqual(['b']);
    expect(lru.keys()).toEqual(['a', 'c']);
  });

  test('remove drops a key without evicting others', () => {
    const lru = new IconSrcLru(3);
    lru.touch('a');
    lru.touch('b');
    lru.touch('c');
    lru.remove('b');
    expect(lru.evict()).toEqual([]);
    expect(lru.keys()).toEqual(['a', 'c']);
  });

  test('default cap matches the store limit', () => {
    const lru = new IconSrcLru();
    for (let i = 0; i < APP_ICON_CACHE_MAX + 5; i += 1) {
      lru.touch(`k${i}`);
    }
    expect(lru.evict()).toHaveLength(5);
    expect(lru.size).toBe(APP_ICON_CACHE_MAX);
  });

  test('missing cap bounds missing keys', () => {
    const lru = new IconSrcLru(APP_ICON_MISSING_CACHE_MAX);
    for (let i = 0; i < APP_ICON_MISSING_CACHE_MAX + 10; i += 1) {
      lru.touch(`missing:${i}`);
    }
    const evicted = lru.evict();
    expect(evicted).toHaveLength(10);
    expect(evicted[0]).toBe('missing:0');
    expect(lru.size).toBe(APP_ICON_MISSING_CACHE_MAX);
  });
});

describe('isIconDataUrl', () => {
  test('accepts base64 PNG data URLs only', () => {
    expect(isIconDataUrl('data:image/png;base64,iVBORw0KGgo=')).toBe(true);
    expect(isIconDataUrl('data:image/png;base64,')).toBe(false);
    expect(isIconDataUrl('data:image/svg+xml;base64,PHN2Zz4=')).toBe(false);
    expect(isIconDataUrl('data:image/png;base64,<script>')).toBe(false);
    expect(isIconDataUrl('C:\\Users\\me\\app-icons\\ab.png')).toBe(false);
    expect(isIconDataUrl('https://example.com/icon.png')).toBe(false);
    expect(isIconDataUrl('')).toBe(false);
    expect(isIconDataUrl(null)).toBe(false);
    expect(isIconDataUrl(42)).toBe(false);
  });
});
