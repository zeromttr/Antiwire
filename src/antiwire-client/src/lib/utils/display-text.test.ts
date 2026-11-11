import { describe, expect, test } from 'bun:test';
import { displayText } from './display-text';

describe('displayText', () => {
  test('escapes bidi and zero-width format controls', () => {
    expect(displayText('report\u{202E}exe\u{200B}.old')).toBe(
      String.raw`report\u{202E}exe\u{200B}.old`,
    );
  });

  test('preserves ordinary Unicode executable paths', () => {
    expect(displayText('C:\\程序\\应用.exe')).toBe('C:\\程序\\应用.exe');
  });

  test('removes line and C0 controls from visible text', () => {
    expect(displayText('line\n\ttext')).toBe('linetext');
  });

  test('escapes supplementary Unicode format controls', () => {
    expect(displayText('a\u{E0001}b\u{E0020}c')).toBe(String.raw`a\u{E0001}b\u{E0020}c`);
  });

  test('removes C1 controls while preserving ordinary Unicode', () => {
    expect(displayText('程序\u{0085}应用\u{009F}🚀')).toBe('程序应用🚀');
  });
});
