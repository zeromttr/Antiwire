import { describe, expect, it } from 'bun:test';
import { hidesToTray } from './window-frame';

describe('hidesToTray', () => {
  it('keeps the window reachable on Linux, where there may be no tray', () => {
    expect(hidesToTray('linux')).toBe(false);
    expect(hidesToTray('win32')).toBe(true);
    expect(hidesToTray('darwin')).toBe(true);
  });
});
