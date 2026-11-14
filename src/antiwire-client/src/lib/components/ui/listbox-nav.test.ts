import { describe, expect, it } from 'bun:test';
import { moveActiveIndex } from './listbox-nav';

describe('moveActiveIndex', () => {
  it('moves down/up through a vertical listbox with wrapping', () => {
    expect(moveActiveIndex(0, 4, 'ArrowDown', 'vertical')).toBe(1);
    expect(moveActiveIndex(3, 4, 'ArrowDown', 'vertical')).toBe(0);
    expect(moveActiveIndex(0, 4, 'ArrowUp', 'vertical')).toBe(3);
    expect(moveActiveIndex(2, 4, 'ArrowUp', 'vertical')).toBe(1);
  });

  it('moves left/right through a horizontal tablist with wrapping', () => {
    expect(moveActiveIndex(0, 3, 'ArrowRight', 'horizontal')).toBe(1);
    expect(moveActiveIndex(2, 3, 'ArrowRight', 'horizontal')).toBe(0);
    expect(moveActiveIndex(0, 3, 'ArrowLeft', 'horizontal')).toBe(2);
  });

  it('ignores the off-axis arrows so lists and tablists stay distinct', () => {
    // A vertical dropdown must not react to Left/Right.
    expect(moveActiveIndex(1, 4, 'ArrowRight', 'vertical')).toBe(1);
    expect(moveActiveIndex(1, 4, 'ArrowLeft', 'vertical')).toBe(1);
    // A horizontal segmented control must not react to Up/Down.
    expect(moveActiveIndex(1, 3, 'ArrowDown', 'horizontal')).toBe(1);
    expect(moveActiveIndex(1, 3, 'ArrowUp', 'horizontal')).toBe(1);
  });

  it('jumps to the first/last option on Home/End', () => {
    expect(moveActiveIndex(2, 5, 'Home')).toBe(0);
    expect(moveActiveIndex(2, 5, 'End')).toBe(4);
  });

  it('starts from the nearest end when nothing is active', () => {
    expect(moveActiveIndex(-1, 4, 'ArrowDown', 'vertical')).toBe(0);
    expect(moveActiveIndex(-1, 4, 'ArrowUp', 'vertical')).toBe(3);
    expect(moveActiveIndex(-1, 3, 'ArrowRight', 'horizontal')).toBe(0);
    expect(moveActiveIndex(-1, 3, 'ArrowLeft', 'horizontal')).toBe(2);
  });

  it('reports no active option for an empty list', () => {
    expect(moveActiveIndex(-1, 0, 'ArrowDown')).toBe(-1);
    expect(moveActiveIndex(0, 0, 'End')).toBe(-1);
  });
});
