import { describe, expect, it } from 'bun:test';
import { TaskSlot } from './task-slot';

describe('TaskSlot', () => {
  it('aborts the previous task when replaced', () => {
    const slot = new TaskSlot();
    const first = slot.replace('first');
    const second = slot.replace('second');
    expect(first.aborted).toBe(true);
    expect(second.aborted).toBe(false);
  });

  it('aborts only the task stored under the given key', () => {
    const slot = new TaskSlot();
    const third = slot.replace('third');
    slot.abortIf('other');
    expect(third.aborted).toBe(false);
    slot.abortIf('third');
    expect(third.aborted).toBe(true);
  });

  it('lets a finished task free the slot without touching a newer one', () => {
    const slot = new TaskSlot();
    const old = slot.replace('a');
    const current = slot.replace('b');
    slot.finish(old);
    expect(current.aborted).toBe(false);
    slot.finish(current);
    expect(current.aborted).toBe(true);
  });
});
