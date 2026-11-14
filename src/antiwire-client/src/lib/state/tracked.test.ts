import { describe, expect, test } from 'bun:test';
import { TrackedReactive } from './tracked.ts';

class Form extends TrackedReactive {
  query = '';
  items: string[] = [];
  untracked = 0;
  computed = 0;

  constructor() {
    super();
    this.track('query', 'items');
  }

  get upper() {
    return this.memo('upper', [this.items], () => {
      this.computed++;
      return this.items.map((item) => item.toUpperCase());
    });
  }
}

describe('TrackedReactive', () => {
  test('assigning a tracked field notifies once per microtask', async () => {
    const form = new Form();
    let calls = 0;
    form.subscribe(() => calls++);
    form.query = 'a';
    form.query = 'ab';
    expect(form.query).toBe('ab');
    await Promise.resolve();
    expect(calls).toBe(1);
  });

  test('assigning the same value or an untracked field does not notify', async () => {
    const form = new Form();
    let calls = 0;
    form.subscribe(() => calls++);
    const version = form.version();
    form.query = '';
    form.untracked = 5;
    await Promise.resolve();
    expect(calls).toBe(0);
    expect(form.version()).toBe(version);
  });

  test('memo recomputes only when a dependency changes identity', () => {
    const form = new Form();
    form.items = ['a'];
    const first = form.upper;
    expect(form.upper).toBe(first);
    expect(form.computed).toBe(1);
    form.items = ['a'];
    expect(form.upper).not.toBe(first);
    expect(form.computed).toBe(2);
  });
});
