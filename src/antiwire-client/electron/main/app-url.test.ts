import { describe, expect, it } from 'bun:test';
import path from 'node:path';
import { contentSecurityPolicyFor, isAppUrlFor, resolveInside, withStyleNonce } from './app-url';

const DEV = 'http://localhost:5173/';
const NONCE = 'q0Zc3+uP/8bN2kVw1xYtEg==';

describe('isAppUrlFor', () => {
  it('allows the app origin', () => {
    expect(isAppUrlFor('app://antiwire/', undefined)).toBe(true);
    expect(isAppUrlFor('app://antiwire/inspector', undefined)).toBe(true);
  });

  it('allows the dev server only when one is set', () => {
    expect(isAppUrlFor('http://localhost:5173/records', DEV)).toBe(true);
    expect(isAppUrlFor('http://localhost:5173/records', undefined)).toBe(false);
  });

  it('refuses foreign content', () => {
    for (const url of [
      'https://example.com/',
      'app://evil/',
      'app://antiwire.evil/',
      'http://localhost:5174/',
      'http://127.0.0.1:5173/',
      'file:///C:/Windows/win.ini',
      'data:text/html,<script>1</script>',
      'javascript:alert(1)',
      'about:srcdoc',
      'not a url',
    ]) {
      expect([url, isAppUrlFor(url, DEV)]).toEqual([url, false]);
    }
  });
});

describe('contentSecurityPolicyFor', () => {
  it('allows inline script only in dev', () => {
    expect(contentSecurityPolicyFor(false, undefined)).toContain("script-src 'self';");
    expect(contentSecurityPolicyFor(true, DEV)).toContain("script-src 'self' 'unsafe-inline'");
    expect(contentSecurityPolicyFor(true, DEV)).toContain('http://localhost:5173 ws:');
  });

  it('allows inline styles only in dev, or with the document nonce', () => {
    expect(contentSecurityPolicyFor(false, undefined)).toContain("style-src 'self';");
    expect(contentSecurityPolicyFor(false, undefined, NONCE)).toContain(
      `style-src 'self' 'nonce-${NONCE}';`,
    );
    expect(contentSecurityPolicyFor(true, DEV)).toContain("style-src 'self' 'unsafe-inline'");
  });

  it('refuses data: fonts and workers, and enforces Trusted Types when packaged', () => {
    const csp = contentSecurityPolicyFor(false, undefined, NONCE);
    expect(csp).toContain("font-src 'self';");
    expect(csp).toContain("worker-src 'none'");
    expect(csp).toContain("require-trusted-types-for 'script'; trusted-types 'none'");
    expect(contentSecurityPolicyFor(true, DEV)).not.toContain('trusted-types');
  });
});

describe('withStyleNonce', () => {
  const html =
    '<!doctype html><html><head><style>a{}</style><style media="x">b{}</style></head></html>';

  it('stamps every <style> and publishes the nonce in a meta tag', () => {
    const out = withStyleNonce(html, NONCE);
    expect(
      out.match(new RegExp(`<style nonce="${NONCE.replace(/[+/]/g, '\\$&')}"`, 'g')),
    ).toHaveLength(2);
    expect(out).toContain(`<head>\n    <meta property="csp-nonce" nonce="${NONCE}" />`);
  });

  it('refuses a nonce that could break out of its attribute', () => {
    expect(() => withStyleNonce(html, '"><script>')).toThrow();
    expect(() => withStyleNonce(html, 'short')).toThrow();
  });
});

describe('resolveInside', () => {
  const root = path.resolve('renderer-root');

  it('resolves files inside the root', () => {
    expect(resolveInside(root, '/assets/app.js')).toBe(path.join(root, 'assets', 'app.js'));
    expect(resolveInside(root, '/a/../b.css')).toBe(path.join(root, 'b.css'));
  });

  it('refuses traversal in any spelling', () => {
    for (const request of [
      '/../secret',
      '/%2e%2e/secret',
      '/..%2fsecret',
      '/..%5csecret',
      '/a/%2e%2e%5c%2e%2e%5csecret',
      '/%00',
      '/%E0%A4%A',
    ]) {
      const resolved = resolveInside(root, request);
      expect([request, resolved === null || resolved.startsWith(root + path.sep)]).toEqual([
        request,
        true,
      ]);
    }
    expect(resolveInside(root, '/%00')).toBeNull();
    expect(resolveInside(root, '/%E0%A4%A')).toBeNull();
  });
});
