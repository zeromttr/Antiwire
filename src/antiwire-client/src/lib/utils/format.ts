import { m } from '#lib/i18n/messages.ts';
import { getLocale } from '#lib/paraglide/runtime.js';

const BYTES_PER_KB = 1024;
const BYTES_PER_MB = 1024 * 1024;
const BYTES_PER_GB = 1024 * 1024 * 1024;

function intlLocale(): string {
  const locale = getLocale();
  // Prefer region tags that produce 24h-friendly defaults where common.
  switch (locale) {
    case 'en':
      return 'en-GB';
    case 'pt':
      return 'pt-PT';
    case 'nb':
      return 'nb-NO';
    default:
      return locale;
  }
}

export function formatBytes(bytes: number): string {
  if (bytes >= BYTES_PER_GB) {
    return m.common_format_bytes_gb({ value: (bytes / BYTES_PER_GB).toFixed(1) });
  }
  if (bytes >= BYTES_PER_MB) {
    return m.common_format_bytes_mb({ value: (bytes / BYTES_PER_MB).toFixed(1) });
  }
  if (bytes >= 1024) {
    return m.common_format_bytes_kb({ value: (bytes / 1024).toFixed(1) });
  }
  return m.common_format_bytes_b({ value: bytes });
}

export type ThroughputDisplay = {
  value: string;
  unit: string;
  label: string;
};

function trimTrailingZero(value: string): string {
  return value.replace(/\.0$/, '');
}

export function formatThroughput(bytesPerSecond: number): ThroughputDisplay {
  const rate = Number(bytesPerSecond);
  if (!Number.isFinite(rate) || rate <= 0) {
    const unit = m.common_unit_b_per_s();
    const value = '0';
    return { value, unit, label: m.common_format_throughput({ value, unit }) };
  }

  if (rate < BYTES_PER_KB) {
    const value = rate < 10 ? trimTrailingZero(rate.toFixed(1)) : String(Math.round(rate));
    const unit = m.common_unit_b_per_s();
    return { value, unit, label: m.common_format_throughput({ value, unit }) };
  }

  if (rate < BYTES_PER_MB) {
    const kb = rate / BYTES_PER_KB;
    const value = kb < 10 ? trimTrailingZero(kb.toFixed(1)) : String(Math.round(kb));
    const unit = m.common_unit_kb_per_s();
    return { value, unit, label: m.common_format_throughput({ value, unit }) };
  }

  if (rate < BYTES_PER_GB) {
    const mb = rate / BYTES_PER_MB;
    const value = mb < 10 ? trimTrailingZero(mb.toFixed(1)) : String(Math.round(mb));
    const unit = m.common_unit_mb_per_s();
    return { value, unit, label: m.common_format_throughput({ value, unit }) };
  }

  const gb = rate / BYTES_PER_GB;
  const value = gb < 10 ? trimTrailingZero(gb.toFixed(1)) : String(Math.round(gb));
  const unit = m.common_unit_gb_per_s();
  return { value, unit, label: m.common_format_throughput({ value, unit }) };
}

/** Whole-number Y-axis tick labels (1–999) with B / KB / MB / GB. */
export function formatThroughputAxisTick(value: unknown): string {
  const rate = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(rate) || rate <= 0) {
    return m.common_format_axis_tick({ value: 0, unit: m.common_unit_b() });
  }

  const units: { div: number; suffix: () => string }[] = [
    { div: 1, suffix: () => m.common_unit_b() },
    { div: BYTES_PER_KB, suffix: () => m.common_unit_kb() },
    { div: BYTES_PER_MB, suffix: () => m.common_unit_mb() },
    { div: BYTES_PER_GB, suffix: () => m.common_unit_gb() },
  ];

  let unit = units[0];
  for (const candidate of units) {
    unit = candidate;
    if (rate / candidate.div < 1000) break;
  }

  const rounded = Math.round(rate / unit.div);
  if (rounded <= 0) {
    return m.common_format_axis_tick({ value: 0, unit: m.common_unit_b() });
  }
  return m.common_format_axis_tick({
    value: Math.min(999, rounded),
    unit: unit.suffix(),
  });
}

export function toEpochMs(ts: number): number {
  if (!Number.isFinite(ts) || ts <= 0) return 0;
  return ts < 1e12 ? ts * 1000 : ts;
}

export function formatTimestamp(ts: number): string {
  const ms = toEpochMs(ts);
  if (!ms) return m.common_em_dash();
  return new Date(ms).toLocaleTimeString(intlLocale(), { hour12: false });
}

export function formatDateTime(ts: number): string {
  const ms = toEpochMs(ts);
  if (!ms) return '';
  return new Date(ms).toLocaleString(intlLocale(), {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

/** Calendar date only, e.g. `14 Aug 1995`; `''` for a missing timestamp. */
export function formatDate(ts: number): string {
  const ms = toEpochMs(ts);
  if (!ms) return '';
  return new Date(ms).toLocaleDateString(intlLocale(), {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function formatTimeAgo(ts: number, now = Date.now()): string {
  const ms = toEpochMs(ts);
  if (!ms) return m.common_em_dash();

  const delta = Math.max(0, now - ms);
  const seconds = Math.floor(delta / 1000);
  if (seconds < 60) return m.common_format_time_ago_s({ count: seconds });

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return m.common_format_time_ago_m({ count: minutes });

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return m.common_format_time_ago_h({ count: hours });

  const days = Math.floor(hours / 24);
  if (days < 7) return m.common_format_time_ago_d({ count: days });

  const weeks = Math.floor(days / 7);
  if (days < 30) return m.common_format_time_ago_w({ count: weeks });

  const months = Math.floor(days / 30);
  if (months < 12) return m.common_format_time_ago_mo({ count: months });

  const years = Math.floor(days / 365);
  return m.common_format_time_ago_y({ count: years });
}

export function formatCompactCount(n: number): string {
  const value = Number(n);
  if (!Number.isFinite(value)) return '0';
  const abs = Math.abs(value);
  if (abs < 1000) return String(Math.trunc(value));
  if (abs < 1_000_000) {
    const scaled = value / 1000;
    const digits = abs < 10_000 ? 1 : 0;
    const formatted = scaled.toFixed(digits).replace(/\.0$/, '');
    return m.common_format_compact_k({ value: formatted });
  }
  const scaled = value / 1_000_000;
  const digits = abs < 10_000_000 ? 1 : 0;
  const formatted = scaled.toFixed(digits).replace(/\.0$/, '');
  return m.common_format_compact_m({ value: formatted });
}

export function initials(name?: string | null): string {
  const safe = (name ?? '').trim();
  if (!safe) return '';
  const parts = safe.split(/\s+/).filter(Boolean);
  if (parts.length >= 2 && parts[0] && parts[1]) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return safe.slice(0, 2).toUpperCase();
}

export function appTint(name?: string | null): string {
  const colors = ['#7EC8E3', '#5FD69B', '#F2C14E', '#B388FF', '#F06767', '#4DD8E6', '#C6CBD4'];
  const safe = (name ?? '').trim();
  if (!safe) return colors[0];
  let hash = 0;
  for (let i = 0; i < safe.length; i++) hash = safe.charCodeAt(i) + ((hash << 5) - hash);
  return colors[Math.abs(hash) % colors.length];
}

export { isNative } from '../bridge.ts';
