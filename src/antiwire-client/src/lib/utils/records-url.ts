export function parseTimeWindowParam(value: string | null): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

export function parseApplicationParam(value: string | null): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

export function parseApplicationIdParam(value: string | null): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

export function recordsTimeWindowUrl(start: number, end: number): string {
  return `/records?from=${start}&to=${end}`;
}

export function recordsApplicationUrl(applicationName: string): string {
  const params = new URLSearchParams({ app: applicationName });
  return `/records?${params.toString()}`;
}
