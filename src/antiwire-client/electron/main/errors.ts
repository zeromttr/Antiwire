/** A message safe to show the user for anything thrown in the main process. */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message || error.name;
  if (typeof error === 'string') return error;
  return 'Unexpected error';
}
