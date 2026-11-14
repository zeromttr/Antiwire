import type { BrowserWindow, WebContents } from 'electron';
import { z } from 'zod';
import type { CommandName, WindowRole } from '#shared/ipc';

/** What a handler knows about the call besides its arguments. */
export interface CommandContext {
  /** The webContents that invoked the command. */
  sender: WebContents;
  /** The kind of window the sender is; already checked against the command. */
  role: WindowRole;
  /** The sender's window, if it still exists. */
  window: BrowserWindow | null;
}

export type CommandHandler = (args: unknown, ctx: CommandContext) => Promise<unknown>;

/** One handler per command; the compiler rejects a missing or unknown name. */
export type CommandTable = Record<CommandName, CommandHandler>;

/**
 * Builds a handler that validates its arguments before running. Unknown keys
 * are rejected so a renderer/main mismatch fails loudly instead of being
 * silently ignored.
 */
export function command<Shape extends z.ZodRawShape, Result>(
  shape: Shape,
  run: (args: z.infer<z.ZodObject<Shape>>, ctx: CommandContext) => Result | Promise<Result>,
): CommandHandler {
  const schema = z.strictObject(shape);
  return async (raw, ctx) => {
    const parsed = schema.safeParse(raw ?? {});
    if (!parsed.success) {
      throw new Error(`Invalid arguments: ${z.prettifyError(parsed.error)}`);
    }
    return run(parsed.data, ctx);
  };
}

/** Handler for a command that takes no arguments. */
export function noArgs<Result>(
  run: (ctx: CommandContext) => Result | Promise<Result>,
): CommandHandler {
  return command({}, (_args, ctx) => run(ctx));
}

/** Shared argument schemas. */
export const arg = {
  /** Unsigned 32-bit integer, as the daemon's proto fields expect. */
  u32: () => z.number().int().min(0).max(0xffff_ffff),
  i32: () => z.number().int().min(-0x8000_0000).max(0x7fff_ffff),
  /** Unix seconds / byte counts: non-negative safe integers. */
  u64: () => z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  /** Bounded string; IPC arguments never need to be large. */
  text: (max = 4096) => z.string().max(max),
};
