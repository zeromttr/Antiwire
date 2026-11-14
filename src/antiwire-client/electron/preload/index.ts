import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron';
import {
  EVENT_CHANNEL,
  INVOKE_CHANNEL,
  isCommandName,
  isEventName,
  type AntiwireBridge,
  type EventName,
  type InvokeResult,
} from '#shared/ipc';

/**
 * The renderer's only door to the main process. It exposes two functions, not
 * `ipcRenderer`, so page script cannot reach arbitrary channels. The main
 * process re-checks every call (sender, window role, arguments); the checks
 * here only fail fast.
 */

type Handler = (payload: unknown) => void;
const listeners = new Map<EventName, Set<Handler>>();

ipcRenderer.on(EVENT_CHANNEL, (_event: IpcRendererEvent, name: unknown, payload: unknown) => {
  if (!isEventName(name)) return;
  for (const handler of listeners.get(name) ?? []) {
    try {
      handler(payload);
    } catch (error) {
      console.error(`[antiwire] ${name} listener failed`, error);
    }
  }
});

const bridge: AntiwireBridge = {
  async invoke(command, args) {
    if (!isCommandName(command)) throw new Error(`Unknown command '${String(command)}'`);
    const result = (await ipcRenderer.invoke(INVOKE_CHANNEL, command, args ?? {})) as InvokeResult;
    if (!result || typeof result !== 'object') throw new Error(`'${command}' returned no result`);
    if (!result.ok) throw new Error(result.error);
    return result.value;
  },
  on(event, handler) {
    if (!isEventName(event)) throw new Error(`Unknown event '${String(event)}'`);
    let set = listeners.get(event);
    if (!set) listeners.set(event, (set = new Set()));
    const wrapped = handler as Handler;
    set.add(wrapped);
    return () => {
      set.delete(wrapped);
    };
  },
  platform: process.platform,
};

contextBridge.exposeInMainWorld('antiwire', bridge);
