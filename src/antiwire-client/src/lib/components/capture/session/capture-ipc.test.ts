import { describe, expect, it, spyOn } from 'bun:test';
import { api } from '#lib/api/daemon.ts';
import { createCaptureIpc } from './capture-ipc';

describe('createCaptureIpc', () => {
  it('sends the application selection to the daemon', async () => {
    const start = spyOn(api, 'startCapture').mockResolvedValue('cap-1');
    try {
      const ipc = createCaptureIpc();

      await ipc.startCapture({
        deviceName: 'eth0',
        appPath: 'C:\\Apps\\edge.exe',
        appName: 'Edge',
        captureFilter: '',
        snapLength: 65535,
        promiscuous: false,
        maxSeconds: 300,
        maxBytes: 1024,
      });

      expect(start).toHaveBeenCalledWith(
        expect.objectContaining({ appPath: 'C:\\Apps\\edge.exe', appName: 'Edge' }),
      );
    } finally {
      start.mockRestore();
    }
  });

  it('delegates downloads to the injected transport (failure path)', async () => {
    const calls: Array<{ captureId: string; path: string }> = [];
    const ipc = createCaptureIpc({
      downloadCapture: async (captureId: string, path: string) => {
        calls.push({ captureId, path });
        throw new Error('daemon rejected download');
      },
    });

    await expect(ipc.downloadCapture('cap-1', '/tmp/a.pcap')).rejects.toThrow(
      'daemon rejected download',
    );
    expect(calls).toEqual([{ captureId: 'cap-1', path: '/tmp/a.pcap' }]);
  });

  it('returns null from an overridden save dialog when cancelled', async () => {
    const ipc = createCaptureIpc({
      pickSavePath: async () => null,
    });

    await expect(ipc.pickSavePath('a.pcap', 'PCAP')).resolves.toBeNull();
  });

  it('propagates dialog failures as Errors for user feedback', async () => {
    const ipc = createCaptureIpc({
      pickSavePath: async () => {
        throw new Error('dialog unavailable');
      },
    });

    await expect(ipc.pickSavePath('a.pcap', 'PCAP')).rejects.toThrow('dialog unavailable');
  });
});
