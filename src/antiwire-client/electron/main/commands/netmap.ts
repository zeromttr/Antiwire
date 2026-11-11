import { z } from 'zod';
import { daemon } from '../daemon/connection';
import { networkMappingToDto } from '../dto/netmap';
import { arg, command, noArgs, type CommandTable } from './define';

const scanRange = { id: arg.i32(), adapterId: arg.text(256), cidr: arg.text(64) };

export const netmapCommands = {
  get_network_mapping_state: noArgs(async () =>
    networkMappingToDto(await daemon.unary('GetNetworkMappingState', {})),
  ),

  scan_network: command(
    { cidrRanges: z.array(arg.text(64)).max(64) },
    async ({ cidrRanges }) => (await daemon.unary('ScanNetwork', { cidrRanges })).success,
  ),

  stop_network_scan: noArgs(async () => (await daemon.unary('StopNetworkScan', {})).success),

  clear_network_devices: noArgs(
    async () => (await daemon.unary('ClearNetworkDevices', {})).success,
  ),

  save_network_scan_range: command(
    scanRange,
    async (a) => (await daemon.unary('SaveNetworkScanRange', a)).success,
  ),

  remove_network_scan_range: command(
    scanRange,
    async (a) => (await daemon.unary('RemoveNetworkScanRange', a)).success,
  ),

  save_network_device_watch: command(
    {
      id: arg.i32(),
      ipAddress: arg.text(64),
      macAddress: arg.text(64),
      adapterId: arg.text(256),
      cidr: arg.text(64),
      intervalMinutes: arg.u32(),
      enabled: z.boolean(),
    },
    async (a) =>
      (await daemon.unary('SaveNetworkDeviceWatch', { ...a, present: false, lastChecked: '' }))
        .success,
  ),

  remove_network_device_watch: command(
    { id: arg.i32(), macAddress: arg.text(64), adapterId: arg.text(256), cidr: arg.text(64) },
    async (a) =>
      (
        await daemon.unary('RemoveNetworkDeviceWatch', {
          ...a,
          ipAddress: '',
          intervalMinutes: 0,
          enabled: false,
          present: false,
          lastChecked: '',
        })
      ).success,
  ),

  update_oui_database: noArgs(async () => (await daemon.unary('UpdateOuiDatabase', {})).success),
} satisfies Partial<CommandTable>;
