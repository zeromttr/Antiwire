import { daemon } from '../daemon/connection';
import { activeApplicationsToDto, statsToDto } from '../dto/stats';
import { noArgs, type CommandTable } from './define';

export const statsCommands = {
  get_stats: noArgs(async () => statsToDto(await daemon.unary('GetStats', {}))),
  get_active_applications: noArgs(async () =>
    activeApplicationsToDto(await daemon.unary('GetActiveApplications', {})),
  ),
} satisfies Partial<CommandTable>;
