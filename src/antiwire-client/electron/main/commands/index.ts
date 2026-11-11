import { aiCommands } from './ai';
import { alertCommands } from './alerts';
import { captureCommands } from './capture';
import { connectionCommands } from './connection';
import type { CommandTable } from './define';
import { externalCommands } from './external';
import { fileCommands } from './files';
import { iconCommands } from './icons';
import { inspectorCommands } from './inspector';
import { netmapCommands } from './netmap';
import { recordCommands } from './records';
import { ruleCommands } from './rules';
import { settingsCommands } from './settings';
import { statsCommands } from './stats';
import { updateCommands } from './updates';
import { windowCommands } from './window';

/** Every command in `shared/ipc.ts`; the type rejects a missing or unknown one. */
export const commandTable: CommandTable = {
  ...aiCommands,
  ...alertCommands,
  ...connectionCommands,
  ...fileCommands,
  ...statsCommands,
  ...ruleCommands,
  ...settingsCommands,
  ...recordCommands,
  ...externalCommands,
  ...iconCommands,
  ...captureCommands,
  ...netmapCommands,
  ...updateCommands,
  ...windowCommands,
  ...inspectorCommands,
};
