import { shell } from 'electron';
import { isReputationService, reputationUrl } from '../reputation';
import { arg, command, type CommandTable } from './define';

export const externalCommands = {
  /** Opens `service`'s reputation report for `domain` in the default browser. */
  open_domain_reputation: command(
    { service: arg.text(32), domain: arg.text(512) },
    async ({ service, domain }) => {
      if (!isReputationService(service)) throw new Error(`unknown reputation service '${service}'`);
      const url = reputationUrl(service, domain);
      if (!url) throw new Error('not a valid domain');
      await shell.openExternal(url);
    },
  ),
} satisfies Partial<CommandTable>;
