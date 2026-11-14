import { daemon } from '../daemon/connection';
import { decisionsPageToDto, decisionToDto } from '../dto/ai';
import { arg, command, type CommandTable } from './define';

const domain = { domain: arg.text(253) };

export const aiCommands = {
  get_ai_decisions: command(
    {
      limit: arg.u32().nullish(),
      offset: arg.u32().nullish(),
      verdictFilter: arg.text(16).nullish(),
      searchQuery: arg.text(512).nullish(),
    },
    async (a) =>
      decisionsPageToDto(
        await daemon.unary('GetAiDecisions', {
          limit: a.limit ?? 0,
          offset: a.offset ?? 0,
          verdictFilter: a.verdictFilter ?? '',
          searchQuery: a.searchQuery ?? '',
        }),
      ),
  ),

  delete_ai_decision: command(
    domain,
    async ({ domain }) => (await daemon.unary('DeleteAiDecision', { domain })).success,
  ),

  // Both wait on the AI backend, outside this machine.
  refresh_ai_decision: command(domain, async ({ domain }) =>
    decisionToDto(await daemon.unary('RefreshAiDecision', { domain }, 'slow')),
  ),

  advanced_ai_decision: command(domain, async ({ domain }) =>
    decisionToDto(await daemon.unary('AdvancedAiDecision', { domain }, 'slow')),
  ),
} satisfies Partial<CommandTable>;
