import { z } from 'zod';
import { daemon } from '../daemon/connection';
import { countryRulesToDto, ruleSupportToDto, rulesToDto } from '../dto/rules';
import { arg, command, noArgs, type CommandTable } from './define';

const action = arg.text(16);
const direction = arg.text(16).nullish();
const countryCode = arg.text(8);
/** A large country is tens of thousands of networks. */
const cidrs = z.array(arg.text(64)).max(200_000);

/**
 * Country mutations return the daemon's rejection reason too: the plain rule
 * commands return a bare bool, but a country block has far more ways to be
 * rejected, so the reason is worth surfacing.
 */
const countryAction = ({ success, message }: { success: boolean; message: string }) => ({
  success,
  message,
});

export const ruleCommands = {
  get_rules: noArgs(async () => rulesToDto(await daemon.unary('GetRules', {}))),

  add_rule: command(
    { targetType: arg.text(32), targetValue: arg.text(4096), action, direction },
    async (a) =>
      (
        await daemon.unary('AddRule', {
          id: 0,
          targetType: a.targetType,
          targetValue: a.targetValue,
          action: a.action,
          direction: a.direction ?? '',
        })
      ).success,
  ),

  remove_rule: command(
    { id: arg.u32(), targetType: arg.text(32), targetValue: arg.text(4096), action },
    async (a) =>
      (
        await daemon.unary('RemoveRule', {
          id: a.id,
          targetType: a.targetType,
          targetValue: a.targetValue,
          action: a.action,
          // Removal is keyed by id/target; direction is not part of the lookup.
          direction: '',
        })
      ).success,
  ),

  get_country_rules: noArgs(async () => countryRulesToDto(await daemon.unary('GetRules', {}))),

  get_rule_support: noArgs(async () => ruleSupportToDto(await daemon.unary('GetRules', {}))),

  add_country_rule: command({ countryCode, cidrs, action, direction }, async (a) =>
    countryAction(
      await daemon.unary('AddCountryRule', {
        id: 0,
        countryCode: a.countryCode,
        action: a.action,
        direction: a.direction ?? '',
        cidrs: a.cidrs,
      }),
    ),
  ),

  remove_country_rule: command({ id: arg.u32(), countryCode }, async (a) =>
    countryAction(
      await daemon.unary('RemoveCountryRule', {
        id: a.id,
        countryCode: a.countryCode,
        action: '',
        direction: '',
        cidrs: [],
      }),
    ),
  ),
} satisfies Partial<CommandTable>;
