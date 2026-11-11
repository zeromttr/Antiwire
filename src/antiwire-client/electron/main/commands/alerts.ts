import { daemon } from '../daemon/connection';
import { DaemonError } from '../daemon/errors';
import { eventToDto, parseAlertId } from '../dto/alerts';
import { arg, command, noArgs, type CommandTable } from './define';

export const alertCommands = {
  get_alerts: noArgs(async () => (await daemon.unary('GetAlerts', {})).alerts.map(eventToDto)),

  dismiss_alert: command({ id: arg.text(64) }, async ({ id }) => {
    const alertId = parseAlertId(id);
    if (!alertId) throw new DaemonError('Invalid alert id');
    // Synthetic notifications only exist in the UI list; there is no daemon
    // row to dismiss, so removal is purely local.
    if (alertId.kind === 'local') return true;
    return (await daemon.unary('DismissAlert', { id: alertId.id })).success;
  }),

  clear_alerts: noArgs(async () => (await daemon.unary('ClearAlerts', {})).success),
} satisfies Partial<CommandTable>;
