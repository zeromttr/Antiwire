import { z } from 'zod';
import { approvedSavePaths } from '../approved-paths';
import { writeFileAtomic } from '../atomic-file';
import { daemon } from '../daemon/connection';
import { DaemonError } from '../daemon/errors';
import {
  appSummariesToDto,
  certificateSearchToDto,
  countryStatisticsToDto,
  dnsRecordsToDto,
  domainLookupToDto,
  logRequest,
  logsPageToDto,
  logsToCsv,
  logsToJson,
  seenSubdomainsToDto,
  type LogQuery,
} from '../dto/records';
import { arg, command, noArgs, type CommandTable } from './define';

/** How many rows an export holds. */
const EXPORT_LIMIT = 10_000;

const filter = (max = 512) => arg.text(max).nullish();
const timeWindow = {
  timeFilterSeconds: arg.u32().nullish(),
  timeWindowStart: arg.u64().nullish(),
  timeWindowEnd: arg.u64().nullish(),
};
const hostDomain = { host: arg.text(253), domain: arg.text(253) };

/** `null` from the renderer means unset, like `undefined`. */
function defined<T extends object>(value: T): LogQuery {
  return Object.fromEntries(
    Object.entries(value).filter(([, v]) => v !== null && v !== undefined),
  ) as LogQuery;
}

async function fetchConnectionLogs(query: LogQuery) {
  return logsPageToDto(await daemon.unary('GetConnectionLogs', logRequest(query)));
}

export const recordCommands = {
  get_connection_logs: command(
    {
      offset: arg.u32(),
      limit: arg.u32(),
      applicationName: filter(4096),
      applicationId: arg.i32().nullish(),
      actionFilter: filter(32),
      ...timeWindow,
      searchQuery: filter(),
      orderBy: filter(64),
      sortDescending: z.boolean().nullish(),
      protocolFilter: filter(32),
      countryFilter: filter(16),
      portFilter: arg.u32().nullish(),
      hostFilter: filter(),
    },
    (a) => fetchConnectionLogs(defined(a)),
  ),

  get_country_statistics: noArgs(async () =>
    countryStatisticsToDto(await daemon.unary('GetCountryStatistics', {})),
  ),

  get_app_summaries: command({ actionFilter: filter(32), ...timeWindow }, async (a) =>
    appSummariesToDto(
      await daemon.unary('GetApplicationLogSummaries', {
        searchQuery: '',
        actionFilter: a.actionFilter ?? '',
        timeFilterSeconds: a.timeFilterSeconds ?? 0,
        timeWindowStart: a.timeWindowStart ?? 0,
        timeWindowEnd: a.timeWindowEnd ?? 0,
      }),
    ),
  ),

  get_activity_buckets: command(
    { days: arg.u32().nullish(), since: arg.u64().nullish(), until: arg.u64().nullish() },
    async (a) => {
      const { buckets } = await daemon.unary('GetActivityBuckets', {
        days: a.days ?? 7,
        since: a.since ?? 0,
        until: a.until ?? 0,
      });
      return buckets.map((b) => ({
        bucketStart: b.bucketStart,
        eventCount: b.eventCount,
        bytesSent: b.bytesSent,
        bytesReceived: b.bytesReceived,
        blockedCount: b.blockedCount,
      }));
    },
  ),

  /**
   * Deletes connection history, its dashboard activity and alerts: all of it
   * when `all` is set, otherwise everything from `since` (unix seconds) on.
   * Returns the number of rows the daemon removed.
   */
  delete_history: command({ all: z.boolean(), since: arg.u64().nullish() }, async (a) => {
    const request = { all: a.all, since: a.since ?? 0 };
    // The daemon also refuses this; failing here keeps a missing start from reaching it at all.
    if (!request.all && request.since === 0) {
      throw new DaemonError('A start time is required to delete recent history');
    }
    return (await daemon.unary('DeleteHistory', request)).deletedCount;
  }),

  export_logs: command({ path: arg.text(4096), format: arg.text(8) }, async ({ path, format }) => {
    approvedSavePaths.require(path);
    const page = await fetchConnectionLogs({ limit: EXPORT_LIMIT });
    await writeFileAtomic(path, format === 'json' ? logsToJson(page.logs) : logsToCsv(page.logs));
    return true;
  }),

  // Registry RDAP/WHOIS, the DNS upstream and crt.sh are outside this machine.
  lookup_domain: command({ domain: arg.text(253) }, async ({ domain }) =>
    domainLookupToDto(await daemon.unary('LookupDomain', { domain }, 'slow')),
  ),

  lookup_dns_records: command({ ...hostDomain, address: arg.text(64) }, async (a) =>
    dnsRecordsToDto(await daemon.unary('LookupDnsRecords', a, 'slow')),
  ),

  // Finding the domain may ask the DNS upstream for the host's zone.
  get_seen_subdomains: command(hostDomain, async (a) =>
    seenSubdomainsToDto(await daemon.unary('GetSeenSubdomains', a, 'slow')),
  ),

  search_certificates: command(hostDomain, async (a) =>
    certificateSearchToDto(await daemon.unary('SearchCertificates', a, 'slow')),
  ),
} satisfies Partial<CommandTable>;
