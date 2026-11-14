import { describe, expect, it } from 'bun:test';
import { protocolFilterValue, sortDirToDescending, sortKeyToOrderBy } from './records-sort';

describe('records sort mapping', () => {
  it('maps UI sort keys to server order_by tokens', () => {
    expect(sortKeyToOrderBy(null)).toBe('last_seen');
    expect(sortKeyToOrderBy('down')).toBe('bytes_received');
    expect(sortKeyToOrderBy('geo')).toBe('country');
    expect(sortKeyToOrderBy('app')).toBe('app');
  });

  it('maps sort direction to descending flag', () => {
    expect(sortDirToDescending(null, -1)).toBe(true);
    expect(sortDirToDescending('port', -1)).toBe(true);
    expect(sortDirToDescending('port', 1)).toBe(false);
  });

  it('normalizes protocol filter values', () => {
    expect(protocolFilterValue('ALL')).toBeUndefined();
    expect(protocolFilterValue('tcp')).toBe('TCP');
    expect(protocolFilterValue(' UDP ')).toBe('UDP');
  });
});
