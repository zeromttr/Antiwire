import SegmentedControl from '#lib/components/ui/SegmentedControl.tsx';
import SearchBox from '#lib/components/ui/SearchBox.tsx';
import { m } from '#lib/i18n/messages.ts';
import type { ActionFilter } from './list/action-filter';
import { showingApplications, type FirewallListType } from './list/firewall-list';
import styles from './FirewallToolbar.module.css';

interface Props {
  /** Controlled search text (was `bind:query`). */
  query?: string;
  onQueryChange?: (next: string) => void;
  listType: FirewallListType;
  filter: ActionFilter;
  visibleCount: number;
  onFilterChange: (next: ActionFilter) => void;
}

export function FirewallToolbar({
  query = '',
  onQueryChange,
  listType,
  filter,
  visibleCount,
  onFilterChange,
}: Props) {
  const appsSelected = showingApplications(listType);
  const filterOptions = [
    { value: 'all', label: m.firewall_filter_all() },
    { value: 'allowed', label: m.firewall_filter_allowed() },
    { value: 'blocked', label: m.firewall_filter_blocked() },
  ];

  return (
    <div className={styles['filter-row']}>
      <SearchBox
        value={query}
        onValueChange={onQueryChange}
        placeholder={
          appsSelected
            ? m.firewall_filter_applications_placeholder()
            : m.firewall_filter_rules_placeholder()
        }
        ariaLabel={
          appsSelected ? m.firewall_filter_applications_aria() : m.firewall_filter_rules_aria()
        }
      />
      <SegmentedControl
        options={filterOptions}
        value={filter}
        ariaLabel={m.firewall_application_filter_aria()}
        onChange={(v) => onFilterChange(v as ActionFilter)}
      />
      <span className={styles.count}>
        {appsSelected
          ? m.firewall_applications_count({ count: visibleCount })
          : m.firewall_rules_count({ count: visibleCount })}
      </span>
    </div>
  );
}

export default FirewallToolbar;
