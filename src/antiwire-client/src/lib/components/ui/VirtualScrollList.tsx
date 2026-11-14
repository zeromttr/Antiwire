import { ErrorBoundary } from './ErrorBoundary.tsx';
import { VirtualScrollListView, type VirtualScrollListProps } from './VirtualScrollListView.tsx';

export type { VirtualScrollListProps };

/** A virtualized, fixed-row-height list inside a `list` error boundary. */
export function VirtualScrollList<T>(props: VirtualScrollListProps<T>) {
  return (
    <ErrorBoundary kind="list">
      <VirtualScrollListView {...props} />
    </ErrorBoundary>
  );
}

export default VirtualScrollList;
