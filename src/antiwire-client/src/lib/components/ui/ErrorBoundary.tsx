import { Component, type ReactNode } from 'react';
import { m } from '#lib/i18n/messages.ts';
import { tryMessage } from '#lib/utils/error.ts';
import { ErrorFallback, type ErrorFallbackVariant } from './ErrorFallback.tsx';

export type ErrorBoundaryKind = 'page' | 'inspector' | 'chart' | 'list';

interface Props {
  children?: ReactNode;
  kind?: ErrorBoundaryKind;
  title?: string;
  retryLabel?: string;
  onError?: (error: unknown) => void;
}

interface State {
  failed: boolean;
  error: unknown;
}

/**
 * Catches render errors below it and shows `ErrorFallback` with a retry that
 * re-mounts the children. To reset it when something outside changes (the
 * route, a selected row), give it a `key`, as the shell does with the pathname.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false, error: null };

  static getDerivedStateFromError(error: unknown): State {
    return { failed: true, error };
  }

  componentDidCatch(error: unknown) {
    console.error('[antiwire] render boundary', error);
    try {
      this.props.onError?.(error);
    } catch (cause) {
      console.error('[antiwire] render boundary onError failed', cause);
    }
  }

  reset = () => {
    this.setState({ failed: false, error: null });
  };

  render() {
    if (!this.state.failed) return this.props.children;
    const { kind = 'page', title = '', retryLabel = '' } = this.props;
    const variant: ErrorFallbackVariant = kind === 'page' || kind === 'inspector' ? kind : 'inline';
    const resolvedTitle =
      title ||
      (kind === 'chart'
        ? tryMessage(() => m.error_chart_title(), 'Chart failed to render')
        : kind === 'list'
          ? tryMessage(() => m.error_list_title(), 'List failed to render')
          : '');
    return (
      <ErrorFallback
        error={this.state.error}
        reset={this.reset}
        variant={variant}
        title={resolvedTitle}
        retryLabel={retryLabel}
      />
    );
  }
}

export default ErrorBoundary;
