import type { ComponentProps } from 'react';
import { ToggleRow } from '#lib/components/ui/ToggleRow.tsx';

/**
 * ToggleRow inside a settings card. The wrapper has no box (`display:
 * contents`, settings-form.css); it gives the card and the page a class to
 * style the row by, since ToggleRow's own class names are CSS-module scoped.
 */
export function SettingsToggleRow(props: ComponentProps<typeof ToggleRow>) {
  return (
    <div className="toggle-row">
      <ToggleRow {...props} />
    </div>
  );
}

export default SettingsToggleRow;
