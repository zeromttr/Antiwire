import clsx from 'clsx';
import type { AnchorHTMLAttributes, ButtonHTMLAttributes, ReactNode, Ref } from 'react';
import styles from './Button.module.css';

/**
 * `danger` is a tinted inline action (Block app); `destructive` is the solid
 * red confirmation at the end of a destructive dialog.
 */
export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'destructive';
export type ButtonSize = 'sm' | 'md';

type Common = {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Square button for a lone icon; pass `aria-label`. */
  iconOnly?: boolean;
  /** Stretch to the container width. */
  block?: boolean;
  className?: string;
  children?: ReactNode;
};

export type ButtonProps = Common &
  (
    | ({ href: string; ref?: Ref<HTMLAnchorElement> } & Omit<
        AnchorHTMLAttributes<HTMLAnchorElement>,
        'className' | 'children' | 'href'
      >)
    | ({ href?: undefined; ref?: Ref<HTMLButtonElement> } & Omit<
        ButtonHTMLAttributes<HTMLButtonElement>,
        'className' | 'children'
      >)
  );

/** The app's button. With `href` it renders a link styled as a button. */
export function Button({
  variant = 'secondary',
  size = 'md',
  iconOnly = false,
  block = false,
  className = '',
  children,
  ...rest
}: ButtonProps) {
  const classes = clsx(
    styles.btn,
    styles[variant],
    styles[size],
    className,
    iconOnly && styles.iconOnly,
    block && styles.block,
  );
  if (rest.href !== undefined) {
    const anchor = rest as AnchorHTMLAttributes<HTMLAnchorElement> & {
      ref?: Ref<HTMLAnchorElement>;
    };
    return (
      <a className={classes} {...anchor}>
        {children}
      </a>
    );
  }
  const button = rest as ButtonHTMLAttributes<HTMLButtonElement> & { ref?: Ref<HTMLButtonElement> };
  return (
    <button type="button" className={classes} {...button}>
      {children}
    </button>
  );
}

export default Button;
