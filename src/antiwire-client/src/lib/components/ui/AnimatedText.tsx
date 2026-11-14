import clsx from 'clsx';
import { memo, type HTMLAttributes, type ReactNode } from 'react';
import styles from './AnimatedText.module.css';

interface Props extends Omit<HTMLAttributes<HTMLSpanElement>, 'children'> {
  /** Shown when there are no children; with children it only identifies the value. */
  text: string;
  children?: ReactNode;
}

export const AnimatedText = memo(function AnimatedText({
  text,
  className = '',
  children,
  ...rest
}: Props) {
  return (
    <span className={clsx(styles.animatedText, className)} {...rest}>
      {children ?? text}
    </span>
  );
});

export default AnimatedText;
