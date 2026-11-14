//! What a running total gained since it was last read.

/// A running total a kernel keeps and never resets while its source runs, such as a count
/// of dropped packets or lost events. It wraps at its own width.
pub trait RunningTotal: Copy + Default {
    /// What the total gained from `earlier` to `self`.
    fn gained_since(self, earlier: Self) -> u64;
}

impl RunningTotal for u32 {
    fn gained_since(self, earlier: Self) -> u64 {
        u64::from(self.wrapping_sub(earlier))
    }
}

impl RunningTotal for u64 {
    fn gained_since(self, earlier: Self) -> u64 {
        self.wrapping_sub(earlier)
    }
}

/// Turns a running total into what it gained since the last look, which is what a
/// [`DegradeReason::BufferOverflow`](netmetrics_core::DegradeReason::BufferOverflow) report
/// carries. The total is taken to start at zero, as a source's does when the source starts.
#[derive(Debug, Default)]
pub struct TotalDelta<T> {
    seen: T,
}

impl<T: RunningTotal> TotalDelta<T> {
    /// What the total gained since the last call, given what it is now.
    pub fn since_last(&mut self, total: T) -> u64 {
        let gained = total.gained_since(self.seen);
        self.seen = total;
        gained
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_total_is_read_as_what_it_gained_since_the_last_look() {
        let mut lost = TotalDelta::<u64>::default();
        assert_eq!(lost.since_last(0), 0);
        assert_eq!(lost.since_last(7), 7);
        assert_eq!(lost.since_last(7), 0);
        assert_eq!(lost.since_last(10), 3);
    }

    #[test]
    fn a_total_that_wrapped_at_its_width_still_counts_what_it_gained() {
        let mut narrow = TotalDelta { seen: u32::MAX - 1 };
        assert_eq!(narrow.since_last(3), 5);
        let mut wide = TotalDelta { seen: u64::MAX - 1 };
        assert_eq!(wide.since_last(3), 5);
    }
}
