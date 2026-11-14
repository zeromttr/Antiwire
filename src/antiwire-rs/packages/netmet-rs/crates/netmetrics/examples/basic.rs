//! Prints normalized native telemetry for ten seconds.

use netmetrics::{Collector, FlowConsumer, FlowEvent, MetricsError};
use std::thread;
use std::time::Duration;

struct Printer;

impl FlowConsumer for Printer {
    fn on_event(&mut self, event: FlowEvent) {
        println!("{event:?}");
    }

    fn on_batch(&mut self, events: &[FlowEvent]) {
        println!("received {} events", events.len());
        for event in events {
            self.on_event(event.clone());
        }
    }
}

fn main() -> Result<(), MetricsError> {
    let mut collector = Collector::builder()
        .session_name(format!("netmetrics-example-{}", std::process::id()))
        .dns_hints(true)
        .build()?;
    collector.start(Box::new(Printer))?;
    thread::sleep(Duration::from_secs(10));
    collector.stop()
}
