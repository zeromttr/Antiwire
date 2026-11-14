//! Test fixtures and thread-local native query/allocation probes.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
#[cfg(windows)]
use std::cell::RefCell;
use std::sync::Arc;

use antiwire_events::{AlertPublisher, NotificationHub, TrafficStreamingHub};
use antiwire_platform::{SiemConfig, SiemExporter};
use antiwire_policy::RuleEngine;
use antiwire_secrets::UnixSecureFileKeyProvider;
use antiwire_store::Store;
use parking_lot::RwLock;

use crate::{AppIdResolver, FlowProcessor};

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub store: Arc<Store>,
    pub publisher: AlertPublisher,
    pub resolver: Arc<AppIdResolver>,
    pub siem: SiemExporter,
}

pub fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let keys = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store = Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keys).unwrap());
    let siem = SiemExporter::new(SiemConfig {
        enabled: true,
        file_path: dir.path().join("siem.json"),
        send_allowed: true,
        ..SiemConfig::default()
    });
    let publisher =
        AlertPublisher::saved(NotificationHub::new(), store.clone(), Some(siem.clone()));
    let resolver = Arc::new(AppIdResolver::new(
        store.clone(),
        publisher.clone(),
        siem.clone(),
    ));
    Fixture {
        dir,
        store,
        publisher,
        resolver,
        siem,
    }
}

pub fn processor(f: &Fixture, traffic: TrafficStreamingHub) -> Arc<FlowProcessor> {
    Arc::new(FlowProcessor::new(
        f.resolver.clone(),
        None,
        Arc::new(RwLock::new(RuleEngine::new())),
        f.store.clone(),
        traffic,
        f.publisher.clone(),
        f.siem.clone(),
    ))
}

#[cfg(windows)]
type NativeProbe = (&'static str, Box<dyn FnOnce()>);

thread_local! {
    static ALLOCS: Cell<Option<[usize; 5]>> = const { Cell::new(None) };
    #[cfg(windows)]
    static NATIVE_PROBE: RefCell<Option<NativeProbe>> = const { RefCell::new(None) };
}

struct CountingAllocator;
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn count(size: usize) {
    let _ = ALLOCS.try_with(|state| {
        if let Some(mut sample) = state.get() {
            sample[2] += usize::from(size == sample[0]);
            sample[3] += usize::from(size == sample[1]);
            sample[4] += 1;
            state.set(Some(sample));
        }
    });
}

#[expect(
    unsafe_code,
    reason = "test instrumentation delegates the allocator contract unchanged to System"
)]
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: forwarding the caller's valid layout to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: forwarding the caller's valid layout to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: every allocation above is made by the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(new_size);
        // SAFETY: forwarding the caller's pointer and allocation layout unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

pub fn allocations(name_len: usize, path_len: usize, work: impl FnOnce()) -> [usize; 3] {
    ALLOCS.with(|state| state.set(Some([name_len, path_len, 0, 0, 0])));
    work();
    let counts = ALLOCS.with(|state| state.replace(None).unwrap());
    [counts[2], counts[3], counts[4]]
}

#[cfg(windows)]
pub fn install_native_probe(query: &'static str, probe: impl FnOnce() + 'static) {
    NATIVE_PROBE.with(|state| *state.borrow_mut() = Some((query, Box::new(probe))));
}

#[cfg(windows)]
pub fn native_probe(query: &str) {
    let probe = NATIVE_PROBE.with(|state| {
        let mut slot = state.borrow_mut();
        if slot.as_ref().is_some_and(|(target, _)| *target == query) {
            slot.take()
        } else {
            None
        }
    });
    if let Some((_, probe)) = probe {
        probe();
    }
}
