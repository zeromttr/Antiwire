//! Runtime-neutral body of the async facades.

/// Defines an async owner of a [`Firewall`](crate::Firewall) for one runtime.
///
/// Every async method moves its work onto the runtime's blocking pool through
/// `$run`, which takes a `FnOnce() -> Result<T, Error>` closure and returns a
/// future resolving to `Result<T, Error>`. Only the executor differs between
/// runtimes, so the method set is written once here.
macro_rules! async_facade {
    (
        $(#[$meta:meta])*
        pub struct $name:ident;
        runtime = $runtime:literal,
        into = $into:ident,
        run = $run:path $(,)?
    ) => {
        $(#[$meta])*
        pub struct $name {
            inner: ::std::sync::Arc<::parking_lot::Mutex<$crate::Firewall>>,
        }

        impl $name {
            pub(crate) fn new(firewall: $crate::Firewall) -> Self {
                Self {
                    inner: ::std::sync::Arc::new(::parking_lot::Mutex::new(firewall)),
                }
            }

            /// Runs `operation` on the owned firewall on the runtime's blocking pool.
            async fn blocking<T: Send + 'static>(
                &self,
                operation: impl FnOnce(&mut $crate::Firewall) -> Result<T, firew_core::Error>
                    + Send
                    + 'static,
            ) -> Result<T, firew_core::Error> {
                let inner = self.inner.clone();
                $run(move || operation(&mut inner.lock())).await
            }

            /// Name of the active native backend, for diagnostics and capability checks.
            #[must_use]
            pub fn backend_name(&self) -> &'static str {
                self.inner.lock().backend_name()
            }

            /// Maximum remote addresses the active backend holds in ONE native object.
            #[must_use]
            pub fn max_address_set_entries(&self) -> Option<usize> {
                self.inner.lock().max_address_set_entries()
            }

            /// Returns whether this owner has been closed.
            #[must_use]
            pub fn is_closed(&self) -> bool {
                self.inner.lock().is_closed()
            }

            /// Drains managed rules that drifted out of recognition.
            ///
            /// # Errors
            ///
            /// Returns backend failures.
            pub async fn take_drift(&self) -> Result<Vec<String>, firew_core::Error> {
                self.blocking(move |firewall| firewall.take_drift()).await
            }

            /// Adds a rule.
            ///
            /// # Errors
            ///
            /// Returns validation, DNS, or backend failures.
            pub async fn add_rule(
                &self,
                rule: firew_core::Rule,
            ) -> Result<$crate::RuleId, firew_core::Error> {
                self.blocking(move |firewall| firewall.add_rule(rule)).await
            }

            /// Fetches a rule from native state.
            ///
            /// # Errors
            ///
            /// Returns lookup or backend failures.
            pub async fn get_rule(
                &self,
                id: $crate::RuleId,
            ) -> Result<firew_core::Rule, firew_core::Error> {
                self.blocking(move |firewall| firewall.get_rule(&id)).await
            }

            /// Updates an existing rule.
            ///
            /// # Errors
            ///
            /// Returns validation, lookup, or backend failures.
            pub async fn update_rule(
                &self,
                id: $crate::RuleId,
                rule: firew_core::Rule,
            ) -> Result<(), firew_core::Error> {
                self.blocking(move |firewall| firewall.update_rule(&id, rule)).await
            }

            /// Removes an existing rule.
            ///
            /// # Errors
            ///
            /// Returns lookup or backend failures.
            pub async fn remove_rule(&self, id: $crate::RuleId) -> Result<(), firew_core::Error> {
                self.blocking(move |firewall| firewall.remove_rule(&id)).await
            }

            /// Lists rules from native state.
            ///
            /// # Errors
            ///
            /// Returns enumeration or reconstruction failures.
            pub async fn list_rules(
                &self,
                filter: firew_sys::RuleFilter,
            ) -> Result<Vec<($crate::RuleId, firew_core::Rule)>, firew_core::Error> {
                self.blocking(move |firewall| firewall.list_rules(&filter)).await
            }

            /// Removes every rule owned by this manager namespace.
            ///
            /// # Errors
            ///
            /// Returns cleanup failures.
            pub async fn remove_all_rules(&self) -> Result<(), firew_core::Error> {
                self.blocking(move |firewall| firewall.remove_all_rules()).await
            }

            /// Reconciles caller-provided desired state against native enumeration.
            ///
            /// # Errors
            ///
            /// Returns validation, DNS, or enumeration failures.
            pub async fn reconcile(
                &self,
                desired: Vec<firew_core::Rule>,
            ) -> Result<$crate::ReconcileReport, firew_core::Error> {
                self.blocking(move |firewall| firewall.reconcile(&desired)).await
            }

            /// Executes a bulk request.
            ///
            /// # Errors
            ///
            /// Returns transaction-level failures.
            pub async fn execute_bulk(
                &self,
                request: firew_core::BulkRequest,
            ) -> Result<firew_core::BulkExecution, firew_core::Error> {
                self.blocking(move |firewall| firewall.execute_bulk(&request)).await
            }

            /// Spawns a periodic native-state health monitor.
            ///
            /// # Errors
            ///
            /// Returns an error when the monitor thread cannot be spawned or the owner is closed.
            pub async fn spawn_health_monitor(
                &self,
                config: $crate::HealthMonitorConfig,
            ) -> Result<$crate::HealthMonitorHandle, firew_core::Error> {
                self.blocking(move |firewall| firewall.spawn_health_monitor(&config)).await
            }

            /// Closes the owned firewall.
            ///
            /// # Errors
            ///
            /// Returns cleanup failures.
            pub async fn close(&self) -> Result<(), firew_core::Error> {
                self.blocking(move |firewall| firewall.close()).await
            }
        }

        impl $crate::Firewall {
            #[doc = concat!(
                "Consumes this synchronous owner and returns a ",
                $runtime,
                "-native adapter."
            )]
            #[must_use]
            pub fn $into(self) -> $name {
                $name::new(self)
            }
        }
    };
}

pub(crate) use async_facade;
