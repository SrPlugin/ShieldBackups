//! The configuration that `Configure` leaves behind and the data services read.
//!
//! A plugin is not a single object: `Plugin`, `Engine` and `Storage` are
//! registered separately, but `Configure` only reaches the first one. Without
//! something shared, every plugin ends up writing the same
//! `Arc<Mutex<Option<Config>>>` and the same "if there is no configuration yet,
//! `failed_precondition`" rule. That is what lives here, once.

use std::sync::{Arc, Mutex, PoisonError};

use tonic::Status;

/// The plugin's configuration, shared between its services.
///
/// `T` is the configuration **already parsed and validated** by the plugin: the
/// SDK cannot parse it, because the schema is defined by each plugin in its
/// `Schema`. The alternative —storing the raw `HashMap<String, Value>` here—
/// was discarded because it would force a re-parse on every data RPC and would
/// make a badly written field surface in the middle of a dump instead of in
/// `Configure`, which is precisely the RPC the core calls in order to validate.
///
/// It is created once and cloned into each service; all the clones see the same
/// value.
///
/// ```ignore
/// let config = Configured::<MyConfig>::new("postgres");
/// PluginRuntime::new(MyPlugin::new(config.clone()))
///     .with_engine(MyEngine::new(config))
///     .serve()
///     .await?;
/// ```
///
/// Before `Configure` writes it there are **no silent defaults**:
/// [`Configured::resolved`] fails. A dump written to a destination nobody asked
/// for is worse than a clear error.
pub struct Configured<T> {
    /// Plugin name, only so the error can say who it is talking about.
    plugin: Option<&'static str>,
    value: Arc<Mutex<Option<T>>>,
}

impl<T> Configured<T> {
    /// A configuration slot identified by the plugin's name.
    ///
    /// The name only feeds the error message; giving it lets the core know
    /// **which** of the plugins it started was left unconfigured.
    #[must_use]
    pub fn new(plugin: &'static str) -> Self {
        Self {
            plugin: Some(plugin),
            value: Arc::new(Mutex::new(None)),
        }
    }

    /// Stores the validated configuration. `Configure` writes it.
    ///
    /// Reconfiguring replaces the previous value: the core may call `Configure`
    /// more than once and the last thing it said is what counts.
    pub fn store(&self, value: T) {
        // A poisoned mutex means another thread panicked while holding it; the
        // data inside is still a valid `Option<T>`, so it is recovered instead
        // of propagating the panic to the whole plugin.
        *self.value.lock().unwrap_or_else(PoisonError::into_inner) = Some(value);
    }

    /// Whether `Configure` has already been called.
    ///
    /// For `Preflight`, which is the diagnostic RPC and must **report** missing
    /// configuration instead of failing because of it.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.value
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
}

impl<T: Clone> Configured<T> {
    /// The current configuration.
    ///
    /// It is the first thing every data RPC does: ask for it and propagate the
    /// error with `?` before touching the channel.
    ///
    /// # Errors
    ///
    /// [`Status::failed_precondition`] if `Configure` has not arrived yet. The
    /// message is **deliberately actionable**: it says who is not configured
    /// and which call is missing, because whoever reads it is an operator
    /// looking at the core's log, not the plugin's author. A plugin that
    /// replaces this error with another one must preserve that property.
    pub fn resolved(&self) -> Result<T, Status> {
        self.value
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| Status::failed_precondition(self.message()))
    }

    fn message(&self) -> String {
        match self.plugin {
            Some(p) => format!(
                "plugin `{p}` is not configured yet: call Configure with the fields published by Schema before any data RPC"
            ),
            None => "the plugin is not configured yet: call Configure with the fields published by Schema before any data RPC".to_string(),
        }
    }
}

/// Cloning shares the same value: that is what allows handing it out to the
/// services. It is implemented by hand because deriving it would require
/// `T: Clone`, and cloning the handle does not clone the configuration.
impl<T> Clone for Configured<T> {
    fn clone(&self) -> Self {
        Self {
            plugin: self.plugin,
            value: Arc::clone(&self.value),
        }
    }
}

/// A plugin with no declared name: the error message comes out generic but
/// still says which call is missing.
impl<T> Default for Configured<T> {
    fn default() -> Self {
        Self {
            plugin: None,
            value: Arc::new(Mutex::new(None)),
        }
    }
}

impl<T> std::fmt::Debug for Configured<T> {
    /// Does not print the value: a real plugin's configuration carries
    /// credentials, and a `Debug` that dumped them to the log would be a leak.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Configured")
            .field("plugin", &self.plugin.unwrap_or("<unnamed>"))
            .field("configured", &self.is_configured())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Config {
        dir: String,
    }

    #[test]
    fn without_configure_it_fails_with_failed_precondition() {
        let e = Configured::<Config>::new("mock").resolved().unwrap_err();
        assert_eq!(e.code(), Code::FailedPrecondition);
    }

    #[test]
    fn the_message_says_who_is_missing_and_which_call_fixes_it() {
        // A bare code is useless to the operator reading the core's log.
        let e = Configured::<Config>::new("postgres")
            .resolved()
            .unwrap_err();
        assert!(e.message().contains("postgres"), "{}", e.message());
        assert!(e.message().contains("Configure"), "{}", e.message());
    }

    #[test]
    fn without_a_name_the_message_still_says_configure_is_missing() {
        let e = Configured::<Config>::default().resolved().unwrap_err();
        assert!(e.message().contains("Configure"), "{}", e.message());
    }

    #[test]
    fn after_storing_it_returns_what_was_stored() {
        let c = Configured::new("mock");
        c.store(Config {
            dir: "/tmp/x".into(),
        });
        assert_eq!(c.resolved().unwrap().dir, "/tmp/x");
    }

    #[test]
    fn the_clones_see_the_configuration_another_one_wrote() {
        // The type's reason to exist: `Configure` reaches the Plugin service and
        // Engine and Storage read it, and those are different values.
        let plugin = Configured::new("mock");
        let engine = plugin.clone();
        let storage = plugin.clone();

        assert!(engine.resolved().is_err());
        plugin.store(Config {
            dir: "/data".into(),
        });

        assert_eq!(engine.resolved().unwrap().dir, "/data");
        assert_eq!(storage.resolved().unwrap().dir, "/data");
    }

    #[test]
    fn reconfiguring_replaces_the_previous_value() {
        let c = Configured::new("mock");
        c.store(Config { dir: "/one".into() });
        c.store(Config { dir: "/two".into() });
        assert_eq!(c.resolved().unwrap().dir, "/two");
    }

    #[test]
    fn is_configured_tells_before_from_after() {
        // Preflight needs it: it must report missing configuration, not fail
        // because of it.
        let c = Configured::new("mock");
        assert!(!c.is_configured());
        c.store(Config { dir: "/x".into() });
        assert!(c.is_configured());
    }

    #[test]
    fn debug_does_not_leak_the_configuration() {
        // A real plugin's configuration carries credentials.
        let c = Configured::new("mock");
        c.store(Config {
            dir: "secret-password".into(),
        });
        assert!(!format!("{c:?}").contains("secret-password"));
    }
}
