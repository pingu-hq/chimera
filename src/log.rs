//! console logging helpers. every `[name] ...` log line renders the `[name]`
//! tag in cyan so logs read uniformly across the supervisor, chi, and
//! policy runtime.

/// a cyan `[name]` log tag, e.g. `\x1b[36m[chimera]\x1b[0m`.
pub fn tag(name: &str) -> String {
    format!("\x1b[36m[{name}]\x1b[0m")
}
