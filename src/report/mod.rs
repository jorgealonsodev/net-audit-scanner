//! Report generation module — HTML/JSON output, template rendering.

pub mod engine;
pub mod view_model;

pub use engine::ReportEngine;
pub use view_model::{ReportContext, ReportHost};

/// Returns the module path for reachability checks.
pub fn module_path() -> &'static str {
    "report"
}
