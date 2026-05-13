use thiserror::Error;

/// Application-level error types.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Config error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Permission denied: {0}")]
    Permission(String),

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Report error: {0}")]
    Report(String),

    #[error("Template error: {0}")]
    Template(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_error_display() {
        let err = Error::Permission("root required for ICMP".into());
        assert_eq!(format!("{}", err), "Permission denied: root required for ICMP");
    }

    #[test]
    fn interface_not_found_error_display() {
        let err = Error::InterfaceNotFound("eth0".into());
        assert_eq!(format!("{}", err), "Interface not found: eth0");
    }

    #[test]
    fn discovery_error_display() {
        let err = Error::Discovery("no hosts found".into());
        assert_eq!(format!("{}", err), "Discovery error: no hosts found");
    }

    #[test]
    fn error_is_debug() {
        let err = Error::Permission("test".into());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Permission"));
    }

    #[test]
    fn report_error_display() {
        let err = Error::Report("failed to generate report".into());
        assert_eq!(format!("{}", err), "Report error: failed to generate report");
    }

    #[test]
    fn template_error_display() {
        let err = Error::Template("undefined variable 'foo'".into());
        assert_eq!(format!("{}", err), "Template error: undefined variable 'foo'");
    }

    #[test]
    fn report_error_is_debug() {
        let err = Error::Report("test".into());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Report"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn template_error_is_debug() {
        let err = Error::Template("test".into());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Template"));
        assert!(debug.contains("test"));
    }
}
