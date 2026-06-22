use regex::Regex;
use std::sync::OnceLock;

static INJECTION_RE: OnceLock<Regex> = OnceLock::new();

fn injection_re() -> &'static Regex {
    INJECTION_RE.get_or_init(|| {
        Regex::new(
            r"(?i)(<[^>]+>|javascript:|on\w+=|\b(?:DROP|SELECT|INSERT|UPDATE|DELETE|UNION|EXEC|CREATE|ALTER|TRUNCATE)\b|\.\.[/\\]|&#x)",
        )
        .expect("injection regex")
    })
}

/// Returns `true` if the value does not contain injection patterns
/// (HTML tags, javascript: URI, event handlers, SQL DDL, path traversal, numeric HTML entities).
pub fn is_safe_text(value: &str) -> bool {
    !injection_re().is_match(value)
}

/// Returns `true` if the password satisfies complexity requirements:
/// at least one uppercase letter, one lowercase letter, one digit, and one special character.
pub fn is_strong_password(password: &str) -> bool {
    password.chars().any(|c| c.is_uppercase())
        && password.chars().any(|c| c.is_lowercase())
        && password.chars().any(|c| c.is_ascii_digit())
        && password.chars().any(|c| !c.is_alphanumeric())
}
