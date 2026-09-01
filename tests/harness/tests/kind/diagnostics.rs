//! Bounded diagnostics for failed Kubernetes commands.

use std::{
    fs,
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};

const MAX_DIAGNOSTICS: usize = 64;
const MAX_DETAIL_BYTES: usize = 8 * 1024;
static DIAGNOSTIC_COUNT: AtomicUsize = AtomicUsize::new(0);

pub(super) fn record(root: &Path, code: &str, detail: &str) {
    if DIAGNOSTIC_COUNT.fetch_add(1, Ordering::Relaxed) >= MAX_DIAGNOSTICS {
        return;
    }
    let directory = root.join("target/e2e-artifacts");
    if fs::create_dir_all(&directory).is_err() {
        return;
    }
    let sequence = DIAGNOSTIC_COUNT.load(Ordering::Relaxed);
    let path = directory.join(format!("{sequence:03}-{code}.log"));
    let mut output = format!("code={code}\n");
    output.push_str(&sanitize(detail));
    let _ = fs::write(path, output);
}

fn sanitize(detail: &str) -> String {
    let mut output = String::new();
    for line in detail.lines().take(64) {
        let lower = line.to_ascii_lowercase();
        if [
            "authorization",
            "certificate-authority-data",
            "client-certificate-data",
            "client-key-data",
            "password",
            "proxy",
            "secret",
            "token",
        ]
        .iter()
        .any(|field| lower.contains(field))
        {
            output.push_str("[redacted sensitive diagnostic line]\n");
        } else {
            output.push_str(line);
            output.push('\n');
        }
        if output.len() >= MAX_DETAIL_BYTES {
            output.truncate(MAX_DETAIL_BYTES);
            break;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn sensitive_lines_are_removed() {
        let output = sanitize("normal\ntoken: private\nclient-key-data: private\n");
        assert!(output.contains("normal"));
        assert!(!output.contains("private"));
    }

    #[test]
    fn details_are_bounded() {
        let output = sanitize(&"x".repeat(20_000));
        assert!(output.len() <= 8 * 1024);
    }
}
