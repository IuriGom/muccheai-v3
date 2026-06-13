use std::process::Command;

fn main() {
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let build_date = chrono::Local::now().format("%Y-%m-%d").to_string();

    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", commit);
    println!("cargo:rustc-env=BUILD_DATE={}", build_date);
}
