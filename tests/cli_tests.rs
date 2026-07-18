// SPDX-License-Identifier: Apache-2.0
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn data_home(name: &str) -> PathBuf {
    std::env::temp_dir().join(name)
}

fn cmd_with_home(name: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cybercuris"));
    c.env("XDG_DATA_HOME", data_home(name));
    c
}

fn run(home: &str, args: &[&str]) -> (String, String, bool) {
    let output = cmd_with_home(home)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("failed to run {args:?}: {e}"));
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

fn run_stdin(
    home: &str,
    args: &[&str],
    input: &[u8],
) -> (String, String, bool) {
    let mut child = cmd_with_home(home)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {args:?}: {e}"));
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait {args:?}: {e}"));
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

fn wl_paste() -> String {
    match Command::new("wl-paste")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
        Err(_) => String::new(),
    }
}

fn wl_paste_available() -> bool {
    Command::new("which")
        .arg("wl-paste")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

const MAIN_PASS: &str = "main-password\n";
const MAIN_PASS_INIT: &str = "main-password\nmain-password\n";

#[test]
fn test_cli_help() {
    let home = "cybercuris_test_help";
    let _ = fs::remove_dir_all(data_home(home));
    let (out, _, ok) = run(home, &["--help"]);
    assert!(ok);
    assert!(out.contains("cybercuris"));
    assert!(out.contains("init"));
    assert!(out.contains("store"));
    assert!(out.contains("get"));
    assert!(out.contains("clip"));
    assert!(out.contains("list"));
    assert!(out.contains("--tty"));
    let _ = fs::remove_dir_all(data_home(home));
}

#[test]
fn test_cli_init_store_get_list() {
    let home = "cybercuris_test_full";
    let _ = fs::remove_dir_all(data_home(home));

    // --- init with -t ---
    let (out, _, ok) =
        run_stdin(home, &["-t", "init"], MAIN_PASS_INIT.as_bytes());
    assert!(ok, "init failed: stderr={out}");
    assert!(out.contains("Main key initialized"));

    // --- store with -t (main key pass + entry pass) ---
    let input = format!("{MAIN_PASS}secret123\n");
    let (out, _, ok) =
        run_stdin(home, &["-t", "store", "test1"], input.as_bytes());
    assert!(ok, "store failed: stdout={out}");
    assert!(out.contains("Stored"));

    // --- store another ---
    let input = format!("{MAIN_PASS}hunter2\n");
    let (out, _, ok) =
        run_stdin(home, &["-t", "store", "test2"], input.as_bytes());
    assert!(ok, "store 2 failed: stdout={out}");

    // --- list ---
    let (out, _, ok) = run(home, &["-t", "list"]);
    assert!(ok, "list failed: {out}");
    assert!(out.contains("test1"));
    assert!(out.contains("test2"));

    // --- get ---
    let (out, _, ok) =
        run_stdin(home, &["-t", "get", "test1"], MAIN_PASS.as_bytes());
    assert!(ok, "get failed: stdout={out}");
    assert!(out.contains("secret123"), "bad password: stdout={out}");

    // --- get wrong pass ---
    let (out, _, ok) =
        run_stdin(home, &["-t", "get", "test1"], b"wrong-pass\n");
    assert!(!ok, "should fail with wrong password, got: {out}");

    // --- get nonexistent ---
    let (_, err, ok) =
        run_stdin(home, &["-t", "get", "nope_404"], MAIN_PASS.as_bytes());
    assert!(!ok, "should fail for nonexistent: {err}");

    // --- store special name ---
    let input = format!("{MAIN_PASS}special_pass\n");
    let (_, _, ok) =
        run_stdin(home, &["-t", "store", "my-website.com"], input.as_bytes());
    assert!(ok);
    let (out, _, ok) = run(home, &["-t", "list"]);
    assert!(ok);
    assert!(out.contains("my-website.com"));

    let _ = fs::remove_dir_all(data_home(home));
}

#[test]
fn test_cli_clip() {
    if !wl_paste_available() {
        eprintln!("SKIP: wl-paste not available");
        return;
    }

    let home = "cybercuris_test_clip";
    let _ = fs::remove_dir_all(data_home(home));

    // drain clipboard before test
    let _ = wl_paste();

    // init
    let (_, _, ok) =
        run_stdin(home, &["-t", "init"], MAIN_PASS_INIT.as_bytes());
    assert!(ok);

    // store
    let entry_pass = "clip_secret42";
    let input = format!("{MAIN_PASS}{entry_pass}\n");
    let (_, _, ok) =
        run_stdin(home, &["-t", "store", "clip_test"], input.as_bytes());
    assert!(ok);

    // clip
    let mut clip = cmd_with_home(home);
    clip.args(["-t", "clip", "clip_test"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = clip.spawn().expect("spawn clip");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(MAIN_PASS.as_bytes())
        .unwrap();

    // Wait for PBKDF2 (~0.5s) + Wayland roundtrip + selection setup
    std::thread::sleep(Duration::from_millis(1500));

    let start = Instant::now();
    let mut pasted = String::new();
    for _ in 0..10 {
        pasted = wl_paste().trim().to_string();
        if pasted == entry_pass {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // Debug: read clip command output
    let output = child.wait_with_output().unwrap();
    drop(output);

    assert_eq!(
        pasted, entry_pass,
        "clipboard paste mismatch. Got: '{pasted}'"
    );

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(5000),
        "Paste took {}ms",
        elapsed.as_millis()
    );

    let _ = fs::remove_dir_all(data_home(home));
}

#[test]
fn test_tty_flag_position() {
    let home = "cybercuris_test_tty_flag";

    let _ = fs::remove_dir_all(data_home(home));
    let (_, _, ok) = run_stdin(home, &["init", "-t"], b"pos-test\npos-test\n");
    assert!(ok, "init with flag after command failed");
    let _ = fs::remove_dir_all(data_home(home));

    let (_, _, ok) =
        run_stdin(home, &["-t", "init"], b"pos-test2\npos-test2\n");
    assert!(ok, "init with flag before command failed");
    let _ = fs::remove_dir_all(data_home(home));
}
