// SPDX-License-Identifier: Apache-2.0
use std::{
    cell::RefCell,
    io::{self, Write},
    os::fd::RawFd,
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use clap::{Arg, ArgAction, Command};
use slint::ComponentHandle;

use crate::{
    keystore::Keystore,
    memory_guard::{MemoryGuard, PasswordBuf, clear_memory},
};

/// Zero a String's heap-allocated buffer before it is dropped, preventing
/// plaintext secrets from lingering in freed heap memory.
fn zero_string(s: &mut str) {
    unsafe { clear_memory(s.as_bytes_mut()) };
}

/// Write end of the self-pipe. The SIGUSR1 handler writes a byte here.
static mut SIGUSR1_PIPE_WRITE: RawFd = -1;
/// Read end of the self-pipe. Used by the watcher thread.
static mut SIGUSR1_PIPE_READ: RawFd = -1;
/// Atomic flag for CLI subcommands (no event loop to watch the pipe).
static SIGUSR1_RECEIVED: AtomicBool = AtomicBool::new(false);
static FORCE_TTY: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigusr1(_sig: libc::c_int) {
    SIGUSR1_RECEIVED.store(true, Ordering::SeqCst);
    let byte: [u8; 1] = [1];
    unsafe {
        if SIGUSR1_PIPE_WRITE >= 0 {
            libc::write(
                SIGUSR1_PIPE_WRITE,
                byte.as_ptr() as *const libc::c_void,
                1,
            );
        }
    }
}

fn setup_signal_handler(pipe_write: RawFd) {
    unsafe {
        SIGUSR1_PIPE_WRITE = pipe_write;
        libc::signal(
            libc::SIGUSR1,
            handle_sigusr1 as *const () as libc::sighandler_t,
        );
    }
}

fn check_and_reset_signal() -> bool {
    SIGUSR1_RECEIVED.swap(false, Ordering::SeqCst)
}

struct CachedKey {
    key: Option<MemoryGuard>,
    loaded_at: Option<Instant>,
    timeout: Duration,
}

impl CachedKey {
    fn new(timeout: Duration) -> Self {
        CachedKey {
            key: None,
            loaded_at: None,
            timeout,
        }
    }

    fn is_valid(&self) -> bool {
        self.key.is_some()
            && self.loaded_at.is_some_and(|t| t.elapsed() < self.timeout)
    }

    /// Returns true if a key was loaded but has now expired.
    fn is_expired(&self) -> bool {
        self.key.is_some()
            && self.loaded_at.is_some_and(|t| t.elapsed() >= self.timeout)
    }

    fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    fn drop_key(&mut self) {
        self.key = None;
        self.loaded_at = None;
    }

    fn set(&mut self, guard: MemoryGuard) {
        self.key = Some(guard);
        self.loaded_at = Some(Instant::now());
    }

    fn as_slice(&self) -> Option<&[u8]> {
        if self.is_valid() {
            self.key.as_ref().map(|k| k.as_slice())
        } else {
            None
        }
    }
}

fn has_wayland() -> bool {
    !FORCE_TTY.load(Ordering::Relaxed)
        && std::env::var_os("WAYLAND_DISPLAY").is_some()
}

fn read_password_tty(prompt: &str) -> anyhow::Result<PasswordBuf> {
    use std::os::fd::AsRawFd;

    let stdin_fd = io::stdin().as_raw_fd();
    let is_tty = unsafe { libc::isatty(stdin_fd) != 0 };

    // Save current terminal settings and disable echo (only if a TTY).
    let saved_term = if is_tty {
        let saved = unsafe {
            let mut term: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(stdin_fd, &mut term) != 0 {
                return Err(anyhow::anyhow!(
                    "tcgetattr failed: {}",
                    io::Error::last_os_error()
                ));
            }
            let saved = term;
            term.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(stdin_fd, libc::TCSANOW, &term) != 0 {
                return Err(anyhow::anyhow!(
                    "tcsetattr failed: {}",
                    io::Error::last_os_error()
                ));
            }
            saved
        };
        Some(saved)
    } else {
        None
    };

    let result = (|| -> anyhow::Result<PasswordBuf> {
        if is_tty {
            eprint!("{prompt}: ");
            io::stderr().flush().ok();
        }
        let mut pass = String::new();
        io::stdin()
            .read_line(&mut pass)
            .context("reading password from stdin")?;
        if is_tty {
            eprintln!();
        }
        let mut pass = pass.trim_end_matches(&['\n', '\r'][..]).to_owned();
        let buf = PasswordBuf::new(&pass)?;
        zero_string(&mut pass);
        Ok(buf)
    })();

    // Restore terminal settings.
    if let Some(saved_term) = saved_term {
        let restore_result =
            unsafe { libc::tcsetattr(stdin_fd, libc::TCSANOW, &saved_term) };
        if restore_result != 0 {
            eprintln!(
                "Warning: failed to restore terminal settings: {}",
                io::Error::last_os_error()
            );
        }
    }

    result
}

fn prompt_unlock_password() -> anyhow::Result<PasswordBuf> {
    if has_wayland() {
        prompt_unlock_password_gui()
    } else {
        read_password_tty("Enter main key password")
    }
}

fn prompt_unlock_password_gui() -> anyhow::Result<PasswordBuf> {
    let dialog = ui::UnlockDialog::new()?;
    slint::set_xdg_app_id(slint::SharedString::from("cybercuris"))?;
    let (tx, rx) = std::sync::mpsc::channel();
    let pending_timers: std::rc::Rc<
        std::cell::RefCell<Vec<Box<slint::Timer>>>,
    > = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));

    let dlg_weak = dialog.as_weak();
    let do_confirm = {
        let dlg_weak = dlg_weak.clone();
        let tx = tx.clone();
        let timers = pending_timers.clone();
        move || {
            let password = if let Some(dlg) = dlg_weak.upgrade() {
                let p = dlg.get_password_text().to_string();
                dlg.hide().ok();
                p
            } else {
                String::new()
            };
            let _ = tx.send(password);
            let timer = Box::new(slint::Timer::default());
            timer.start(
                slint::TimerMode::SingleShot,
                Duration::from_millis(50),
                move || {
                    let _ = slint::quit_event_loop();
                },
            );
            timers.borrow_mut().push(timer);
        }
    };

    dialog.on_accepted(do_confirm.clone());
    dialog.on_ok_clicked(do_confirm);

    dialog.on_cancel_clicked({
        let dlg_weak = dlg_weak.clone();
        let timers = pending_timers.clone();
        move || {
            if let Some(dlg) = dlg_weak.upgrade() {
                dlg.hide().ok();
            }
            let _ = tx.send(String::new());
            let timer = Box::new(slint::Timer::default());
            timer.start(
                slint::TimerMode::SingleShot,
                Duration::from_millis(50),
                move || {
                    let _ = slint::quit_event_loop();
                },
            );
            timers.borrow_mut().push(timer);
        }
    });

    dialog.show()?;
    slint::run_event_loop()?;

    drop(pending_timers);

    let mut password = rx
        .recv()
        .map_err(|_| anyhow::anyhow!("Password dialog closed"))?;
    if password.is_empty() {
        zero_string(&mut password);
        anyhow::bail!("Password dialog dismissed");
    }
    let buf = PasswordBuf::new(&password)?;
    zero_string(&mut password);
    Ok(buf)
}

fn prompt_set_password() -> anyhow::Result<PasswordBuf> {
    if has_wayland() {
        prompt_set_password_gui()
    } else {
        prompt_set_password_tty()
    }
}

fn prompt_set_password_tty() -> anyhow::Result<PasswordBuf> {
    let pass = read_password_tty("Enter new main key password")?;
    let confirm = read_password_tty("Confirm new main key password")?;
    if !constant_time_eq(pass.as_bytes(), confirm.as_bytes()) {
        anyhow::bail!("Passwords do not match");
    }
    if pass.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }
    Ok(pass)
}

/// Constant-time byte comparison to prevent timing side-channels
/// on password verification.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn prompt_set_password_gui() -> anyhow::Result<PasswordBuf> {
    slint::set_xdg_app_id(slint::SharedString::from("cybercuris"))?;

    // Collect timers from all loop iterations so we can drop them
    // cleanly instead of leaking them via Box::leak.
    let pending_timers: std::rc::Rc<
        std::cell::RefCell<Vec<Box<slint::Timer>>>,
    > = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));

    loop {
        let dialog = ui::SetPasswordDialog::new()?;
        let (tx, rx) = std::sync::mpsc::channel();

        let dlg_weak = dialog.as_weak();
        let do_confirm = {
            let dlg_weak = dlg_weak.clone();
            let tx = tx.clone();
            let timers = pending_timers.clone();
            move || {
                let (p1, p2) = if let Some(dlg) = dlg_weak.upgrade() {
                    let p1 = dlg.get_password1().to_string();
                    let p2 = dlg.get_password2().to_string();
                    dlg.hide().ok();
                    (p1, p2)
                } else {
                    (String::new(), String::new())
                };
                let _ = tx.send((p1, p2));
                let timer = Box::new(slint::Timer::default());
                timer.start(
                    slint::TimerMode::SingleShot,
                    Duration::from_millis(50),
                    move || {
                        let _ = slint::quit_event_loop();
                    },
                );
                timers.borrow_mut().push(timer);
            }
        };

        dialog.on_accepted(do_confirm.clone());
        dialog.on_ok_clicked(do_confirm);

        dialog.on_cancel_clicked({
            let dlg_weak = dlg_weak.clone();
            let timers = pending_timers.clone();
            move || {
                if let Some(dlg) = dlg_weak.upgrade() {
                    dlg.hide().ok();
                }
                let _ = tx.send((String::new(), String::new()));
                let timer = Box::new(slint::Timer::default());
                timer.start(
                    slint::TimerMode::SingleShot,
                    Duration::from_millis(50),
                    move || {
                        let _ = slint::quit_event_loop();
                    },
                );
                timers.borrow_mut().push(timer);
            }
        });

        dialog.show()?;
        slint::run_event_loop()?;

        let (mut p1, mut p2) = rx
            .recv()
            .map_err(|_| anyhow::anyhow!("Password dialog closed"))?;

        if p1.is_empty() && p2.is_empty() {
            zero_string(&mut p1);
            zero_string(&mut p2);
            anyhow::bail!("Password setup dismissed");
        }

        if !constant_time_eq(p1.as_bytes(), p2.as_bytes()) {
            eprintln!("Passwords do not match.");
            zero_string(&mut p1);
            zero_string(&mut p2);
            continue;
        }

        if p1.is_empty() {
            eprintln!("Password cannot be empty.");
            zero_string(&mut p1);
            zero_string(&mut p2);
            continue;
        }

        let buf = PasswordBuf::new(&p1)?;
        zero_string(&mut p2);
        zero_string(&mut p1);
        return Ok(buf);
    }
}

fn unlock_key_with_init(
    keystore: &Keystore,
    cached: &Arc<Mutex<CachedKey>>,
) -> anyhow::Result<()> {
    if check_and_reset_signal() {
        cached.lock().unwrap().drop_key();
    }

    {
        let c = cached.lock().unwrap();
        if c.is_valid() {
            return Ok(());
        }
    }

    if !keystore.is_initialized() {
        let password = prompt_set_password()?;
        keystore.init_main_key(&password)?;
    }

    loop {
        let password = prompt_unlock_password()?;
        if password.is_empty() {
            anyhow::bail!("No password provided");
        }
        match keystore.load_main_key(&password) {
            Ok(guard) => {
                cached.lock().unwrap().set(guard);
                return Ok(());
            }
            Err(e) => {
                eprintln!("Wrong password: {e:#}");
            }
        }
    }
}

fn aes_password_key(cached: &Arc<Mutex<CachedKey>>) -> Option<[u8; 32]> {
    let c = cached.lock().unwrap();
    c.as_slice().map(keystore::password_aes_key_from_main_key)
}

fn with_main_key<F, T>(cached: &Arc<Mutex<CachedKey>>, f: F) -> Option<T>
where
    F: FnOnce(&[u8]) -> T,
{
    let c = cached.lock().unwrap();
    c.as_slice().map(f)
}

fn main() -> anyhow::Result<()> {
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        anyhow::bail!(
            "failed to create signal pipe: {}",
            std::io::Error::last_os_error()
        );
    }
    unsafe {
        SIGUSR1_PIPE_READ = pipe_fds[0];
    }
    setup_signal_handler(pipe_fds[1]);

    let matches = Command::new("cybercuris")
        .about("Linux password manager")
        .arg(
            Arg::new("tty")
                .short('t')
                .long("tty")
                .action(ArgAction::SetTrue)
                .help("Force TTY password input mode")
                .global(true),
        )
        .subcommand(
            Command::new("init").about("Initialize the main key").arg(
                Arg::new("force")
                    .short('f')
                    .long("force")
                    .action(ArgAction::SetTrue)
                    .help("Force reinitialization even if already initialized"),
            ),
        )
        .subcommand(
            Command::new("store").about("Store a password").arg(
                Arg::new("NAME")
                    .required(true)
                    .index(1)
                    .help("Password name"),
            ),
        )
        .subcommand(
            Command::new("get")
                .about("Retrieve and print a password to stdout")
                .arg(
                    Arg::new("NAME")
                        .required(true)
                        .index(1)
                        .help("Password name"),
                ),
        )
        .subcommand(
            Command::new("clip")
                .about("Copy a password to the Wayland clipboard")
                .arg(
                    Arg::new("NAME")
                        .required(true)
                        .index(1)
                        .help("Password name"),
                ),
        )
        .subcommand(Command::new("list").about("List stored password names"))
        .get_matches();

    if matches.get_flag("tty") {
        FORCE_TTY.store(true, Ordering::Relaxed);
    }

    match matches.subcommand() {
        None => {
            // No subcommand: launch GUI if WAYLAND_DISPLAY is set,
            // otherwise print help.
            if has_wayland() {
                // Check for existing instance — if found, tell it to
                // show its window and exit.
                if single_instance::try_activate_existing() {
                    return Ok(());
                }
                run_gui()
            } else {
                let mut cmd = Command::new("cybercuris")
                    .about("Linux password manager")
                    .arg_required_else_help(true);
                cmd.print_help()?;
                Ok(())
            }
        }
        Some(("init", sub_m)) => cli_init(sub_m),
        Some(("store", sub_m)) => cli_store(sub_m),
        Some(("get", sub_m)) => cli_get(sub_m),
        Some(("clip", sub_m)) => cli_clip(sub_m),
        Some(("list", _)) => cli_list(),
        Some((cmd, _)) => {
            anyhow::bail!("Unknown command: {cmd}");
        }
    }
}

fn read_password(name: &str) -> anyhow::Result<PasswordBuf> {
    eprint!("Password for {name}: ");
    io::stderr().flush().ok();
    let mut pass = String::new();
    io::stdin()
        .read_line(&mut pass)
        .context("reading password from stdin")?;
    let mut pass = pass.trim_end_matches(&['\n', '\r'][..]).to_owned();
    let buf = PasswordBuf::new(&pass)?;
    zero_string(&mut pass);
    Ok(buf)
}

fn cli_init(matches: &clap::ArgMatches) -> anyhow::Result<()> {
    FORCE_TTY.store(true, Ordering::Relaxed);
    let keystore = Keystore::new()?;

    if keystore.is_initialized() && !matches.get_flag("force") {
        println!("Password store already initialized.");
        println!(
            "Use --force to reinitialize (will overwrite existing main key)."
        );
        return Ok(());
    }

    let password = prompt_set_password_tty()?;
    keystore.init_main_key(&password)?;
    println!("Main key initialized.");
    Ok(())
}

fn cli_store(matches: &clap::ArgMatches) -> anyhow::Result<()> {
    FORCE_TTY.store(true, Ordering::Relaxed);
    let name = matches.get_one::<String>("NAME").unwrap();
    let keystore = Keystore::new()?;
    let cached: Arc<Mutex<CachedKey>> = Arc::new(Mutex::new(CachedKey::new(
        settings::Settings::load().timeout(),
    )));

    unlock_key_with_init(&keystore, &cached)?;

    let password = read_password(name)?;

    let stored = with_main_key(&cached, |mk| {
        keystore.store_password(name, password.as_bytes(), mk)
    });

    match stored {
        Some(Ok(())) => {
            println!("Stored password for {name}.");
            Ok(())
        }
        Some(Err(e)) => {
            anyhow::bail!("Failed to store password for {name}: {e:#}")
        }
        None => {
            anyhow::bail!("Key expired — please unlock again")
        }
    }
}

fn cli_get(matches: &clap::ArgMatches) -> anyhow::Result<()> {
    FORCE_TTY.store(true, Ordering::Relaxed);
    let name = matches.get_one::<String>("NAME").unwrap();
    let keystore = Keystore::new()?;
    let ciphertext = keystore.read_password_ciphertext(name)?;
    let cached: Arc<Mutex<CachedKey>> = Arc::new(Mutex::new(CachedKey::new(
        settings::Settings::load().timeout(),
    )));

    unlock_key_with_init(&keystore, &cached)?;

    let plain = match with_main_key(&cached, |mk| {
        keystore::decrypt_with_main_key(mk, &ciphertext)
    }) {
        Some(Ok(guard)) => guard,
        Some(Err(e)) => anyhow::bail!("Failed to decrypt password: {e:#}"),
        None => anyhow::bail!("Key expired — please unlock again"),
    };

    let mut stdout = io::stdout().lock();
    stdout.write_all(plain.as_slice())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn cli_clip(matches: &clap::ArgMatches) -> anyhow::Result<()> {
    FORCE_TTY.store(true, Ordering::Relaxed);
    let name = matches.get_one::<String>("NAME").unwrap();
    let keystore = Keystore::new()?;
    let ciphertext = keystore.read_password_ciphertext(name)?;
    let cached: Arc<Mutex<CachedKey>> = Arc::new(Mutex::new(CachedKey::new(
        settings::Settings::load().timeout(),
    )));

    unlock_key_with_init(&keystore, &cached)?;

    let aes_key = aes_password_key(&cached)
        .ok_or_else(|| anyhow::anyhow!("Failed to get AES key"))?;
    let clipboard = clipboard::spawn_clipboard_thread(aes_key)?;
    clipboard.hold_and_wait(ciphertext);
    println!("Copied {name} to clipboard.");
    Ok(())
}

fn cli_list() -> anyhow::Result<()> {
    let keystore = Keystore::new()?;
    let names = keystore.list_passwords()?;
    for name in &names {
        println!("{name}");
    }
    if names.is_empty() {
        println!("(no passwords stored)");
    }
    Ok(())
}

fn run_gui() -> anyhow::Result<()> {
    let keystore = Rc::new(Keystore::new()?);
    let settings = Rc::new(RefCell::new(settings::Settings::load()));
    let cached: Arc<Mutex<CachedKey>> =
        Arc::new(Mutex::new(CachedKey::new(settings.borrow().timeout())));
    let clipboard: Arc<Mutex<Option<clipboard::ClipboardHandle>>> =
        Arc::new(Mutex::new(None));
    let all_names: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    // Holds the inactivity timer so it lives for the entire GUI session
    // without being leaked.
    let mut _inactivity_timer: Option<Box<slint::Timer>> = None;

    let win = ui::MainWindow::new()?;
    slint::set_xdg_app_id(slint::SharedString::from("cybercuris"))?;

    win.set_locked(true);
    win.set_needs_init(!keystore.is_initialized());
    win.set_quit_shortcut_key(settings.borrow().quit_key.as_str().into());
    win.set_hide_shortcut_key(settings.borrow().hide_key.as_str().into());
    win.set_settings_timeout_minutes(
        (settings.borrow().unlock_timeout_secs / 60)
            .to_string()
            .into(),
    );

    {
        let settings = settings.clone();
        let cached = cached.clone();
        let win_weak = win.as_weak();
        win.on_save_settings(move |timeout_min, quit_key, hide_key| {
            let Some(win) = win_weak.upgrade() else {
                return;
            };
            let minutes: u64 = match timeout_min.trim().parse() {
                Ok(n) if n > 0 => n,
                _ => {
                    win.set_status(
                        "Invalid timeout: enter minutes > 0.".into(),
                    );
                    return;
                }
            };
            let quit_key = quit_key.trim().to_lowercase();
            let hide_key = hide_key.trim().to_lowercase();
            if quit_key.chars().count() != 1 || hide_key.chars().count() != 1 {
                win.set_status("Shortcut must be a single character.".into());
                return;
            }
            if quit_key == hide_key {
                win.set_status("Shortcuts must differ.".into());
                return;
            }
            {
                let mut s = settings.borrow_mut();
                s.unlock_timeout_secs = minutes * 60;
                s.quit_key = quit_key.clone();
                s.hide_key = hide_key.clone();
                if let Err(e) = s.save() {
                    win.set_status(
                        format!("Settings save error: {e:#}").into(),
                    );
                    return;
                }
            }
            cached
                .lock()
                .unwrap()
                .set_timeout(Duration::from_secs(minutes * 60));
            win.set_quit_shortcut_key(quit_key.as_str().into());
            win.set_hide_shortcut_key(hide_key.as_str().into());
            win.set_settings_timeout_minutes(minutes.to_string().into());
            win.set_status("Settings saved.".into());
        });
    }

    let tray = ui::CybercurisTray::new()?;

    {
        let win_weak = win.as_weak();
        tray.on_show_window(move || {
            if let Some(win) = win_weak.upgrade() {
                win.set_filter_text("".into());
                win.invoke_filter_changed("".into());
                let _ = win.show();
            }
        });
    }

    {
        let cached_clone = cached.clone();
        tray.on_quit(move || {
            cached_clone.lock().unwrap().drop_key();
            let _ = slint::quit_event_loop();
        });
    }

    // Unlock callback
    {
        let keystore = keystore.clone();
        let cached = cached.clone();
        let clipboard = clipboard.clone();
        let all_names = all_names.clone();
        let win_weak = win.as_weak();
        win.on_unlock_password(move |password| {
            let Some(win) = win_weak.upgrade() else {
                return;
            };
            match keystore.load_main_key(&password) {
                Ok(guard) => {
                    let aes_key = keystore::password_aes_key_from_main_key(
                        guard.as_slice(),
                    );
                    match clipboard::spawn_clipboard_thread(aes_key) {
                        Ok(handle) => {
                            *clipboard.lock().unwrap() = Some(handle);
                        }
                        Err(e) => {
                            win.set_status(
                                format!("Clipboard error: {e:#}").into(),
                            );
                            return;
                        }
                    }
                    cached.lock().unwrap().set(guard);
                    win.set_locked(false);
                    win.set_status("".into());
                    let names = keystore.list_passwords().unwrap_or_default();
                    *all_names.borrow_mut() = names.clone();
                    let shared: Vec<slint::SharedString> = names
                        .iter()
                        .map(|n| slint::SharedString::from(n.as_str()))
                        .collect();
                    win.set_password_names(slint::ModelRc::new(
                        slint::VecModel::from(shared),
                    ));
                }
                Err(_) => {
                    win.set_status("Wrong password.".into());
                }
            }
        });
    }

    // Set init password callback
    {
        let keystore = keystore.clone();
        let cached = cached.clone();
        let clipboard = clipboard.clone();
        let win_weak = win.as_weak();
        win.on_set_init_password(move |p1, p2| {
            let Some(win) = win_weak.upgrade() else {
                return;
            };
            if p1 != p2 {
                win.set_status("Passwords do not match.".into());
                return;
            }
            if p1.is_empty() {
                win.set_status("Password cannot be empty.".into());
                return;
            }
            if let Err(e) = keystore.init_main_key(&p1) {
                win.set_status(format!("Init error: {e:#}").into());
                return;
            }
            match keystore.load_main_key(&p1) {
                Ok(guard) => {
                    let aes_key = keystore::password_aes_key_from_main_key(
                        guard.as_slice(),
                    );
                    match clipboard::spawn_clipboard_thread(aes_key) {
                        Ok(handle) => {
                            *clipboard.lock().unwrap() = Some(handle);
                        }
                        Err(e) => {
                            win.set_status(
                                format!("Clipboard error: {e:#}").into(),
                            );
                            return;
                        }
                    }
                    cached.lock().unwrap().set(guard);
                    win.set_needs_init(false);
                    win.set_locked(false);
                    win.set_status("".into());
                }
                Err(e) => {
                    win.set_status(format!("Load error: {e:#}").into());
                }
            }
        });
    }

    // Lock callback
    {
        let cached = cached.clone();
        let clipboard = clipboard.clone();
        let win_weak = win.as_weak();
        win.on_lock(move || {
            cached.lock().unwrap().drop_key();
            *clipboard.lock().unwrap() = None;
            if let Some(win) = win_weak.upgrade() {
                win.set_locked(true);
                win.set_status("".into());
                win.window().hide().ok();
            }
        });
    }

    let app = Rc::new(RefCell::new(App {
        keystore: keystore.clone(),
        clipboard: clipboard.clone(),
        cached: cached.clone(),
        names: Vec::new(),
    }));

    {
        let all_names = all_names.clone();
        let win_weak = win.as_weak();
        win.on_filter_changed(move |text| {
            let Some(win) = win_weak.upgrade() else {
                return;
            };
            let all = all_names.borrow();
            let filtered: Vec<String> = if text.is_empty() {
                all.clone()
            } else {
                all.iter()
                    .filter(|n| n.to_lowercase().contains(&text.to_lowercase()))
                    .cloned()
                    .collect()
            };
            let shared: Vec<slint::SharedString> = filtered
                .iter()
                .map(|n| slint::SharedString::from(n.as_str()))
                .collect();
            win.set_password_names(slint::ModelRc::new(slint::VecModel::from(
                shared,
            )));
        });
    }

    {
        let app = app.clone();
        let win_weak = win.as_weak();
        let all_names = all_names.clone();
        win.on_store_password(move |name, password| {
            let Some(win) = win_weak.upgrade() else {
                return false;
            };
            let mut app = app.borrow_mut();
            let stored = store_password(
                &mut app,
                &win,
                name.as_str(),
                password.as_str(),
            );
            *all_names.borrow_mut() = app.names.clone();
            stored
        });
    }

    {
        let app = app.clone();
        let win_weak = win.as_weak();
        let all_names = all_names.clone();
        win.on_edit_password(move |old_name, new_name, password| {
            let Some(win) = win_weak.upgrade() else {
                return;
            };
            let mut app = app.borrow_mut();
            edit_password(
                &mut app,
                &win,
                old_name.as_str(),
                new_name.as_str(),
                password.as_str(),
            );
            *all_names.borrow_mut() = app.names.clone();
        });
    }

    {
        let app = app.clone();
        let win_weak = win.as_weak();
        win.on_copy_password(move |name| {
            let Some(win) = win_weak.upgrade() else {
                return;
            };
            let mut app = app.borrow_mut();
            copy_password(&mut app, &win, name.as_str());
            win.window().hide().ok();
        });
    }

    {
        let app = app.clone();
        let win_weak = win.as_weak();
        let all_names = all_names.clone();
        win.on_remove_password(move |name| {
            let Some(win) = win_weak.upgrade() else {
                return;
            };
            let mut app = app.borrow_mut();
            remove_password(&mut app, &win, name.as_str());
            *all_names.borrow_mut() = app.names.clone();
        });
    }

    {
        let app = app.clone();
        let win_weak = win.as_weak();
        let all_names = all_names.clone();
        win.on_refresh(move || {
            let Some(win) = win_weak.upgrade() else {
                return;
            };
            let mut app = app.borrow_mut();
            refresh(&mut app, &win);
            *all_names.borrow_mut() = app.names.clone();
        });
    }

    {
        let win_weak = win.as_weak();
        win.on_hide_window(move || {
            if let Some(win) = win_weak.upgrade() {
                win.window().hide().ok();
            }
        });
    }

    {
        let cached_clone = cached.clone();
        win.on_exit(move || {
            cached_clone.lock().unwrap().drop_key();
            let _ = slint::quit_event_loop();
        });
    }

    win.window()
        .on_close_requested(|| slint::CloseRequestResponse::HideWindow);

    // Spawn a thread that blocks on the self-pipe read end.
    // When SIGUSR1 fires, the handler writes a byte, waking this
    // thread which dispatches the full lock action via
    // slint::invoke_from_event_loop — zero polling, instant response.
    {
        let cached = cached.clone();
        let clipboard = clipboard.clone();
        let win_weak = win.as_weak();
        let pipe_read = unsafe { SIGUSR1_PIPE_READ };
        thread::spawn(move || {
            let mut buf = [0u8; 64];
            loop {
                let n = unsafe {
                    libc::read(
                        pipe_read,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n <= 0 {
                    break;
                }
                let _ = slint::invoke_from_event_loop({
                    let cached = cached.clone();
                    let clipboard = clipboard.clone();
                    let win_weak = win_weak.clone();
                    move || {
                        cached.lock().unwrap().drop_key();
                        *clipboard.lock().unwrap() = None;
                        if let Some(win) = win_weak.upgrade() {
                            win.set_locked(true);
                            win.set_status("".into());
                            win.window().hide().ok();
                        }
                    }
                });
            }
        });
    }

    // Auto-lock after 30 minutes of inactivity: periodically check
    // whether the cached key has expired and trigger a lock if so.
    {
        let cached = cached.clone();
        let clipboard = clipboard.clone();
        let win_weak = win.as_weak();
        let timer = Box::new(slint::Timer::default());
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_secs(30),
            move || {
                if cached.lock().unwrap().is_expired() {
                    cached.lock().unwrap().drop_key();
                    *clipboard.lock().unwrap() = None;
                    if let Some(win) = win_weak.upgrade() {
                        win.set_locked(true);
                        win.set_status(
                            "Session expired — please unlock.".into(),
                        );
                        win.window().hide().ok();
                    }
                }
            },
        );
        _inactivity_timer = Some(timer);
    }

    // Start single-instance socket listener. When a second instance
    // launches, it will trigger this callback to show the main window.
    let _guard = single_instance::start_listener(Arc::new({
        let win_weak = win.as_weak();
        move || {
            if let Some(win) = win_weak.upgrade() {
                win.set_filter_text("".into());
                win.invoke_filter_changed("".into());
                let _ = win.show();
            }
        }
    }));

    win.show()?;
    // Signal the listener thread that the event loop is about to run,
    // so it can safely queue callbacks via slint::invoke_from_event_loop.
    _guard.set_event_loop_ready();
    slint::run_event_loop_until_quit()?;

    Ok(())
}

fn copy_password(app: &mut App, win: &ui::MainWindow, name: &str) {
    let ciphertext = match app.keystore.read_password_ciphertext(name) {
        Ok(c) => c,
        Err(e) => {
            win.set_status(format!("Read error: {e:#}").into());
            return;
        }
    };

    if let Some(ref clip) = *app.clipboard.lock().unwrap() {
        clip.hold(ciphertext);
        win.set_status(format!("Copied {name} to clipboard.").into());
    }
}

fn store_password(
    app: &mut App,
    win: &ui::MainWindow,
    name: &str,
    password: &str,
) -> bool {
    if name.is_empty() {
        win.set_status("Name cannot be empty.".into());
        return false;
    }

    if app.keystore.has_password(name) {
        win.set_status(
            format!("{name} already exists. Use Edit to change it.").into(),
        );
        return false;
    }

    let result = {
        let c = app.cached.lock().unwrap();
        match c.as_slice() {
            Some(mk) => {
                app.keystore.store_password(name, password.as_bytes(), mk)
            }
            None => return false,
        }
    };

    if let Err(e) = result {
        win.set_status(format!("Store error: {e:#}").into());
        return false;
    }

    refresh(app, win);
    win.set_status(format!("Stored {name}.").into());
    true
}

fn edit_password(
    app: &mut App,
    win: &ui::MainWindow,
    old_name: &str,
    new_name: &str,
    password: &str,
) {
    if new_name.is_empty() {
        win.set_status("Name cannot be empty.".into());
        return;
    }

    if password.is_empty() {
        if old_name != new_name
            && let Err(e) = app.keystore.rename_password(old_name, new_name)
        {
            win.set_status(format!("Rename error: {e:#}").into());
            return;
        }
    } else {
        let result = {
            let c = app.cached.lock().unwrap();
            match c.as_slice() {
                Some(mk) => app.keystore.store_password(
                    new_name,
                    password.as_bytes(),
                    mk,
                ),
                None => return,
            }
        };
        if let Err(e) = result {
            win.set_status(format!("Store error: {e:#}").into());
            return;
        }
        if old_name != new_name
            && let Err(e) = app.keystore.remove_password(old_name)
        {
            win.set_status(format!("Remove error: {e:#}").into());
            return;
        }
    }

    refresh(app, win);
    win.set_status(format!("Updated {new_name}.").into());
}

fn remove_password(app: &mut App, win: &ui::MainWindow, name: &str) {
    match app.keystore.remove_password(name) {
        Ok(()) => {
            refresh(app, win);
            win.set_status(format!("Removed {name}.").into());
        }
        Err(e) => {
            win.set_status(format!("Remove error: {e:#}").into());
        }
    }
}

fn refresh(app: &mut App, win: &ui::MainWindow) {
    match app.keystore.list_passwords() {
        Ok(names) => {
            app.names = names;
            let shared: Vec<slint::SharedString> = app
                .names
                .iter()
                .map(|n| slint::SharedString::from(n.as_str()))
                .collect();
            let model = slint::VecModel::from(shared);
            win.set_password_names(slint::ModelRc::new(model));
        }
        Err(e) => {
            win.set_status(format!("List error: {e:#}").into());
        }
    }
}

struct App {
    keystore: Rc<Keystore>,
    clipboard: Arc<Mutex<Option<clipboard::ClipboardHandle>>>,
    cached: Arc<Mutex<CachedKey>>,
    names: Vec<String>,
}

mod clipboard;
mod keystore;
mod memory_guard;
mod settings;
mod single_instance;
mod ui;
