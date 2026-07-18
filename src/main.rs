// SPDX-License-Identifier: Apache-2.0
use std::{
    cell::RefCell,
    io::{self, Write},
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use anyhow::Context as _;
use clap::{Arg, ArgAction, Command};
use slint::ComponentHandle;

use crate::{
    keystore::Keystore,
    memory_guard::{MemoryGuard, PasswordBuf},
};

static SIGUSR1_RECEIVED: AtomicBool = AtomicBool::new(false);
static FORCE_TTY: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigusr1(_sig: libc::c_int) {
    SIGUSR1_RECEIVED.store(true, Ordering::SeqCst);
}

fn setup_signal_handler() {
    unsafe {
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
}

impl CachedKey {
    fn is_valid(&self) -> bool {
        self.key.is_some()
            && self
                .loaded_at
                .map_or(false, |t| t.elapsed() < Duration::from_secs(1800))
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
    eprint!("{prompt}: ");
    io::stderr().flush().ok();
    let mut pass = String::new();
    io::stdin()
        .read_line(&mut pass)
        .context("reading password from stdin")?;
    let pass = pass.trim_end_matches(&['\n', '\r'][..]).to_owned();
    Ok(PasswordBuf::new(&pass)?)
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
    let (tx, rx) = std::sync::mpsc::channel();

    let dlg_weak = dialog.as_weak();
    dialog.on_confirmed(move |password| {
        let _ = tx.send(password.to_string());
        // Defer hide+quit to next event-loop tick so the Wayland
        // compositor receives the hide before we tear down the loop.
        let timer = Box::new(slint::Timer::default());
        let dlg_weak = dlg_weak.clone();
        timer.start(
            slint::TimerMode::SingleShot,
            Duration::ZERO,
            move || {
                if let Some(dlg) = dlg_weak.upgrade() {
                    dlg.window().hide().ok();
                }
                let _ = slint::quit_event_loop();
            },
        );
        Box::leak(timer);
    });

    {
        let dlg_weak = dialog.as_weak();
        dialog.window().on_close_requested(move || {
            // Hide the window first, then quit on next tick
            if let Some(dlg) = dlg_weak.upgrade() {
                dlg.window().hide().ok();
            }
            let timer = Box::new(slint::Timer::default());
            timer.start(
                slint::TimerMode::SingleShot,
                Duration::ZERO,
                move || {
                    let _ = slint::quit_event_loop();
                },
            );
            Box::leak(timer);
            slint::CloseRequestResponse::HideWindow
        });
    }

    dialog.show()?;
    slint::run_event_loop()?;
    drop(dialog);

    rx.recv()
        .map_err(|_| anyhow::anyhow!("Password dialog closed"))
        .and_then(|s| Ok(PasswordBuf::new(&s)?))
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
    if *pass != *confirm {
        anyhow::bail!("Passwords do not match");
    }
    if pass.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }
    Ok(pass)
}

fn prompt_set_password_gui() -> anyhow::Result<PasswordBuf> {
    let dialog = ui::SetPasswordDialog::new()?;
    let (tx, rx) = std::sync::mpsc::channel();

    let dlg_weak = dialog.as_weak();
    dialog.on_confirmed(move |password| {
        let _ = tx.send(password.to_string());
        // Defer hide+quit to next event-loop tick so the Wayland
        // compositor receives the hide before we tear down the loop.
        let timer = Box::new(slint::Timer::default());
        let dlg_weak = dlg_weak.clone();
        timer.start(
            slint::TimerMode::SingleShot,
            Duration::ZERO,
            move || {
                if let Some(dlg) = dlg_weak.upgrade() {
                    dlg.window().hide().ok();
                }
                let _ = slint::quit_event_loop();
            },
        );
        Box::leak(timer);
    });

    {
        let dlg_weak = dialog.as_weak();
        dialog.window().on_close_requested(move || {
            if let Some(dlg) = dlg_weak.upgrade() {
                dlg.window().hide().ok();
            }
            let timer = Box::new(slint::Timer::default());
            timer.start(
                slint::TimerMode::SingleShot,
                Duration::ZERO,
                move || {
                    let _ = slint::quit_event_loop();
                },
            );
            Box::leak(timer);
            slint::CloseRequestResponse::HideWindow
        });
    }

    dialog.show()?;
    slint::run_event_loop()?;
    drop(dialog);

    rx.recv()
        .map_err(|_| anyhow::anyhow!("Password dialog closed"))
        .and_then(|s| Ok(PasswordBuf::new(&s)?))
}

fn unlock_key(
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
    c.as_slice()
        .map(|mk| keystore::password_aes_key_from_main_key(mk))
}

fn with_main_key<F, T>(cached: &Arc<Mutex<CachedKey>>, f: F) -> Option<T>
where
    F: FnOnce(&[u8]) -> T,
{
    let c = cached.lock().unwrap();
    c.as_slice().map(f)
}

fn main() -> anyhow::Result<()> {
    setup_signal_handler();

    let matches = Command::new("cybercuris")
        .about("Linux password manager")
        .arg_required_else_help(true)
        .arg(
            Arg::new("tty")
                .short('t')
                .long("tty")
                .action(ArgAction::SetTrue)
                .help("Force TTY password input mode")
                .global(true),
        )
        .subcommand(Command::new("gui").about("Launch the GUI"))
        .subcommand(
            Command::new("guiclip")
                .about("Show password list, pick one to copy to clipboard"),
        )
        .subcommand(Command::new("init").about("Initialize the main key"))
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
        Some(("gui", _)) | None => {
            if has_wayland() {
                run_gui()
            } else {
                anyhow::bail!(
                    "No WAYLAND_DISPLAY set; use CLI commands or -t for TTY \
                     mode"
                );
            }
        }
        Some(("guiclip", _)) => run_guiclip(),
        Some(("init", _)) => cli_init(),
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
    let pass = pass.trim_end_matches(&['\n', '\r'][..]).to_owned();
    Ok(PasswordBuf::new(&pass)?)
}

fn cli_init() -> anyhow::Result<()> {
    let keystore = Keystore::new()?;
    let password = prompt_set_password()?;
    keystore.init_main_key(&password)?;
    println!("Main key initialized.");
    Ok(())
}

fn cli_store(matches: &clap::ArgMatches) -> anyhow::Result<()> {
    let name = matches.get_one::<String>("NAME").unwrap();
    let keystore = Keystore::new()?;
    let cached: Arc<Mutex<CachedKey>> = Arc::new(Mutex::new(CachedKey {
        key: None,
        loaded_at: None,
    }));

    unlock_key_with_init(&keystore, &cached)?;

    let password = read_password(name)?;

    with_main_key(&cached, |mk| {
        keystore.store_password(name, password.as_bytes(), mk).ok();
    });

    println!("Stored password for {name}.");
    Ok(())
}

fn cli_get(matches: &clap::ArgMatches) -> anyhow::Result<()> {
    let name = matches.get_one::<String>("NAME").unwrap();
    let keystore = Keystore::new()?;
    let ciphertext = keystore.read_password_ciphertext(name)?;
    let cached: Arc<Mutex<CachedKey>> = Arc::new(Mutex::new(CachedKey {
        key: None,
        loaded_at: None,
    }));

    unlock_key_with_init(&keystore, &cached)?;

    let plain = with_main_key(&cached, |mk| {
        keystore::decrypt_with_main_key(mk, &ciphertext).ok()
    })
    .flatten()
    .ok_or_else(|| anyhow::anyhow!("Failed to decrypt password"))?;

    let mut stdout = io::stdout().lock();
    stdout.write_all(plain.as_slice())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn cli_clip(matches: &clap::ArgMatches) -> anyhow::Result<()> {
    let name = matches.get_one::<String>("NAME").unwrap();
    let keystore = Keystore::new()?;
    let ciphertext = keystore.read_password_ciphertext(name)?;
    let cached: Arc<Mutex<CachedKey>> = Arc::new(Mutex::new(CachedKey {
        key: None,
        loaded_at: None,
    }));

    unlock_key_with_init(&keystore, &cached)?;

    let aes_key = aes_password_key(&cached)
        .ok_or_else(|| anyhow::anyhow!("Failed to get AES key"))?;
    let clipboard = clipboard::spawn_clipboard_thread(aes_key)?;
    clipboard.hold_and_wait(ciphertext);
    println!("Copied {name} to clipboard.");
    Ok(())
}

fn run_guiclip() -> anyhow::Result<()> {
    let keystore = Keystore::new()?;
    let cached: Arc<Mutex<CachedKey>> = Arc::new(Mutex::new(CachedKey {
        key: None,
        loaded_at: None,
    }));

    unlock_key_with_init(&keystore, &cached)?;

    let all_names = keystore.list_passwords()?;

    if all_names.is_empty() {
        println!("No passwords stored.");
        return Ok(());
    }

    let aes_key = aes_password_key(&cached)
        .ok_or_else(|| anyhow::anyhow!("Failed to get AES key"))?;
    let clipboard = Rc::new(clipboard::spawn_clipboard_thread(aes_key)?);

    let win = ui::ClipSelector::new()?;
    slint::set_xdg_app_id(slint::SharedString::from("cybercuris_clip"))?;

    let make_model = |names: &[String]| {
        let shared: Vec<slint::SharedString> = names
            .iter()
            .map(|n| slint::SharedString::from(n.as_str()))
            .collect();
        slint::ModelRc::new(slint::VecModel::from(shared))
    };
    win.set_password_names(make_model(&all_names));

    let (tray_tx, tray_rx) = mpsc::channel::<tray::TrayAction>();
    let cybertray = tray::CybercurisTray::new(tray_tx);
    if let Err(e) = ksni::blocking::TrayMethods::spawn(cybertray) {
        eprintln!("System tray not available: {e:#}");
    }

    {
        let all_names = all_names.clone();
        let win_weak = win.as_weak();
        win.on_filter_changed(move |text| {
            let Some(win) = win_weak.upgrade() else {
                return;
            };
            let filtered: Vec<String> = if text.is_empty() {
                all_names.clone()
            } else {
                all_names
                    .iter()
                    .filter(|n| n.to_lowercase().contains(&text.to_lowercase()))
                    .cloned()
                    .collect()
            };
            win.set_password_names(make_model(&filtered));
        });
    }

    {
        let keystore = Rc::new(keystore);
        let clipboard = clipboard.clone();
        let win_weak = win.as_weak();
        win.on_copy_password(move |name| {
            let Some(win) = win_weak.upgrade() else {
                return;
            };
            if let Ok(ct) = keystore.read_password_ciphertext(name.as_str()) {
                clipboard.hold(ct);
            }
            win.window().hide().ok();
        });
    }

    {
        let win_weak = win.as_weak();
        win.on_quit(move || {
            if let Some(win) = win_weak.upgrade() {
                win.window().hide().ok();
            }
        });
    }

    win.window()
        .on_close_requested(|| slint::CloseRequestResponse::HideWindow);

    let tray_timer = slint::Timer::default();
    {
        let win_weak = win.as_weak();
        let cached_clone = cached.clone();
        tray_timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(250),
            move || {
                while let Ok(action) = tray_rx.try_recv() {
                    match action {
                        tray::TrayAction::ShowWindow => {
                            if let Some(win) = win_weak.upgrade() {
                                let _ = win.show();
                            }
                        }
                        tray::TrayAction::Quit => {
                            cached_clone.lock().unwrap().drop_key();
                            let _ = slint::quit_event_loop();
                        }
                    }
                }
            },
        );
    }

    win.run()?;

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
    let cached: Arc<Mutex<CachedKey>> = Arc::new(Mutex::new(CachedKey {
        key: None,
        loaded_at: None,
    }));

    unlock_key_with_init(&keystore, &cached)?;

    let aes_key = aes_password_key(&cached)
        .ok_or_else(|| anyhow::anyhow!("Failed to get AES key"))?;
    let clipboard = clipboard::spawn_clipboard_thread(aes_key)?;

    let win = ui::MainWindow::new()?;
    slint::set_xdg_app_id(slint::SharedString::from("cybercuris"))?;

    let (tray_tx, tray_rx) = mpsc::channel::<tray::TrayAction>();
    let cybertray = tray::CybercurisTray::new(tray_tx);
    if let Err(e) = ksni::blocking::TrayMethods::spawn(cybertray) {
        eprintln!("System tray not available: {e:#}");
    }

    let app = Rc::new(RefCell::new(App {
        keystore: keystore.clone(),
        clipboard,
        cached: cached.clone(),
        names: Vec::new(),
    }));

    {
        let app = app.clone();
        let win_weak = win.as_weak();
        win.on_store_password(move |name, password| {
            let win = win_weak.upgrade().unwrap();
            let mut app = app.borrow_mut();
            if unlock_key(&app.keystore, &app.cached).is_err() {
                win.set_status("Failed to unlock main key.".into());
                return;
            }
            store_password(&mut app, &win, name.as_str(), password.as_str());
        });
    }

    {
        let app = app.clone();
        let win_weak = win.as_weak();
        win.on_copy_password(move |name| {
            let win = win_weak.upgrade().unwrap();
            let mut app = app.borrow_mut();
            if unlock_key(&app.keystore, &app.cached).is_err() {
                win.set_status("Failed to unlock main key.".into());
                return;
            }
            copy_password(&mut app, &win, name.as_str());
            win.window().hide().ok();
        });
    }

    {
        let app = app.clone();
        let win_weak = win.as_weak();
        win.on_remove_password(move |name| {
            let win = win_weak.upgrade().unwrap();
            let mut app = app.borrow_mut();
            remove_password(&mut app, &win, name.as_str());
        });
    }

    {
        let app = app.clone();
        let win_weak = win.as_weak();
        win.on_refresh(move || {
            let win = win_weak.upgrade().unwrap();
            let mut app = app.borrow_mut();
            refresh(&mut app, &win);
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

    refresh(&mut app.borrow_mut(), &win);

    win.window()
        .on_close_requested(|| slint::CloseRequestResponse::HideWindow);

    let tray_timer = slint::Timer::default();
    {
        let win_weak = win.as_weak();
        let cached_clone = cached.clone();
        tray_timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(250),
            move || {
                while let Ok(action) = tray_rx.try_recv() {
                    match action {
                        tray::TrayAction::ShowWindow => {
                            if let Some(win) = win_weak.upgrade() {
                                let _ = win.show();
                            }
                        }
                        tray::TrayAction::Quit => {
                            cached_clone.lock().unwrap().drop_key();
                            let _ = slint::quit_event_loop();
                        }
                    }
                }
            },
        );
    }

    win.run()?;

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

    app.clipboard.hold(ciphertext);
    win.set_status(format!("Copied {name} to clipboard.").into());
}

fn store_password(
    app: &mut App,
    win: &ui::MainWindow,
    name: &str,
    password: &str,
) {
    let result = {
        let c = app.cached.lock().unwrap();
        match c.as_slice() {
            Some(mk) => {
                app.keystore.store_password(name, password.as_bytes(), mk)
            }
            None => return,
        }
    };

    if let Err(e) = result {
        win.set_status(format!("Store error: {e:#}").into());
        return;
    }

    refresh(app, win);
    win.set_status(format!("Stored {name}.").into());
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
    clipboard: clipboard::ClipboardHandle,
    cached: Arc<Mutex<CachedKey>>,
    names: Vec<String>,
}

mod clipboard;
mod keystore;
mod memory_guard;
mod tray;
mod ui;
