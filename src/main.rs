// SPDX-License-Identifier: Apache-2.0
use std::{
    cell::RefCell,
    io::{self, Write},
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
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
    slint::set_xdg_app_id(slint::SharedString::from("cybercuris"))?;
    let (tx, rx) = std::sync::mpsc::channel();

    let dlg_weak = dialog.as_weak();
    let do_confirm = {
        let dlg_weak = dlg_weak.clone();
        let tx = tx.clone();
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
            Box::leak(timer);
        }
    };

    dialog.on_accepted(do_confirm.clone());
    dialog.on_ok_clicked(do_confirm);

    dialog.on_cancel_clicked(move || {
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
        Box::leak(timer);
    });

    dialog.show()?;
    slint::run_event_loop()?;

    let password = rx
        .recv()
        .map_err(|_| anyhow::anyhow!("Password dialog closed"))?;
    if password.is_empty() {
        anyhow::bail!("Password dialog dismissed");
    }
    Ok(PasswordBuf::new(&password)?)
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
    slint::set_xdg_app_id(slint::SharedString::from("cybercuris"))?;

    loop {
        let dialog = ui::SetPasswordDialog::new()?;
        let (tx, rx) = std::sync::mpsc::channel();

        let dlg_weak = dialog.as_weak();
        let do_confirm = {
            let dlg_weak = dlg_weak.clone();
            let tx = tx.clone();
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
                Box::leak(timer);
            }
        };

        dialog.on_accepted(do_confirm.clone());
        dialog.on_ok_clicked(do_confirm);

        dialog.on_cancel_clicked(move || {
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
            Box::leak(timer);
        });

        dialog.show()?;
        slint::run_event_loop()?;

        let (p1, p2) = rx
            .recv()
            .map_err(|_| anyhow::anyhow!("Password dialog closed"))?;

        if p1.is_empty() && p2.is_empty() {
            anyhow::bail!("Password setup dismissed");
        }

        if p1 != p2 {
            eprintln!("Passwords do not match.");
            continue;
        }

        if p1.is_empty() {
            eprintln!("Password cannot be empty.");
            continue;
        }

        return Ok(PasswordBuf::new(&p1)?);
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
                    "No WAYLAND_DISPLAY set; use CLI commands or -t for TTY mode"
                );
            }
        }
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
    let clipboard: Rc<RefCell<Option<clipboard::ClipboardHandle>>> =
        Rc::new(RefCell::new(None));
    let all_names: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));

    let win = ui::MainWindow::new()?;
    slint::set_xdg_app_id(slint::SharedString::from("cybercuris"))?;

    win.set_locked(true);
    win.set_needs_init(!keystore.is_initialized());

    let tray = ui::CybercurisTray::new()?;

    {
        let win_weak = win.as_weak();
        tray.on_show_window(move || {
            if let Some(win) = win_weak.upgrade() {
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
                    *clipboard.borrow_mut() = Some(
                        clipboard::spawn_clipboard_thread(aes_key).unwrap(),
                    );
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
                    *clipboard.borrow_mut() = Some(
                        clipboard::spawn_clipboard_thread(aes_key).unwrap(),
                    );
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
            *clipboard.borrow_mut() = None;
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
            let Some(win) = win_weak.upgrade() else { return };
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
                return;
            };
            let mut app = app.borrow_mut();
            store_password(&mut app, &win, name.as_str(), password.as_str());
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

    win.show()?;
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

    if let Some(ref clip) = *app.clipboard.borrow() {
        clip.hold(ciphertext);
        win.set_status(format!("Copied {name} to clipboard.").into());
    }
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
    clipboard: Rc<RefCell<Option<clipboard::ClipboardHandle>>>,
    cached: Arc<Mutex<CachedKey>>,
    names: Vec<String>,
}

mod clipboard;
mod keystore;
mod memory_guard;
mod ui;
