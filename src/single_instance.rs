// SPDX-License-Identifier: Apache-2.0
//! Single-instance enforcement via Unix domain socket.
//!
//! When a second instance is launched, it sends a "show" command to the
//! existing instance and exits. The existing instance brings its main
//! window to the foreground.

use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

type ShowCallback = Arc<dyn Fn() + Send + Sync + 'static>;

/// Tries to activate an existing instance by connecting to its socket
/// and sending the "show" command. Returns `true` if the existing
/// instance was successfully notified.
pub(crate) fn try_activate_existing() -> bool {
    let path = socket_path();
    match UnixStream::connect(&path) {
        Ok(mut stream) => {
            // Notify existing instance to show its window.
            let _ = stream.write_all(b"show\n");
            let _ = stream.flush();
            // Read acknowledgment.
            let mut buf = [0u8; 2];
            let _ = stream.read_exact(&mut buf);
            true
        }
        Err(_) => false,
    }
}

#[derive(Clone)]
pub(crate) struct InstanceGuard {
    thread_handle: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
    shutdown: Arc<AtomicBool>,
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Wake up the listener by connecting and disconnecting.
        let path = socket_path();
        if let Ok(stream) = UnixStream::connect(&path) {
            drop(stream);
        }
        if let Ok(mut handle) = self.thread_handle.lock() {
            if let Some(h) = handle.take() {
                let _ = h.join();
            }
        }
        // Try to clean up the socket file.
        let _ = std::fs::remove_file(&path);
    }
}

/// Starts listening on the socket. Returns a guard that cleans up on drop.
/// `show_window` will be called (via slint::invoke_from_event_loop) when
/// a second instance wants to show the window.
pub(crate) fn start_listener(show_window: Arc<dyn Fn() + Send + Sync + 'static>) -> InstanceGuard {
    let show_window: ShowCallback = show_window;
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_handle = Arc::new(Mutex::new(None::<thread::JoinHandle<()>>));

    let shutdown_clone = shutdown.clone();
    let thread_handle_clone = thread_handle.clone();

    let handle = thread::spawn(move || {
        let path = socket_path();

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = match bind_socket(&path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to bind single-instance socket: {e}");
                return;
            }
        };

        // Set non-blocking so we can check shutdown flag between polls.
        listener
            .set_nonblocking(true)
            .expect("set_nonblocking on UnixListener");

        let polling_interval = std::time::Duration::from_millis(500);

        loop {
            if shutdown_clone.load(Ordering::SeqCst) {
                break;
            }

            match listener.accept() {
                Ok((stream, _addr)) => {
                    handle_connection(stream, show_window.clone());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(polling_interval);
                    continue;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("Single-instance accept error: {e}");
                }
            }
        }
    });

    *thread_handle_clone.lock().unwrap() = Some(handle);

    InstanceGuard {
        thread_handle: thread_handle_clone,
        shutdown,
    }
}

fn socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("cybercuris.sock")
    } else if let Some(data_dir) = dirs::data_local_dir() {
        data_dir.join("cybercuris").join("socket")
    } else {
        PathBuf::from("/tmp/cybercuris.sock")
    }
}

fn bind_socket(path: &std::path::Path) -> std::io::Result<UnixListener> {
    // Try to bind; if the socket file exists but nobody is listening,
    // remove the stale file and retry.
    match UnixListener::bind(path) {
        Ok(listener) => Ok(listener),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // Check if the socket is stale.
            match UnixStream::connect(path) {
                Ok(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "Another cybercuris instance is already running",
                )),
                Err(_) => {
                    // Stale socket – remove and retry.
                    let _ = std::fs::remove_file(path);
                    UnixListener::bind(path)
                }
            }
        }
        Err(e) => Err(e),
    }
}

fn handle_connection(
    stream: UnixStream,
    show_window: ShowCallback,
) {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_ok() {
        let cmd = line.trim();
        if cmd == "show" {
            // Use slint::invoke_from_event_loop from any thread.
            let _ = slint::invoke_from_event_loop(move || {
                show_window();
            });
            // Send acknowledgment.
            let _ = (&stream).write_all(b"ok");
            let _ = (&stream).flush();
        }
    }
}
