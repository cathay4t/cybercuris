// SPDX-License-Identifier: Apache-2.0
use std::{io::Write, os::fd::AsRawFd, sync::mpsc};

use wayland_client::{
    Connection, Dispatch, QueueHandle,
    globals::{GlobalListContents, registry_queue_init},
    protocol::{wl_registry, wl_seat},
};
use wayland_protocols_wlr::data_control::v1::client::{
    zwlr_data_control_device_v1,
    zwlr_data_control_device_v1::ZwlrDataControlDeviceV1,
    zwlr_data_control_manager_v1::ZwlrDataControlManagerV1,
    zwlr_data_control_offer_v1::ZwlrDataControlOfferV1,
    zwlr_data_control_source_v1::ZwlrDataControlSourceV1,
};

use crate::keystore;

const MIME_TYPES: &[&str] = &["text/plain;charset=utf-8", "text/plain"];

pub(crate) enum ClipboardJob {
    Hold {
        ciphertext: Vec<u8>,
        done: Option<mpsc::Sender<()>>,
    },
    Shutdown,
}

pub(crate) struct ClipboardHandle {
    sender: mpsc::Sender<ClipboardJob>,
    pipe_write: i32,
}

impl ClipboardHandle {
    fn wake(&self) {
        let wake_byte: [u8; 1] = [1];
        unsafe {
            libc::write(
                self.pipe_write,
                wake_byte.as_ptr() as *const libc::c_void,
                1,
            );
        }
    }

    pub(crate) fn hold_and_wait(&self, ciphertext: Vec<u8>) {
        let (tx, rx) = mpsc::channel();
        let _ = self.sender.send(ClipboardJob::Hold {
            ciphertext,
            done: Some(tx),
        });
        self.wake();
        let _ = rx.recv_timeout(std::time::Duration::from_secs(10));
    }

    pub(crate) fn hold(&self, ciphertext: Vec<u8>) {
        let _ = self.sender.send(ClipboardJob::Hold {
            ciphertext,
            done: None,
        });
        self.wake();
    }
}

impl Drop for ClipboardHandle {
    fn drop(&mut self) {
        let _ = self.sender.send(ClipboardJob::Shutdown);
        self.wake();
        unsafe {
            libc::close(self.pipe_write);
        }
    }
}

pub(crate) fn spawn_clipboard_thread(
    aes_key: [u8; 32],
) -> anyhow::Result<ClipboardHandle> {
    let (tx, rx) = mpsc::channel();

    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        anyhow::bail!(
            "failed to create pipe: {}",
            std::io::Error::last_os_error()
        );
    }

    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

    std::thread::spawn(move || {
        if let Err(e) = run_clipboard_loop(rx, pipe_read, aes_key) {
            eprintln!("Clipboard thread error: {e:#}");
        }
        unsafe {
            libc::close(pipe_read);
        }
    });

    Ok(ClipboardHandle {
        sender: tx,
        pipe_write,
    })
}

struct ClipboardState {
    running: bool,
    manager: ZwlrDataControlManagerV1,
    device: ZwlrDataControlDeviceV1,
    source: Option<ZwlrDataControlSourceV1>,
    held: Option<Vec<u8>>,
    aes_key: [u8; 32],
    done_tx: Option<mpsc::Sender<()>>,
    send_count: u32,
}

fn run_clipboard_loop(
    rx: mpsc::Receiver<ClipboardJob>,
    pipe_read: i32,
    aes_key: [u8; 32],
) -> anyhow::Result<()> {
    let conn = Connection::connect_to_env()?;
    let (globals, mut event_queue) =
        registry_queue_init::<ClipboardState>(&conn)?;
    let qh = event_queue.handle();

    let manager: ZwlrDataControlManagerV1 = globals.bind(&qh, 1..=2, ())?;
    let seat: wl_seat::WlSeat = globals.bind(&qh, 1..=1, ())?;
    let device = manager.get_data_device(&seat, &qh, ());

    let mut state = ClipboardState {
        running: true,
        manager,
        device,
        source: None,
        held: None,
        aes_key,
        done_tx: None,
        send_count: 0,
    };

    event_queue.roundtrip(&mut state)?;

    let qh = event_queue.handle();

    while state.running {
        event_queue.dispatch_pending(&mut state)?;

        loop {
            match rx.try_recv() {
                Ok(ClipboardJob::Hold { ciphertext, done }) => {
                    set_selection(&mut state, &qh, ciphertext, done);
                }
                Ok(ClipboardJob::Shutdown)
                | Err(mpsc::TryRecvError::Disconnected) => {
                    state.running = false;
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
            }
        }

        event_queue.flush()?;

        if !state.running {
            break;
        }

        let Some(guard) = event_queue.prepare_read() else {
            continue;
        };

        let conn_fd = guard.connection_fd().as_raw_fd();

        let mut poll_fds = [
            libc::pollfd {
                fd: conn_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pipe_read,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }

        if poll_fds[0].revents & libc::POLLIN != 0 {
            guard.read().ok();
        } else {
            drop(guard);
        }

        if poll_fds[1].revents & libc::POLLIN != 0 {
            let mut buf = [0u8; 64];
            unsafe {
                libc::read(
                    pipe_read,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                );
            }
        }
    }

    if let Some(source) = state.source.take() {
        source.destroy();
    }
    state.held = None;
    if let Some(tx) = state.done_tx.take() {
        let _ = tx.send(());
    }
    event_queue.flush().ok();

    Ok(())
}

fn set_selection(
    state: &mut ClipboardState,
    qh: &QueueHandle<ClipboardState>,
    ciphertext: Vec<u8>,
    done: Option<mpsc::Sender<()>>,
) {
    if let Some(source) = state.source.take() {
        source.destroy();
    }

    let source = state.manager.create_data_source(qh, ());
    for mime in MIME_TYPES {
        source.offer(mime.to_string());
    }

    state.device.set_selection(Some(&source));
    state.source = Some(source);
    state.held = Some(ciphertext);
    state.done_tx = done;
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for ClipboardState {
    fn event(
        _state: &mut Self,
        _proxy: &wl_registry::WlRegistry,
        _event: wl_registry::Event,
        _data: &GlobalListContents,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_seat::WlSeat, ()> for ClipboardState {
    fn event(
        _state: &mut Self,
        _proxy: &wl_seat::WlSeat,
        _event: wl_seat::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwlrDataControlManagerV1, ()> for ClipboardState {
    fn event(
        _state: &mut Self,
        _proxy: &ZwlrDataControlManagerV1,
        _event: <ZwlrDataControlManagerV1 as wayland_client::Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwlrDataControlDeviceV1, ()> for ClipboardState {
    fn event(
        _state: &mut Self,
        _proxy: &ZwlrDataControlDeviceV1,
        _event: <ZwlrDataControlDeviceV1 as wayland_client::Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }

    wayland_client::event_created_child!(
        ClipboardState,
        ZwlrDataControlDeviceV1,
        [zwlr_data_control_device_v1::EVT_DATA_OFFER_OPCODE => (ZwlrDataControlOfferV1, ())]
    );
}

impl Dispatch<ZwlrDataControlOfferV1, ()> for ClipboardState {
    fn event(
        _state: &mut Self,
        _proxy: &ZwlrDataControlOfferV1,
        _event: <ZwlrDataControlOfferV1 as wayland_client::Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwlrDataControlSourceV1, ()> for ClipboardState {
    fn event(
        state: &mut Self,
        _proxy: &ZwlrDataControlSourceV1,
        event: <ZwlrDataControlSourceV1 as wayland_client::Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        use wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_source_v1::Event;
        match event {
            Event::Send { mime_type, fd } => {
                if !mime_type.starts_with("text/plain") {
                    return;
                }
                if let Some(ciphertext) = state.held.as_ref() {
                    let mut file = std::fs::File::from(fd);
                    let _ = keystore::decrypt_with_aes_key_into_writer(
                        &state.aes_key,
                        ciphertext,
                        &mut file,
                    );
                    let _ = file.flush();
                    drop(file);
                    state.send_count += 1;
                    if state.send_count >= 2 {
                        // Paste-once: drop ciphertext after full paste cycle
                        state.held = None;
                        if let Some(tx) = state.done_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                }
            }
            Event::Cancelled => {
                if let Some(source) = state.source.take() {
                    source.destroy();
                }
                state.held = None;
                if let Some(tx) = state.done_tx.take() {
                    let _ = tx.send(());
                }
            }
            _ => {}
        }
    }
}
