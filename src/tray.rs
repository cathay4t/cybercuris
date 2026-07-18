// SPDX-License-Identifier: Apache-2.0
use std::{io::Cursor, sync::mpsc};

use image::ImageReader;

/// Embedded logo PNG (decoded once at startup).
static LOGO_PNG: &[u8] = include_bytes!("../logo/cybercuris.png");

#[derive(Clone, Debug)]
pub(crate) enum TrayAction {
    ShowWindow,
    Quit,
}

pub(crate) struct CybercurisTray {
    tx: mpsc::Sender<TrayAction>,
    pixmap: Option<ksni::Icon>,
}

impl ksni::Tray for CybercurisTray {
    fn id(&self) -> String {
        "cybercuris".into()
    }

    fn icon_name(&self) -> String {
        // Fallback themed icon if pixmap is not supported
        "cybercuris".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        self.pixmap.iter().cloned().collect()
    }

    fn title(&self) -> String {
        "cybercuris".into()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.send(TrayAction::ShowWindow);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        let show_tx = self.tx.clone();
        let quit_tx = self.tx.clone();
        vec![
            StandardItem {
                label: "Show cybercuris".into(),
                activate: Box::new(move |_| {
                    let _ = show_tx.send(TrayAction::ShowWindow);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(move |_| {
                    let _ = quit_tx.send(TrayAction::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

impl CybercurisTray {
    pub(crate) fn new(tx: mpsc::Sender<TrayAction>) -> Self {
        let pixmap = decode_logo_icon();
        Self { tx, pixmap }
    }
}

/// Decode the embedded PNG into an ARGB32 ksni::Icon.
fn decode_logo_icon() -> Option<ksni::Icon> {
    let img = ImageReader::new(Cursor::new(LOGO_PNG))
        .with_guessed_format()
        .ok()?
        .decode()
        .ok()?;
    let (w, h) = (img.width(), img.height());
    let mut data = img.into_rgba8().into_vec();
    // image crate produces RGBA; ksni expects ARGB, so rotate each pixel by 1 byte.
    for pixel in data.chunks_exact_mut(4) {
        pixel.rotate_right(1);
    }
    Some(ksni::Icon {
        width: w as i32,
        height: h as i32,
        data,
    })
}
