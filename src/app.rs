use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;

use crate::model::{Analysis, Network};
use crate::scanner::{Scanner, macos_redaction_note_after_scan};

pub struct App {
    pub analysis: Option<Analysis>,
    pub selected_network: usize,
    pub status: String,
    /// Shown when macOS hides SSIDs; otherwise defaults to [`Self::base_access_status`].
    pub access_status: Option<String>,
    base_access_status: Option<String>,
    pub last_scan_summary: String,
    pub scan_in_progress: bool,
    scan_worker: ScanWorker,
    spinner_index: usize,
}

impl App {
    pub fn new(scanner: Scanner) -> Self {
        let status = format!(
            "Ready. Backend: {}. Starting initial scan...",
            scanner.backend_label()
        );

        Self {
            analysis: None,
            selected_network: 0,
            status,
            access_status: None,
            base_access_status: None,
            last_scan_summary: "No scan yet".into(),
            scan_in_progress: false,
            scan_worker: ScanWorker::spawn(scanner),
            spinner_index: 0,
        }
    }

    pub fn set_access_status(&mut self, access_status: Option<String>) {
        self.base_access_status = access_status.clone();
        self.access_status = access_status;
    }

    pub fn set_initial_analysis(&mut self, analysis: Option<Analysis>) {
        if let Some(analysis) = analysis {
            self.last_scan_summary = format!("{} networks detected", analysis.networks.len());
            let note = macos_redaction_note_after_scan(&analysis);
            self.analysis = Some(analysis);
            self.status = "Loaded current network. Scanning nearby networks...".into();
            self.access_status = note.or_else(|| self.base_access_status.clone());
        }
    }

    pub fn request_scan(&mut self) {
        if self.scan_in_progress {
            self.status = "Scan already running. Please wait for it to finish.".into();
            return;
        }

        if self.scan_worker.request_scan().is_ok() {
            self.scan_in_progress = true;
            self.spinner_index = 0;
            self.status = "Scanning nearby networks...".into();
        } else {
            self.status = "Scanner worker unavailable.".into();
        }
    }

    pub fn on_tick(&mut self) {
        if self.scan_in_progress {
            let frames = [
                "Scanning nearby networks   ",
                "Scanning nearby networks.  ",
                "Scanning nearby networks.. ",
                "Scanning nearby networks...",
            ];
            self.status = frames[self.spinner_index % frames.len()].into();
            self.spinner_index = (self.spinner_index + 1) % frames.len();
        }

        loop {
            match self.scan_worker.try_recv() {
                Ok(Ok((analysis, redaction_note))) => {
                    self.scan_in_progress = false;
                    self.last_scan_summary =
                        format!("{} networks detected", analysis.networks.len());
                    self.selected_network = self
                        .selected_network
                        .min(analysis.networks.len().saturating_sub(1));
                    self.status = "Scan complete. Press r to rescan, q to quit.".into();
                    self.access_status = redaction_note.or_else(|| self.base_access_status.clone());
                    self.analysis = Some(analysis);
                }
                Ok(Err(error)) => {
                    self.scan_in_progress = false;
                    self.last_scan_summary = "Scan failed".into();
                    self.status = format!("Scan failed: {error}");
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.scan_in_progress = false;
                    self.last_scan_summary = "Scanner unavailable".into();
                    self.status = "Scanner worker disconnected.".into();
                    break;
                }
            }
        }
    }

    pub fn networks(&self) -> &[Network] {
        self.analysis
            .as_ref()
            .map(|analysis| analysis.networks.as_slice())
            .unwrap_or(&[])
    }

    pub fn next_network(&mut self) {
        if !self.networks().is_empty() {
            self.selected_network = (self.selected_network + 1) % self.networks().len();
        }
    }

    pub fn previous_network(&mut self) {
        if !self.networks().is_empty() {
            self.selected_network = if self.selected_network == 0 {
                self.networks().len() - 1
            } else {
                self.selected_network - 1
            };
        }
    }
}

struct ScanWorker {
    request_tx: Sender<()>,
    result_rx: Receiver<Result<(Analysis, Option<String>), String>>,
}

impl ScanWorker {
    fn spawn(scanner: Scanner) -> Self {
        let (request_tx, request_rx) = mpsc::channel::<()>();
        let (result_tx, result_rx) =
            mpsc::channel::<Result<(Analysis, Option<String>), String>>();

        thread::spawn(move || {
            while request_rx.recv().is_ok() {
                let result = scanner.scan().map_err(|error| error.to_string());
                if result_tx.send(result).is_err() {
                    break;
                }
            }
        });

        Self {
            request_tx,
            result_rx,
        }
    }

    fn request_scan(&self) -> Result<(), mpsc::SendError<()>> {
        self.request_tx.send(())
    }

    fn try_recv(&self) -> Result<Result<(Analysis, Option<String>), String>, TryRecvError> {
        self.result_rx.try_recv()
    }
}
