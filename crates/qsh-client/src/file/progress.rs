//! Progress reporting for file transfers.

use std::io::{self, Write};
use std::time::{Duration, Instant};

/// Format bytes in human-readable form.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format duration as mm:ss or hh:mm:ss.
fn format_duration(secs: f64) -> String {
    let total_secs = secs as u64;
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, mins, secs)
    } else {
        format!("{:02}:{:02}", mins, secs)
    }
}

/// Progress reporter for file transfers.
pub struct ProgressReporter {
    /// Transfer name (filename).
    name: String,
    /// Total size in bytes (if known).
    total: Option<u64>,
    /// Current bytes transferred.
    current: u64,
    /// Start time.
    start_time: Instant,
    /// Last update time.
    last_update: Instant,
    /// Last bytes count (for speed calc).
    last_bytes: u64,
    /// Minimum update interval.
    update_interval: Duration,
    /// Whether to show progress bar.
    show_bar: bool,
    /// Terminal width.
    term_width: u16,
}

impl ProgressReporter {
    /// Create a new progress reporter.
    pub fn new(name: String, total: Option<u64>) -> Self {
        let now = Instant::now();
        Self {
            name,
            total,
            current: 0,
            start_time: now,
            last_update: now,
            last_bytes: 0,
            update_interval: Duration::from_millis(100),
            show_bar: true,
            term_width: 80,
        }
    }

    /// Set whether to show progress bar.
    pub fn with_bar(mut self, show: bool) -> Self {
        self.show_bar = show;
        self
    }

    /// Set terminal width.
    pub fn with_width(mut self, width: u16) -> Self {
        self.term_width = width;
        self
    }

    /// Update progress.
    pub fn update(&mut self, bytes: u64) {
        self.current = bytes;

        let now = Instant::now();
        if now.duration_since(self.last_update) >= self.update_interval {
            self.render();
            self.last_update = now;
            self.last_bytes = bytes;
        }
    }

    /// Add bytes to current progress.
    pub fn add(&mut self, bytes: u64) {
        self.update(self.current + bytes);
    }

    /// Set the total size.
    pub fn set_total(&mut self, total: u64) {
        self.total = Some(total);
    }

    /// Finish the progress display.
    pub fn finish(&self) {
        self.render_final();
    }

    /// Render progress to stderr.
    fn render(&self) {
        if !self.show_bar {
            return;
        }

        let elapsed = self.start_time.elapsed().as_secs_f64();
        let speed = if elapsed > 0.0 {
            self.current as f64 / elapsed
        } else {
            0.0
        };

        let progress_str = if let Some(total) = self.total {
            let percent = if total > 0 {
                (self.current as f64 / total as f64 * 100.0).min(100.0)
            } else {
                100.0
            };

            let eta = if speed > 0.0 && self.current < total {
                let remaining = total - self.current;
                Some(remaining as f64 / speed)
            } else {
                None
            };

            // Build progress bar
            let bar_width = (self.term_width as usize).saturating_sub(60).max(10);
            let filled = ((percent / 100.0) * bar_width as f64) as usize;
            let bar: String = (0..bar_width)
                .map(|i| if i < filled { '#' } else { '-' })
                .collect();

            format!(
                "\r{}: [{}] {:5.1}% {}/{} {}/s ETA: {}",
                truncate_name(&self.name, 20),
                bar,
                percent,
                format_bytes(self.current),
                format_bytes(total),
                format_bytes(speed as u64),
                eta.map(format_duration)
                    .unwrap_or_else(|| "--:--".to_string())
            )
        } else {
            format!(
                "\r{}: {} {}/s",
                truncate_name(&self.name, 20),
                format_bytes(self.current),
                format_bytes(speed as u64)
            )
        };

        let _ = eprint!("{}", progress_str);
        let _ = io::stderr().flush();
    }

    /// Render final progress line.
    fn render_final(&self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let speed = if elapsed > 0.0 {
            self.current as f64 / elapsed
        } else {
            0.0
        };

        eprintln!(
            "\r{}: {} in {} ({}/s)                    ",
            truncate_name(&self.name, 20),
            format_bytes(self.current),
            format_duration(elapsed),
            format_bytes(speed as u64)
        );
    }
}

/// Truncate a name to fit in the given width.
fn truncate_name(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        format!("{:width$}", name, width = max_len)
    } else {
        format!("...{}", &name[name.len() - max_len + 3..])
    }
}

/// Simple progress for multiple files.
pub struct MultiProgress {
    /// Current file index (1-based).
    current_file: usize,
    /// Total number of files.
    total_files: usize,
    /// Total bytes transferred across all files.
    total_bytes: u64,
}

impl MultiProgress {
    /// Create a new multi-file progress tracker.
    pub fn new(total_files: usize) -> Self {
        Self {
            current_file: 0,
            total_files,
            total_bytes: 0,
        }
    }

    /// Start a new file.
    pub fn start_file(&mut self, name: &str, size: Option<u64>) -> ProgressReporter {
        self.current_file += 1;
        let prefix = format!("[{}/{}] {}", self.current_file, self.total_files, name);
        ProgressReporter::new(prefix, size)
    }

    /// Record completed file bytes.
    pub fn file_done(&mut self, bytes: u64) {
        self.total_bytes += bytes;
    }

    /// Get total bytes transferred.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(100), "100 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0.0), "00:00");
        assert_eq!(format_duration(65.0), "01:05");
        assert_eq!(format_duration(3665.0), "01:01:05");
    }

    #[test]
    fn test_truncate_name() {
        assert_eq!(truncate_name("short", 10), "short     ");
        assert_eq!(truncate_name("verylongfilename.txt", 10), "...ame.txt");
    }

    #[test]
    fn test_progress_reporter() {
        let mut reporter = ProgressReporter::new("test.txt".to_string(), Some(1000));
        reporter.update(500);
        reporter.finish();
    }
}
