use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::config::SubnetEntry;

pub trait ProgressReporter: Send + Sync {
    fn update(&self, subnet_index: usize, global_scanned: usize);
    fn record_hit(&self, subnet_index: usize);
    fn finish(&self);
}

struct SubnetProgress {
    bar: ProgressBar,
    found: AtomicUsize,
}

pub struct TerminalProgress {
    _multi: MultiProgress,
    subnet_bars: Vec<SubnetProgress>,
    overall_bar: ProgressBar,
    stats_bar: ProgressBar,
    total_found: AtomicUsize,
}

impl TerminalProgress {
    /// Create progress bars for each subnet + an overall bar.
    pub fn new(subnets: &[SubnetEntry], host_counts: &[u64]) -> Self {
        let multi = MultiProgress::new();
        let total_hosts: u64 = host_counts.iter().sum();

        let bar_style = ProgressStyle::with_template(
            "  {prefix}\n  {bar:40.cyan/dark_gray}  {percent:>3}% {pos:>9}/{len:9}  {msg}",
        )
        .unwrap()
        .progress_chars("█░░");

        // Header
        let header = multi.add(ProgressBar::new(0));
        header.set_style(ProgressStyle::with_template("{msg}").unwrap());
        header.set_message(format!(
            "subnet-recon v0.1.0 — scanning {} hosts across {} subnets\n",
            format_number(total_hosts),
            subnets.len()
        ));
        header.tick();

        let mut subnet_bars = Vec::new();
        for (i, entry) in subnets.iter().enumerate() {
            let bar = multi.add(ProgressBar::new(host_counts[i]));
            bar.set_style(bar_style.clone());
            let label = if entry.label.is_empty() {
                entry.cidr.clone()
            } else {
                format!("{} ({})", entry.cidr, entry.label)
            };
            bar.set_prefix(label);
            bar.set_message("0 found");
            bar.enable_steady_tick(Duration::from_millis(100));
            subnet_bars.push(SubnetProgress {
                bar,
                found: AtomicUsize::new(0),
            });
        }

        // Spacer
        let spacer = multi.add(ProgressBar::new(0));
        spacer.set_style(ProgressStyle::with_template("{msg}").unwrap());
        spacer.set_message("");
        spacer.tick();

        // Overall bar
        let overall_bar = multi.add(ProgressBar::new(total_hosts));
        overall_bar.set_style(bar_style);
        overall_bar.set_prefix("Overall".to_string());
        overall_bar.set_message("0 found");
        overall_bar.enable_steady_tick(Duration::from_millis(100));

        // Stats line
        let stats_bar = multi.add(ProgressBar::new(0));
        stats_bar.set_style(ProgressStyle::with_template("\n  {msg}").unwrap());
        stats_bar.set_message("Rate: 0 probes/sec    Elapsed: 0s    ETA: --");
        stats_bar.enable_steady_tick(Duration::from_millis(100));

        Self {
            _multi: multi,
            subnet_bars,
            overall_bar,
            stats_bar,
            total_found: AtomicUsize::new(0),
        }
    }
}

impl ProgressReporter for TerminalProgress {
    fn update(&self, subnet_index: usize, global_scanned: usize) {
        if let Some(sp) = self.subnet_bars.get(subnet_index) {
            sp.bar.inc(1);
        }
        self.overall_bar.set_position(global_scanned as u64);

        // Update stats line periodically (every 100 probes to reduce overhead)
        if global_scanned % 100 == 0 {
            let elapsed = self.overall_bar.elapsed();
            let elapsed_secs = elapsed.as_secs_f64();
            let rate = if elapsed_secs > 0.0 {
                global_scanned as f64 / elapsed_secs
            } else {
                0.0
            };
            let total = self.overall_bar.length().unwrap_or(0);
            let remaining = total.saturating_sub(global_scanned as u64);
            let eta = if rate > 0.0 {
                format_duration(Duration::from_secs_f64(remaining as f64 / rate))
            } else {
                "--".to_string()
            };
            self.stats_bar.set_message(format!(
                "Rate: {} probes/sec    Elapsed: {}    ETA: ~{}",
                format_number(rate as u64),
                format_duration(elapsed),
                eta
            ));
        }
    }

    fn record_hit(&self, subnet_index: usize) {
        if let Some(sp) = self.subnet_bars.get(subnet_index) {
            let count = sp.found.fetch_add(1, Ordering::Relaxed) + 1;
            sp.bar.set_message(format!("{} found", format_number(count as u64)));
        }
        let total = self.total_found.fetch_add(1, Ordering::Relaxed) + 1;
        self.overall_bar
            .set_message(format!("{} found", format_number(total as u64)));
    }

    fn finish(&self) {
        for sp in &self.subnet_bars {
            sp.bar.finish();
        }
        self.overall_bar.finish();
        self.stats_bar.finish_and_clear();
    }
}

/// No-op progress reporter for quiet mode.
pub struct SilentProgress;

impl ProgressReporter for SilentProgress {
    fn update(&self, _: usize, _: usize) {}
    fn record_hit(&self, _: usize) {}
    fn finish(&self) {}
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}
