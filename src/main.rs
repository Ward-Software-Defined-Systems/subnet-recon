mod config;
mod progress;
mod results;
mod scan;

use std::sync::Arc;

use clap::Parser;
use ipnet::Ipv4Net;

use config::{Cli, load_config};
use progress::{ProgressReporter, SilentProgress, TerminalProgress};
use scan::{build_scan_targets, run_scan};

fn main() {
    let cli = Cli::parse();

    // Load and validate config
    let mut config = match load_config(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // Apply CLI overrides
    if let Some(threads) = cli.threads {
        config.scan.threads = if threads == 0 {
            num_cpus::get()
        } else {
            threads
        };
    }
    if let Some(ref output) = cli.output {
        config.output.file = output.to_string_lossy().to_string();
    }

    // Compute host counts per subnet
    let host_counts: Vec<u64> = config
        .subnets
        .iter()
        .map(|s| {
            let net: Ipv4Net = s.cidr.parse().unwrap();
            net.hosts().count() as u64
        })
        .collect();
    let total_hosts: u64 = host_counts.iter().sum();

    if cli.verbose > 0 {
        eprintln!(
            "Config: {} subnets, {} total hosts, {} threads, {:?} probe",
            config.subnets.len(),
            total_hosts,
            config.scan.threads,
            config.scan.method
        );
    }

    // Build scan targets
    let targets = build_scan_targets(&config.subnets, &config.scan.randomize);

    // Create progress reporter
    let progress: Arc<dyn ProgressReporter> = if cli.quiet {
        Arc::new(SilentProgress)
    } else {
        Arc::new(TerminalProgress::new(&config.subnets, &host_counts))
    };

    // Run scan
    let result = run_scan(targets, &config.scan, &progress);

    // Finish progress display
    progress.finish();

    // Write results
    if let Err(e) = results::write_results(&result, &config) {
        eprintln!("Error writing results: {}", e);
        std::process::exit(1);
    }

    // Print summary
    eprintln!(
        "\nScan complete: {} hosts scanned, {} reachable, {:.1}s elapsed",
        result.total_scanned,
        result.reachable.len(),
        result.duration.as_secs_f64()
    );
}
