use std::io::Write;
use std::path::Path;

use crate::config::{Config, OutputFormat};
use crate::scan::{ScanResult, ScanTarget};

pub fn write_results(result: &ScanResult, config: &Config) -> std::io::Result<()> {
    let mut targets = result.reachable.clone();
    targets.sort_by(|a, b| a.ip.cmp(&b.ip));

    let output_path = &config.output.file;
    let mut writer: Box<dyn Write> = if output_path.is_empty() {
        Box::new(std::io::stdout().lock())
    } else {
        Box::new(std::fs::File::create(Path::new(output_path))?)
    };

    match config.output.format {
        OutputFormat::Plain => write_plain(&mut writer, &targets)?,
        OutputFormat::Json => write_json(&mut writer, &targets, &config.subnets)?,
    }

    writer.flush()?;
    Ok(())
}

fn write_plain(writer: &mut dyn Write, targets: &[ScanTarget]) -> std::io::Result<()> {
    for target in targets {
        writeln!(writer, "{}", target.ip)?;
    }
    Ok(())
}

fn write_json(
    writer: &mut dyn Write,
    targets: &[ScanTarget],
    subnets: &[crate::config::SubnetEntry],
) -> std::io::Result<()> {
    let entries: Vec<serde_json::Value> = targets
        .iter()
        .map(|t| {
            let label = subnets
                .get(t.subnet_index)
                .map(|s| s.label.as_str())
                .unwrap_or("");
            serde_json::json!({
                "ip": t.ip.to_string(),
                "subnet": subnets.get(t.subnet_index).map(|s| s.cidr.as_str()).unwrap_or(""),
                "label": label,
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&entries).unwrap();
    writeln!(writer, "{}", json)?;
    Ok(())
}
