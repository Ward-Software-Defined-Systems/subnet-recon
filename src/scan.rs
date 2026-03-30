use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::Ipv4Net;
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rayon::prelude::*;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::config::{DnsConfig, ProbeMethod, RandomizeMode, ScanConfig, SubnetEntry};
use crate::progress::ProgressReporter;

#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub ip: Ipv4Addr,
    pub subnet_index: usize,
    pub hostname: Option<String>,
}

pub struct ScanResult {
    pub reachable: Vec<ScanTarget>,
    pub total_scanned: usize,
    pub duration: Duration,
}

/// Expand all configured subnets into scan targets, shuffled per mode.
pub fn build_scan_targets(subnets: &[SubnetEntry], mode: &RandomizeMode) -> Vec<ScanTarget> {
    match mode {
        RandomizeMode::Global => {
            let mut targets: Vec<ScanTarget> = subnets
                .iter()
                .enumerate()
                .flat_map(|(idx, entry)| {
                    let net: Ipv4Net = entry.cidr.parse().unwrap();
                    net.hosts().map(move |ip| ScanTarget {
                        ip,
                        subnet_index: idx,
                        hostname: None,
                    })
                })
                .collect();
            targets.shuffle(&mut thread_rng());
            targets
        }
        RandomizeMode::PerSubnet => {
            let mut per_subnet: Vec<Vec<ScanTarget>> = subnets
                .iter()
                .enumerate()
                .map(|(idx, entry)| {
                    let net: Ipv4Net = entry.cidr.parse().unwrap();
                    let mut targets: Vec<ScanTarget> = net
                        .hosts()
                        .map(|ip| ScanTarget {
                            ip,
                            subnet_index: idx,
                            hostname: None,
                        })
                        .collect();
                    targets.shuffle(&mut thread_rng());
                    targets
                })
                .collect();

            // Round-robin interleave
            let max_len = per_subnet.iter().map(|v| v.len()).max().unwrap_or(0);
            let mut result = Vec::new();
            for i in 0..max_len {
                for subnet_targets in &mut per_subnet {
                    if i < subnet_targets.len() {
                        result.push(subnet_targets[i].clone());
                    }
                }
            }
            result
        }
        RandomizeMode::None => subnets
            .iter()
            .enumerate()
            .flat_map(|(idx, entry)| {
                let net: Ipv4Net = entry.cidr.parse().unwrap();
                net.hosts().map(move |ip| ScanTarget {
                    ip,
                    subnet_index: idx,
                    hostname: None,
                })
            })
            .collect(),
    }
}

/// Probe a single host. Returns true if reachable.
pub fn probe_host(ip: Ipv4Addr, method: &ProbeMethod, timeout: Duration, tcp_port: u16) -> bool {
    match method {
        ProbeMethod::Icmp => probe_icmp(ip, timeout),
        ProbeMethod::Tcp => probe_tcp(ip, tcp_port, timeout),
    }
}

fn probe_icmp(ip: Ipv4Addr, timeout: Duration) -> bool {
    let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return false,
    };

    if socket.set_read_timeout(Some(timeout)).is_err() {
        return false;
    }

    // Build ICMP Echo Request
    let identifier: u16 = rand::random();
    let sequence: u16 = 1;
    let packet = build_icmp_echo_request(identifier, sequence);

    let dest = SocketAddr::from((ip, 0));
    let dest = SockAddr::from(dest);

    if socket.send_to(&packet, &dest).is_err() {
        return false;
    }

    // Receive loop until timeout
    let start = Instant::now();
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1024];
    while start.elapsed() < timeout {
        let result = socket.recv_from(&mut buf);
        match result {
            Ok((len, _)) => {
                if len >= 28 {
                    // IP header (20 bytes) + ICMP header
                    // Safety: recv_from initialized `len` bytes
                    let data: &[u8] = unsafe {
                        std::slice::from_raw_parts(buf.as_ptr() as *const u8, len)
                    };
                    let icmp_type = data[20];
                    let reply_id = u16::from_be_bytes([data[24], data[25]]);
                    let reply_seq = u16::from_be_bytes([data[26], data[27]]);
                    if icmp_type == 0 && reply_id == identifier && reply_seq == sequence {
                        return true;
                    }
                }
            }
            Err(_) => return false,
        }
    }
    false
}

fn probe_tcp(ip: Ipv4Addr, port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::from((ip, port));
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => true,
        Err(e) => {
            // Connection refused = host is reachable (responded with RST)
            e.kind() == std::io::ErrorKind::ConnectionRefused
        }
    }
}

/// Build an ICMP Echo Request packet with RFC 1071 checksum.
fn build_icmp_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 8];
    packet[0] = 8; // Type: Echo Request
    packet[1] = 0; // Code: 0
    // Checksum placeholder at [2..4]
    packet[2] = 0;
    packet[3] = 0;
    // Identifier
    packet[4] = (identifier >> 8) as u8;
    packet[5] = (identifier & 0xff) as u8;
    // Sequence
    packet[6] = (sequence >> 8) as u8;
    packet[7] = (sequence & 0xff) as u8;

    // Compute checksum
    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;

    packet
}

/// RFC 1071 internet checksum: ones' complement of the ones' complement sum of 16-bit words.
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < data.len() {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum += word;
        i += 2;
    }
    // Fold 32-bit sum into 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// Token-bucket rate limiter.
pub struct RateLimiter {
    tokens: Mutex<f64>,
    rate: f64,
    last_refill: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(rate: u32) -> Option<Self> {
        if rate == 0 {
            None
        } else {
            Some(Self {
                tokens: Mutex::new(rate as f64),
                rate: rate as f64,
                last_refill: Mutex::new(Instant::now()),
            })
        }
    }

    /// Block until a token is available.
    pub fn acquire(&self) {
        loop {
            {
                let mut tokens = self.tokens.lock();
                let mut last = self.last_refill.lock();
                let now = Instant::now();
                let elapsed = now.duration_since(*last).as_secs_f64();
                *tokens += elapsed * self.rate;
                if *tokens > self.rate {
                    *tokens = self.rate;
                }
                *last = now;

                if *tokens >= 1.0 {
                    *tokens -= 1.0;
                    return;
                }
            }
            std::thread::sleep(Duration::from_micros(100));
        }
    }
}

/// Perform reverse DNS lookups on reachable hosts in parallel.
pub fn resolve_hostnames(targets: &mut [ScanTarget], dns_config: &DnsConfig) {
    use hickory_resolver::config::{
        NameServerConfigGroup, ResolverConfig, ResolverOpts,
    };
    use hickory_resolver::TokioResolver;

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(dns_config.timeout_ms);

    let resolver = if dns_config.servers.is_empty() {
        TokioResolver::builder_tokio()
            .expect("Failed to create DNS resolver")
            .with_options(opts)
            .build()
    } else {
        let ips: Vec<IpAddr> = dns_config
            .servers
            .iter()
            .map(|s| s.parse().unwrap()) // validated in config
            .collect();
        let name_servers = NameServerConfigGroup::from_ips_clear(&ips, 53, true);
        use hickory_resolver::name_server::TokioConnectionProvider;
        let config = ResolverConfig::from_parts(None, vec![], name_servers);
        TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build()
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime for DNS");

    let resolver = Arc::new(resolver);
    let rt = Arc::new(rt);

    targets.par_iter_mut().for_each(|target| {
        let ip = IpAddr::V4(target.ip);
        let resolver = Arc::clone(&resolver);
        let rt = Arc::clone(&rt);
        target.hostname = rt.block_on(async move {
            resolver.reverse_lookup(ip).await.ok().and_then(|lookup| {
                lookup.iter().next().map(|name| {
                    name.to_string().trim_end_matches('.').to_string()
                })
            })
        });
    });
}

/// Execute the scan across all targets using a rayon thread pool.
pub fn run_scan(
    targets: Vec<ScanTarget>,
    config: &ScanConfig,
    progress: &Arc<dyn ProgressReporter>,
) -> ScanResult {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.threads)
        .build()
        .expect("Failed to build thread pool");

    let scanned = Arc::new(AtomicUsize::new(0));
    let reachable: Arc<Mutex<Vec<ScanTarget>>> = Arc::new(Mutex::new(Vec::new()));
    let rate_limiter = RateLimiter::new(config.rate_limit).map(Arc::new);
    let timeout = Duration::from_millis(config.timeout_ms);
    let method = config.method.clone();
    let tcp_port = config.tcp_port;

    let start = Instant::now();

    pool.install(|| {
        let scanned = &scanned;
        let reachable = &reachable;
        let rate_limiter = &rate_limiter;
        let progress = progress;

        targets.par_iter().for_each(|target| {
            if let Some(ref limiter) = rate_limiter {
                limiter.acquire();
            }

            let is_up = probe_host(target.ip, &method, timeout, tcp_port);

            if is_up {
                reachable.lock().push(target.clone());
                progress.record_hit(target.subnet_index);
            }

            let count = scanned.fetch_add(1, Ordering::Relaxed) + 1;
            progress.update(target.subnet_index, count);
        });
    });

    let duration = start.elapsed();
    let reachable = match Arc::try_unwrap(reachable) {
        Ok(mutex) => mutex.into_inner(),
        Err(arc) => arc.lock().clone(),
    };

    ScanResult {
        reachable,
        total_scanned: scanned.load(Ordering::Relaxed),
        duration,
    }
}
