use std::collections::HashMap;
use std::env;
use std::fs;
use std::process;

const FAILED_LOGIN_THRESHOLD: usize = 3;
const SUSPICIOUS_KEYWORDS: [&str; 5] = [
    "../", "union select", "drop table", "/etc/passwd", "<script>",
];
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn from_str(s: &str) -> Option<Level> {
        match s {
            "INFO" => Some(Level::Info),
            "WARN" => Some(Level::Warn),
            "ERROR" => Some(Level::Error),
            _ => None,
        }
    }
}

struct LogEntry {
    date: String,
    time: String,
    level: Level,
    ip: String,
    message: String,
}
// parsing single line
fn parse_line(line: &str) -> Option<LogEntry> {
    let mut parts = line.splitn(5, ' ');
    let date = parts.next()?;
    let time = parts.next()?;
    let level = Level::from_str(parts.next()?)?;
    let ip = parts.next()?;
    let message = parts.next()?;

    Some(LogEntry {
        date: date.to_string(),
        time: time.to_string(),
        level,
        ip: ip.to_string(),
        message: message.to_string(),
    })
}
// whole file
fn parse_all(content: &str) -> (Vec<LogEntry>, usize) {
    let mut entries = Vec::new();
    let mut bad = 0;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match parse_line(line) {
            Some(entry) => entries.push(entry),
            None => bad += 1,
        }
    }
    (entries, bad)
}

fn count_levels(entries: &[LogEntry]) -> (usize, usize, usize) {
    let (mut info, mut warn, mut error) = (0, 0, 0);
    for entry in entries {
        match entry.level {
            Level::Info => info += 1,
            Level::Warn => warn += 1,
            Level::Error => error += 1,
        }
    }
    (info, warn, error)
}

fn count_ips(entries: &[LogEntry]) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    for entry in entries {
        *map.entry(entry.ip.clone()).or_insert(0) += 1;
    }
    map
}

fn find_brute_force(entries: &[LogEntry]) -> Vec<(String, usize)> {
    let mut map: HashMap<String, usize> = HashMap::new();
    for entry in entries {
        if entry.message.to_lowercase().contains("failed login") {
            *map.entry(entry.ip.clone()).or_insert(0) += 1;
        }
    }

    let mut result: Vec<(String, usize)> = map
        .into_iter()
        .filter(|(_, count)| *count >= FAILED_LOGIN_THRESHOLD)
        .collect();
    result.sort_by(|a, b| b.1.cmp(&a.1));
    result
}

fn find_keyword_hits(entries: &[LogEntry]) -> Vec<String> {
    let mut hits = Vec::new();
    for entry in entries {
        let msg = entry.message.to_lowercase();
        for keyword in SUSPICIOUS_KEYWORDS {
            if msg.contains(keyword) {
                hits.push(format!(
                    "{} {} from {} matched '{}'",
                    entry.date, entry.time, entry.ip, keyword
                ));
                break;
            }
        }
    }
    hits
}

fn print_report(
    entries: &[LogEntry],
    bad_lines: usize,
    levels: (usize, usize, usize),
    ip_counts: &HashMap<String, usize>,
    brute: &[(String, usize)],
    hits: &[String],
) {
    let (info, warn, error) = levels;

    println!("\n{BOLD}=== LOG ANALYSIS REPORT ==={RESET}");
    println!("Entries parsed  : {}", entries.len());
    println!("Malformed lines : {}", bad_lines);
    if let (Some(first), Some(last)) = (entries.first(), entries.last()) {
        println!(
            "Time range      : {} {}  ->  {} {}",
            first.date, first.time, last.date, last.time
        );
    }

    println!("\n{BOLD}Log levels{RESET}");
    println!("  {GREEN}INFO {RESET}: {info}");
    println!("  {YELLOW}WARN {RESET}: {warn}");
    println!("  {RED}ERROR{RESET}: {error}");

    println!("\n{BOLD}Top IP addresses{RESET}");
    let mut top: Vec<(&String, &usize)> = ip_counts.iter().collect();
    top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (ip, count) in top.iter().take(5) {
        println!("  {:<18} {}", ip, count);
    }

    println!("\n{BOLD}Suspicious activity{RESET}");
    if brute.is_empty() && hits.is_empty() {
        println!("  {GREEN}Nothing suspicious found.{RESET}");
    }
    for (ip, count) in brute {
        println!("  {RED}[BRUTE FORCE]{RESET} {ip} had {count} failed logins");
    }
    for hit in hits {
        println!("  {RED}[PATTERN]{RESET} {hit}");
    }
    println!();
}

fn get_path() -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: log_analyzer <logfile>");
        process::exit(1);
    }
    args[1].clone()
}

fn read_file(path: &str) -> String {
    match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("Could not read '{}': {}", path, e);
            process::exit(1);
        }
    }
}

fn main() {
    let path = get_path();
    let content = read_file(&path);
    let (entries, bad_lines) = parse_all(&content);

    let levels = count_levels(&entries);
    let ip_counts = count_ips(&entries);
    let brute = find_brute_force(&entries);
    let hits = find_keyword_hits(&entries);

    print_report(&entries, bad_lines, levels, &ip_counts, &brute, &hits);
}