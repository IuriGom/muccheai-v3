use console::Style;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::AtomicBool;

pub static JSON_MODE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Cyber,
    Minimal,
}

impl Theme {
    pub fn print_header(&self, text: &str) {
        match self {
            Theme::Cyber => {
                let line = "━".repeat(text.len() + 8);
                println!("\n  {}  ", line);
                println!("  ┃  {}  ┃", Style::new().white().bold().apply_to(text));
                println!("  {}  \n", line);
            }
            Theme::Minimal => {
                println!("\n── {} ──\n", text);
            }
        }
    }

    pub fn print_banner(&self) {
        let banner = "MuccheAI v3";
        match self {
            Theme::Cyber => println!("{}", Style::new().color256(51).bold().apply_to(banner)),
            Theme::Minimal => println!("{}", banner),
        }
    }

    pub fn print_step(&self, step: usize, total: usize, title: &str) {
        let step_str = format!("Step {}/{}", step, total);
        match self {
            Theme::Cyber => {
                let step_style = Style::new().color256(51).bold();
                let title_style = Style::new().white().bold();
                println!(
                    "\n  {}  {}  {}",
                    step_style.apply_to("▶"),
                    step_style.apply_to(step_str),
                    title_style.apply_to(title)
                );
                println!("  {}", "─".repeat(50));
            }
            Theme::Minimal => {
                println!("\n[{}] {}", step_str, title);
                println!("{}", "─".repeat(40));
            }
        }
    }

    pub fn print_success(&self, msg: &str) {
        let check = Style::new().green().bold().apply_to("✓");
        println!("  {} {}", check, msg);
    }

    pub fn print_warning(&self, msg: &str) {
        let warn = Style::new().yellow().bold().apply_to("⚠");
        println!("  {} {}", warn, msg);
    }

    pub fn print_error(&self, msg: &str) {
        let err = Style::new().red().bold().apply_to("✗");
        eprintln!("  {} {}", err, msg);
    }

    pub fn print_info(&self, msg: &str) {
        let info = Style::new().cyan().apply_to("ℹ");
        println!("  {} {}", info, msg);
    }

    pub fn print_divider(&self) {
        match self {
            Theme::Cyber => println!("\n  {}\n", "━".repeat(54)),
            Theme::Minimal => println!("\n{}\n", "─".repeat(48)),
        }
    }

    pub fn divider(&self) -> String {
        match self {
            Theme::Cyber => "━".repeat(54),
            Theme::Minimal => "─".repeat(48),
        }
        .to_string()
    }

    pub fn style_success(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().color256(46).bold(),
            Theme::Minimal => Style::new().green(),
        }
    }

    pub fn style_warning(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().color256(214).bold(),
            Theme::Minimal => Style::new().yellow(),
        }
    }

    pub fn style_error(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().color256(196).bold(),
            Theme::Minimal => Style::new().red(),
        }
    }

    pub fn style_info(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().color256(51).bold(),
            Theme::Minimal => Style::new().cyan(),
        }
    }

    pub fn style_primary(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().white().bold(),
            Theme::Minimal => Style::new().white(),
        }
    }

    pub fn style_secondary(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().color256(245),
            Theme::Minimal => Style::new().color256(250),
        }
    }
}

impl Default for Theme {
    fn default() -> Self {
        Theme::Minimal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationType {
    None,
    Standard,
    RetypeSummary,
    HardwareToken,
    MultiDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
    Emergency,
}

impl RiskLevel {
    pub fn badge(&self) -> String {
        match self {
            RiskLevel::Low => "LOW".into(),
            RiskLevel::Medium => "MED".into(),
            RiskLevel::High => "HIGH".into(),
            RiskLevel::Critical => "CRIT".into(),
            RiskLevel::Emergency => "EMRG".into(),
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            RiskLevel::Low => "No delay, no confirmation required",
            RiskLevel::Medium => "3-second delay + standard dialog",
            RiskLevel::High => "5-second delay + re-type summary required",
            RiskLevel::Critical => "10-second delay + hardware token required",
            RiskLevel::Emergency => "Emergency lockdown, multi-device co-sign required",
        }
    }

    pub fn delay_seconds(&self) -> u64 {
        match self {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 3,
            RiskLevel::High => 5,
            RiskLevel::Critical => 10,
            RiskLevel::Emergency => 0,
        }
    }

    pub fn confirmation_required(&self) -> ConfirmationType {
        match self {
            RiskLevel::Low => ConfirmationType::None,
            RiskLevel::Medium => ConfirmationType::Standard,
            RiskLevel::High => ConfirmationType::RetypeSummary,
            RiskLevel::Critical => ConfirmationType::HardwareToken,
            RiskLevel::Emergency => ConfirmationType::MultiDevice,
        }
    }

    pub fn color(&self) -> Style {
        match self {
            RiskLevel::Low => Style::new().green().bold(),
            RiskLevel::Medium => Style::new().yellow().bold(),
            RiskLevel::High => Style::new().color256(214).bold(),
            RiskLevel::Critical => Style::new().red().bold(),
            RiskLevel::Emergency => Style::new().black().on_red().bold(),
        }
    }

    pub fn print(&self) {
        let badge = self.color().apply_to(self.badge());
        println!("{} — {}", badge, self.description());
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.badge())
    }
}

pub fn progress_bar(len: u64) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.cyan} {msg} [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
            .progress_chars("##-"),
    );
    pb
}

pub fn start_thinking_spinner() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    thread::spawn(move || {
        let words = ["Working", "Processing", "Thinking"];
        let mut idx = 0;
        while running_clone.load(Ordering::SeqCst) {
            eprint!("\r{}... ", words[idx % words.len()]);
            idx += 1;
            thread::sleep(Duration::from_millis(800));
        }
        eprint!("\r{: <60}\r", "");
    });

    running
}
