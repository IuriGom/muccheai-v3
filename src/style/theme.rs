use console::Style;
pub enum Theme {
    /// High-contrast cyberpunk theme with spotted ASCII banners.
    Cyber,
    /// Clean, subdued theme for everyday use.
    Minimal,
}

impl Theme {
    /// Prints a themed header.
    ///
    /// *Cyber*: spotted ASCII banner.
    /// *Minimal*: clean single-line header.
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

    /// Prints the MuccheAI cow banner.
    pub fn print_banner(&self) {
        let cow = r#"
         _______________________________
        <  MuccheAI v3.2 — Secure AI   >
         -------------------------------
                \   ^__^
                 \  (oo)\_______
                    (__)\       )\/\
                        ||----w |
                        ||     ||
        "#;
        match self {
            Theme::Cyber => {
                println!("{}", Style::new().color256(51).apply_to(cow));
            }
            Theme::Minimal => {
                println!("{}", cow);
            }
        }
    }

    /// Prints a step header for the setup wizard.
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

    /// Prints a success message with a checkmark.
    pub fn print_success(&self, msg: &str) {
        let check = Style::new().green().bold().apply_to("✓");
        println!("  {} {}", check, msg);
    }

    /// Prints a warning message.
    pub fn print_warning(&self, msg: &str) {
        let warn = Style::new().yellow().bold().apply_to("⚠");
        println!("  {} {}", warn, msg);
    }

    /// Prints an error message.
    pub fn print_error(&self, msg: &str) {
        let err = Style::new().red().bold().apply_to("✗");
        eprintln!("  {} {}", err, msg);
    }

    /// Prints an info message.
    pub fn print_info(&self, msg: &str) {
        let info = Style::new().cyan().apply_to("ℹ");
        println!("  {} {}", info, msg);
    }

    /// Prints a divider line.
    pub fn print_divider(&self) {
        match self {
            Theme::Cyber => println!("\n  {}\n", "━".repeat(54)),
            Theme::Minimal => println!("\n{}\n", "─".repeat(48)),
        }
    }

    /// Returns a themed divider string.
    pub fn divider(&self) -> String {
        match self {
            Theme::Cyber => "━".repeat(54),
            Theme::Minimal => "─".repeat(48),
        }
        .to_string()
    }

    /// Style for successful operations.
    pub fn style_success(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().color256(46).bold(), // #00FF88
            Theme::Minimal => Style::new().green(),
        }
    }

    /// Style for warnings.
    pub fn style_warning(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().color256(214).bold(), // #FFAA00
            Theme::Minimal => Style::new().yellow(),
        }
    }

    /// Style for errors.
    pub fn style_error(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().color256(196).bold(), // #FF2222
            Theme::Minimal => Style::new().red(),
        }
    }

    /// Style for informational messages.
    pub fn style_info(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().color256(51).bold(), // #00D4FF
            Theme::Minimal => Style::new().cyan(),
        }
    }

    /// Primary text style.
    pub fn style_primary(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().white().bold(),
            Theme::Minimal => Style::new().white(),
        }
    }

    /// Secondary (muted) text style.
    pub fn style_secondary(&self) -> Style {
        match self {
            Theme::Cyber => Style::new().color256(245), // #888888
            Theme::Minimal => Style::new().color256(250),
        }
    }
}

impl Default for Theme {
    fn default() -> Self {
        Theme::Minimal
    }
}

