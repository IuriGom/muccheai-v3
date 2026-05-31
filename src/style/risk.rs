use console::Style;
pub enum ConfirmationType {
    /// No confirmation needed.
    None,
    /// Standard dialog approval.
    Standard,
    /// Re-type summary confirmation.
    RetypeSummary,
    /// Hardware token required.
    HardwareToken,
    /// Multi-device co-sign required.
    MultiDevice,
}

/// Danger-zone ranking using Italian wind and disaster names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// 🟢 Low — Clear skies
    Sereno,
    /// 🟡 Medium — North wind
    Tramontana,
    /// 🟠 High — Hot desert wind
    Scirocco,
    /// 🔴 Critical — Volcanic
    Vesuvio,
    /// ⚫ Emergency — Earthquake
    Terremoto,
}

impl RiskLevel {
    /// Returns the colored badge string with emoji.
    pub fn badge(&self) -> String {
        match self {
            RiskLevel::Sereno => "🟢 SERENO".into(),
            RiskLevel::Tramontana => "🟡 TRAMONTANA".into(),
            RiskLevel::Scirocco => "🟠 SCIROCCO".into(),
            RiskLevel::Vesuvio => "🔴 VESUVIO".into(),
            RiskLevel::Terremoto => "⚫ TERREMOTO".into(),
        }
    }

    /// English display name.
    pub fn english_name(&self) -> &'static str {
        match self {
            RiskLevel::Sereno => "Low Risk",
            RiskLevel::Tramontana => "Medium Risk",
            RiskLevel::Scirocco => "High Risk",
            RiskLevel::Vesuvio => "Critical Risk",
            RiskLevel::Terremoto => "Emergency Risk",
        }
    }

    /// Italian name.
    pub fn italian_name(&self) -> &'static str {
        match self {
            RiskLevel::Sereno => "Sereno",
            RiskLevel::Tramontana => "Tramontana",
            RiskLevel::Scirocco => "Scirocco",
            RiskLevel::Vesuvio => "Vesuvio",
            RiskLevel::Terremoto => "Terremoto",
        }
    }

    /// Human-readable description of the consequences.
    pub fn description(&self) -> &'static str {
        match self {
            RiskLevel::Sereno => "No delay, no confirmation required",
            RiskLevel::Tramontana => "3-second delay + standard dialog",
            RiskLevel::Scirocco => "5-second delay + re-type summary required",
            RiskLevel::Vesuvio => "10-second delay + hardware token required",
            RiskLevel::Terremoto => "Emergency lockdown, multi-device co-sign required",
        }
    }

    /// Approval delay in seconds.
    pub fn delay_seconds(&self) -> u64 {
        match self {
            RiskLevel::Sereno => 0,
            RiskLevel::Tramontana => 3,
            RiskLevel::Scirocco => 5,
            RiskLevel::Vesuvio => 10,
            RiskLevel::Terremoto => 0, // lockdown, not a simple delay
        }
    }

    /// Required confirmation mechanism for this risk level.
    pub fn confirmation_required(&self) -> ConfirmationType {
        match self {
            RiskLevel::Sereno => ConfirmationType::None,
            RiskLevel::Tramontana => ConfirmationType::Standard,
            RiskLevel::Scirocco => ConfirmationType::RetypeSummary,
            RiskLevel::Vesuvio => ConfirmationType::HardwareToken,
            RiskLevel::Terremoto => ConfirmationType::MultiDevice,
        }
    }

    /// `console::Style` associated with this risk level.
    pub fn color(&self) -> Style {
        match self {
            RiskLevel::Sereno => Style::new().green().bold(),
            RiskLevel::Tramontana => Style::new().yellow().bold(),
            RiskLevel::Scirocco => Style::new().color256(214).bold(), // amber
            RiskLevel::Vesuvio => Style::new().red().bold(),
            RiskLevel::Terremoto => Style::new().black().on_red().bold(),
        }
    }

    /// Emoji badge only.
    pub fn emoji(&self) -> &'static str {
        match self {
            RiskLevel::Sereno => "🟢",
            RiskLevel::Tramontana => "🟡",
            RiskLevel::Scirocco => "🟠",
            RiskLevel::Vesuvio => "🔴",
            RiskLevel::Terremoto => "⚫",
        }
    }

    /// Formatted multi-line display.
    pub fn print(&self) {
        let badge = self.color().apply_to(self.badge());
        println!("{} — {}", badge, self.english_name());
        println!("    {}", self.description());
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.english_name())
    }
}

