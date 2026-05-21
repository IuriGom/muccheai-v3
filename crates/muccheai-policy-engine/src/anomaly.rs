//! Anomaly detection for MuccheAI Policy Engine
//!
//! Statistical process control on capability request rates.
//! Local ML model (tiny, in Policy Engine) for pattern recognition.

use std::collections::HashMap;

use muccheai_types::audit::*;

/// Baseline behavior profile
#[derive(Debug, Clone)]
pub struct BehaviorBaseline {
    /// Normal capability requests per minute
    pub capability_rate: f64,
    /// Standard deviation of rate
    pub capability_rate_stddev: f64,
    /// Normal CPU usage
    pub cpu_usage: f64,
    /// Standard deviation of CPU usage
    pub cpu_usage_stddev: f64,
    /// Normal memory usage
    pub memory_usage: f64,
    /// Standard deviation of memory usage
    pub memory_usage_stddev: f64,
    /// Action type distribution
    pub action_distribution: HashMap<String, f64>,
}

/// Current activity being evaluated
#[derive(Debug, Clone)]
pub struct AgentActivity {
    /// Capability requests per minute
    pub capability_rate: f64,
    /// CPU usage
    pub cpu_usage: f64,
    /// Memory usage
    pub memory_usage: f64,
    /// Recent action sequence
    pub recent_actions: Vec<String>,
}

/// Detected anomaly/incident
#[derive(Debug, Clone)]
pub struct Incident {
    /// Severity
    pub severity: AnomalySeverity,
    /// Description
    pub description: String,
    /// Indicators that triggered this
    pub indicators: Vec<Indicator>,
}

/// Specific anomaly indicator
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Indicator {
    /// Capability request rate spike
    RateSpike,
    /// Impossible action sequence
    SequenceViolation,
    /// Off-hours high-risk action
    OffHoursHighRisk,
    /// Unusual resource access pattern
    UnusualResourceAccess,
    /// CPU usage anomaly
    CpuAnomaly,
    /// Memory usage anomaly
    MemoryAnomaly,
}

/// Anomaly detector
pub struct AnomalyDetector {
    /// Baseline behavior
    baseline: BehaviorBaseline,
    /// Recent activity window
    activity_window: Vec<AgentActivity>,
    /// Known impossible sequences
    impossible_sequences: Vec<Vec<String>>,
}

impl AnomalyDetector {
    /// Create detector with baseline
    pub fn new(baseline: BehaviorBaseline) -> Self {
        Self {
            baseline,
            activity_window: vec![],
            impossible_sequences: vec![
                // Example: delete before read is impossible for most resources
                vec!["filesystem.delete".to_string(), "filesystem.read".to_string()],
            ],
        }
    }

    /// Detect anomaly in current activity.
    /// Two-sided z-score checks flag both spikes and drops (e.g. log suppression).
    /// Collects all indicators instead of returning on the first match.
    pub fn detect(&self, activity: &AgentActivity) -> Option<Incident> {
        let mut indicators = Vec::new();

        let rate_zscore = if self.baseline.capability_rate_stddev > 0.0 {
            (activity.capability_rate - self.baseline.capability_rate)
                / self.baseline.capability_rate_stddev
        } else {
            0.0
        };

        if rate_zscore.abs() > 5.0 {
            indicators.push(Indicator::RateSpike);
        }

        if self.is_impossible_sequence(&activity.recent_actions) {
            indicators.push(Indicator::SequenceViolation);
        }

        let cpu_zscore = if self.baseline.cpu_usage_stddev > 0.0 {
            (activity.cpu_usage - self.baseline.cpu_usage)
                / self.baseline.cpu_usage_stddev
        } else {
            0.0
        };

        if cpu_zscore.abs() > 5.0 {
            indicators.push(Indicator::CpuAnomaly);
        }

        let mem_zscore = if self.baseline.memory_usage_stddev > 0.0 {
            (activity.memory_usage - self.baseline.memory_usage)
                / self.baseline.memory_usage_stddev
        } else {
            0.0
        };

        if mem_zscore.abs() > 5.0 {
            indicators.push(Indicator::MemoryAnomaly);
        }

        if indicators.is_empty() {
            None
        } else {
            let severity = if indicators.contains(&Indicator::RateSpike) || indicators.contains(&Indicator::SequenceViolation) {
                AnomalySeverity::Critical
            } else {
                AnomalySeverity::Medium
            };
            Some(Incident {
                severity,
                description: format!("Anomalies detected: {:?}", indicators),
                indicators,
            })
        }
    }

    /// Check if action sequence contains an impossible pattern
    fn is_impossible_sequence(&self, actions: &[String]) -> bool {
        for impossible in &self.impossible_sequences {
            if actions.windows(impossible.len()).any(|w| w == impossible.as_slice()) {
                return true;
            }
        }
        false
    }

    /// Update baseline with new activity (adaptive, but slow)
    pub fn update_baseline(&mut self, activity: &AgentActivity) {
        self.activity_window.push(activity.clone());
        if self.activity_window.len() > 10080 { // 1 week at 1-min granularity
            self.activity_window.remove(0);
        }

        // Recalculate baseline (simplified)
        if self.activity_window.len() >= 60 {
            let rates: Vec<f64> = self.activity_window.iter().map(|a| a.capability_rate).collect();
            self.baseline.capability_rate = rates.iter().sum::<f64>() / rates.len() as f64;
            
            let variance = rates.iter()
                .map(|r| (r - self.baseline.capability_rate).powi(2))
                .sum::<f64>() / rates.len() as f64;
            self.baseline.capability_rate_stddev = variance.sqrt();

            // Update CPU usage baseline
            let cpus: Vec<f64> = self.activity_window.iter().map(|a| a.cpu_usage).collect();
            self.baseline.cpu_usage = cpus.iter().sum::<f64>() / cpus.len() as f64;
            let cpu_variance = cpus.iter()
                .map(|c| (c - self.baseline.cpu_usage).powi(2))
                .sum::<f64>() / cpus.len() as f64;
            self.baseline.cpu_usage_stddev = cpu_variance.sqrt();

            // Update memory usage baseline
            let mems: Vec<f64> = self.activity_window.iter().map(|a| a.memory_usage).collect();
            self.baseline.memory_usage = mems.iter().sum::<f64>() / mems.len() as f64;
            let mem_variance = mems.iter()
                .map(|m| (m - self.baseline.memory_usage).powi(2))
                .sum::<f64>() / mems.len() as f64;
            self.baseline.memory_usage_stddev = mem_variance.sqrt();

            // Update action distribution
            let mut action_counts: HashMap<String, u64> = HashMap::new();
            for a in &self.activity_window {
                for action in &a.recent_actions {
                    *action_counts.entry(action.clone()).or_insert(0) += 1;
                }
            }
            let total: u64 = action_counts.values().sum();
            if total > 0 {
                self.baseline.action_distribution = action_counts.into_iter()
                    .map(|(k, v)| (k, v as f64 / total as f64))
                    .collect();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> BehaviorBaseline {
        BehaviorBaseline {
            capability_rate: 10.0,
            capability_rate_stddev: 2.0,
            cpu_usage: 0.5,
            cpu_usage_stddev: 0.1,
            memory_usage: 0.3,
            memory_usage_stddev: 0.05,
            action_distribution: HashMap::new(),
        }
    }

    fn activity(rate: f64) -> AgentActivity {
        AgentActivity {
            capability_rate: rate,
            cpu_usage: 0.5,
            memory_usage: 0.3,
            recent_actions: vec![],
        }
    }

    #[test]
    fn test_normal_rate() {
        let detector = AnomalyDetector::new(baseline());
        assert!(detector.detect(&activity(10.0)).is_none());
        assert!(detector.detect(&activity(15.0)).is_none());
    }

    #[test]
    fn test_rate_spike() {
        let detector = AnomalyDetector::new(baseline());
        let incident = detector.detect(&activity(100.0));
        assert!(incident.is_some());
        assert_eq!(incident.unwrap().severity, AnomalySeverity::Critical);
    }

    #[test]
    fn test_impossible_sequence() {
        let detector = AnomalyDetector::new(baseline());
        let activity = AgentActivity {
            capability_rate: 10.0,
            cpu_usage: 0.5,
            memory_usage: 0.3,
            recent_actions: vec![
                "filesystem.delete".to_string(),
                "filesystem.read".to_string(),
            ],
        };
        let incident = detector.detect(&activity);
        assert!(incident.is_some());
    }

    #[test]
    fn test_cpu_anomaly() {
        let detector = AnomalyDetector::new(baseline());
        let activity = AgentActivity {
            capability_rate: 10.0,
            cpu_usage: 1.5, // 10 sigma above baseline (0.5 + 10*0.1)
            memory_usage: 0.3,
            recent_actions: vec![],
        };
        let incident = detector.detect(&activity);
        assert!(incident.is_some());
        assert_eq!(incident.unwrap().indicators, vec![Indicator::CpuAnomaly]);
    }

    #[test]
    fn test_memory_anomaly() {
        let detector = AnomalyDetector::new(baseline());
        let activity = AgentActivity {
            capability_rate: 10.0,
            cpu_usage: 0.5,
            memory_usage: 0.8, // 10 sigma above baseline (0.3 + 10*0.05)
            recent_actions: vec![],
        };
        let incident = detector.detect(&activity);
        assert!(incident.is_some());
        assert_eq!(incident.unwrap().indicators, vec![Indicator::MemoryAnomaly]);
    }
}
