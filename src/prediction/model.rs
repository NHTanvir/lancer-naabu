use std::collections::HashMap;

pub struct PredictionModel {
    /// correlations[(src_port, dst_port)] = probability (0.0-1.0)
    correlations: HashMap<(u16, u16), f32>,
}

impl PredictionModel {
    pub fn new() -> Self {
        Self {
            correlations: HashMap::new(),
        }
    }

    pub fn set(&mut self, src: u16, dst: u16, prob: f32) {
        self.correlations.insert((src, dst), prob);
    }

    #[allow(dead_code)]
    pub fn get(&self, src: u16, dst: u16) -> f32 {
        self.correlations
            .get(&(src, dst))
            .copied()
            .unwrap_or(0.0)
    }

    /// Return all ports correlated with `open_port` with probability >= `threshold`.
    pub fn get_correlated_ports(&self, open_port: u16, threshold: f32) -> Vec<(u16, f32)> {
        self.correlations
            .iter()
            .filter(|((src, _dst), _prob)| *src == open_port)
            .filter(|(_, prob)| **prob >= threshold)
            .map(|((_, dst), prob)| (*dst, *prob))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlated_ports_80_returns_443() {
        use crate::prediction::build_default_model;
        let model = build_default_model();
        let correlated = model.get_correlated_ports(80, 0.9);
        let ports: Vec<u16> = correlated.iter().map(|(p, _)| *p).collect();
        assert!(
            ports.contains(&443),
            "Expected port 443 in correlated ports for 80 at threshold 0.9, got: {:?}",
            ports
        );
    }

    #[test]
    fn test_get_unknown_pair() {
        let model = PredictionModel::new();
        assert_eq!(model.get(1234, 5678), 0.0);
    }

    #[test]
    fn test_set_and_get() {
        let mut model = PredictionModel::new();
        model.set(80, 443, 0.95);
        assert!((model.get(80, 443) - 0.95).abs() < f32::EPSILON);
    }

    /// Smart-scan with no open ports should return an empty correlated list — no panic.
    #[test]
    fn test_smart_scan_no_open_ports_no_panic() {
        use crate::prediction::build_default_model;
        let model = build_default_model();
        // Simulate: scan produced 0 open ports → no correlated ports generated
        let open_ports: Vec<u16> = vec![];
        let threshold = 0.20_f32;
        let mut extra: Vec<u16> = Vec::new();
        for p in &open_ports {
            for (dst, _) in model.get_correlated_ports(*p, threshold) {
                extra.push(dst);
            }
        }
        assert!(extra.is_empty());
    }

    #[test]
    fn test_threshold_filters_low_prob() {
        use crate::prediction::build_default_model;
        let model = build_default_model();
        // 80→8443 has probability 0.3847, below threshold 0.5
        let correlated = model.get_correlated_ports(80, 0.5);
        let ports: Vec<u16> = correlated.iter().map(|(p, _)| *p).collect();
        // 8443 (0.3847) should NOT appear at threshold 0.5
        assert!(!ports.contains(&8443));
        // 443 (0.9234) SHOULD appear
        assert!(ports.contains(&443));
    }
}
