use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ResumeState {
    /// "host:port" strings already confirmed open.
    pub completed: HashSet<String>,
    /// "host:port" pairs already attempted (superset of completed).
    pub scanned: HashSet<String>,
}

impl ResumeState {
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let state: Self = serde_json::from_str(&data)?;
        Ok(state)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    pub fn mark_scanned(&mut self, host: &str, port: u16) {
        self.scanned.insert(format!("{host}:{port}"));
    }

    #[allow(dead_code)]
    pub fn is_scanned(&self, host: &str, port: u16) -> bool {
        self.scanned.contains(&format!("{host}:{port}"))
    }

    pub fn mark_open(&mut self, host: &str, port: u16) {
        let key = format!("{host}:{port}");
        self.scanned.insert(key.clone());
        self.completed.insert(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mark_and_check() {
        let mut state = ResumeState::default();
        assert!(!state.is_scanned("10.0.0.1", 80));
        state.mark_scanned("10.0.0.1", 80);
        assert!(state.is_scanned("10.0.0.1", 80));
        assert!(!state.is_scanned("10.0.0.1", 443));
    }

    #[test]
    fn test_mark_open_also_marks_scanned() {
        let mut state = ResumeState::default();
        state.mark_open("10.0.0.1", 80);
        assert!(state.is_scanned("10.0.0.1", 80));
        assert!(state.completed.contains("10.0.0.1:80"));
    }

    #[test]
    fn test_save_load_roundtrip() {
        let mut state = ResumeState::default();
        state.mark_open("192.168.1.1", 22);
        state.mark_scanned("192.168.1.1", 80);

        let dir = std::env::temp_dir();
        let path = dir.join("resume_test.json");
        state.save(&path).unwrap();

        let loaded = ResumeState::load(&path).unwrap();
        assert!(loaded.completed.contains("192.168.1.1:22"));
        assert!(loaded.is_scanned("192.168.1.1", 80));
        assert!(!loaded.is_scanned("192.168.1.1", 443));

        std::fs::remove_file(&path).ok();
    }
}
