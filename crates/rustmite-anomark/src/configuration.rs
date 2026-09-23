// Example: Configuration File Support
// Makes it easy to manage complex setups

use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnomarkConfig {
    pub training: TrainingConfig,
    pub execution: ExecutionConfig,
    pub placeholders: PlaceholderConfig,
    pub performance: PerformanceConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrainingConfig {
    /// N-gram order (window size)
    pub order: usize,
    /// Apply standard placeholders
    pub apply_placeholders: bool,
    /// Apply filepath placeholders
    pub apply_filepath_placeholders: bool,
    /// Percentage of data to use
    pub data_percentage: Option<f64>,
    /// Number of lines to use
    pub max_lines: Option<usize>,
    /// Randomize data selection
    pub randomize: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExecutionConfig {
    /// Anomaly threshold percentage
    pub threshold_percent: f64,
    /// Number of results to display
    pub display_lines: usize,
    /// Enable colored output
    pub color_output: bool,
    /// Show percentage scores
    pub show_percentage: bool,
    /// Silent mode
    pub silent: bool,
    /// Auto-save results
    pub auto_save: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PlaceholderConfig {
    /// Enable GUID replacement
    pub enable_guid: bool,
    /// Enable SID replacement
    pub enable_sid: bool,
    /// Enable user path replacement
    pub enable_user: bool,
    /// Enable hash replacement
    pub enable_hash: bool,
    /// Custom regex patterns
    pub custom_patterns: Vec<CustomPattern>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomPattern {
    pub name: String,
    pub pattern: String,
    pub replacement: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PerformanceConfig {
    /// Number of threads (0 = auto)
    pub num_threads: usize,
    /// Enable parallel processing
    pub parallel: bool,
    /// Batch size for processing
    pub batch_size: usize,
}

impl Default for AnomarkConfig {
    fn default() -> Self {
        Self {
            training: TrainingConfig {
                order: 4,
                apply_placeholders: true,
                apply_filepath_placeholders: false,
                data_percentage: None,
                max_lines: None,
                randomize: false,
            },
            execution: ExecutionConfig {
                threshold_percent: 95.0,
                display_lines: 50,
                color_output: true,
                show_percentage: true,
                silent: false,
                auto_save: true,
            },
            placeholders: PlaceholderConfig {
                enable_guid: true,
                enable_sid: true,
                enable_user: true,
                enable_hash: true,
                custom_patterns: vec![],
            },
            performance: PerformanceConfig {
                num_threads: 0,  // auto-detect
                parallel: true,
                batch_size: 10000,
            },
        }
    }
}

impl AnomarkConfig {
    /// Load configuration from TOML file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: AnomarkConfig = toml::from_str(&contents)?;
        Ok(config)
    }
    
    /// Save configuration to TOML file
    pub fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let toml = toml::to_string_pretty(self)?;
        fs::write(path, toml)?;
        Ok(())
    }
    
    /// Generate default config file
    pub fn generate_default(path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let config = Self::default();
        config.save_to_file(path)
    }
}

// Example anomark.toml file:
/*
[training]
order = 4
apply_placeholders = true
apply_filepath_placeholders = false
# max_lines = 100000
# data_percentage = 50.0
randomize = false

[execution]
threshold_percent = 95.0
display_lines = 50
color_output = true
show_percentage = true
silent = false
auto_save = true

[placeholders]
enable_guid = true
enable_sid = true
enable_user = true
enable_hash = true

[[placeholders.custom_patterns]]
name = "IP Address"
pattern = "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"
replacement = "<IP>"

[[placeholders.custom_patterns]]
name = "Port Number"
pattern = ":([0-9]{2,5})\\b"
replacement = ":<PORT>"

[[placeholders.custom_patterns]]
name = "Email"
pattern = "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
replacement = "<EMAIL>"

[performance]
num_threads = 0  # 0 = auto-detect
parallel = true
batch_size = 10000
*/

// Usage in CLI:
/*
// train-from-csv with config
cargo run --release --bin train-from-csv -- \
    -d data.csv \
    -c CommandLine \
    --config anomark.toml

// Or generate default config
cargo run --release --bin train-from-csv -- \
    --generate-config anomark.toml
*/

// Add to Cargo.toml:
// [dependencies]
// toml = "0.8"
// serde = { version = "1.0", features = ["derive"] }
