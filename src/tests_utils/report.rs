//! This module contains functions for reporting test results to a CSV file.
//!
//! The CSV file is used to track the size of bitcoin scripts.
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref REPORT_FILE: Mutex<File> = Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("target/bitcoin_scripts_performance_report.csv")
            .unwrap()
    );
}

/// Report the size of a bitcoin script to a CSV file.
/// # Arguments
/// * `category` - A descriptive category for the script.
/// * `name` - The name of the script.
/// * `script_size_bytes` - The size of the script in bytes.
pub fn report_bitcoin_script_size(category: &str, name: &str, script_size_bytes: usize) {
    let mut file = REPORT_FILE.lock().unwrap();
    println!("{}.{}() = {} bytes", category, name, script_size_bytes);
    writeln!(file, "{},{},{}", category, name, script_size_bytes).unwrap();
}
