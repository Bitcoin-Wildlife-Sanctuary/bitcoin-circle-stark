//! This module contains functions for reporting test results to a CSV file.
//!
//! The CSV file is used to track the size of bitcoin scripts.
use std::io::{BufRead, Write};
use std::sync::Mutex;
use std::{
    fs::{File, OpenOptions},
    io::BufReader,
};

lazy_static::lazy_static! {
    static ref REPORT_FILE: Mutex<File> = Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("target/bitcoin_scripts_performance_report.csv")
            .unwrap()
    );
}

// This function will run before any tests
#[ctor::ctor]
fn setup() {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("target/bitcoin_scripts_performance_report.csv")
        .unwrap();
    writeln!(file, "category,name,script_size_bytes").unwrap();
}

// Ensure this runs after all tests have completed
#[ctor::dtor]
fn finalize() {
    sort_csv_file("target/bitcoin_scripts_performance_report.csv");
}

/// Report the size of a bitcoin script to a CSV file.
/// # Arguments
/// * `category` - A descriptive category for the script.
/// * `name` - The name of the script.
/// * `script_size_bytes` - The size of the script in bytes.
pub fn report_bitcoin_script_size(category: &str, name: &str, script_size_bytes: usize) {
    let mut file = REPORT_FILE.lock().unwrap();
    println!("{}.{} = {} bytes", category, name, script_size_bytes);
    writeln!(file, "{},{},{}", category, name, script_size_bytes).unwrap();
}

// Function to sort the CSV file by the first column
fn sort_csv_file(file_path: &str) {
    let mut rows: Vec<Vec<String>> = BufReader::new(File::open(file_path).unwrap())
        .lines()
        .skip(1) // Skip the header
        .map(|line| {
            line.unwrap()
                .split(',')
                .map(|s| s.to_string())
                .collect::<Vec<String>>()
        })
        .collect();

    rows.sort_by(|a, b| a[0].cmp(&b[0]));

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(file_path)
        .unwrap();

    writeln!(file, "category,primitive,script_size_bytes").unwrap();
    for row in rows {
        writeln!(file, "{},{},{}", row[0], row[1], row[2]).unwrap();
    }
}
