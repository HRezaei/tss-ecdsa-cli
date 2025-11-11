use std::collections::HashMap;
use std::process::Child;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{fs, thread};
use std::path::Path;
use std::time::Duration;
use rand::distr::Alphanumeric;
use rand::Rng;
use serde_json::Value;

mod eddsa;
mod ecdsa;
mod integration;

pub(crate) mod offline_utils;

pub(crate) const CLI_NAME: &str = "tss_cli";

// Rust runs tests in parallel. We want to prevent separate tests from using the same port:
static MANAGER_PORT_COUNTER: AtomicUsize = AtomicUsize::new(integration::MANAGER_PORT as usize);

fn get_next_manager_port() -> usize {
    MANAGER_PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
}

struct TestResourcesCleanUp {
    keyfiles: Vec<String>,
    manager: Option<(Child, String)>
}

impl Drop for TestResourcesCleanUp {
    fn drop(&mut self) {
        println!("Running cleanup code...");
        if self.keyfiles.len() > 0 {
            clean_up_files(self.keyfiles.clone());
        }

        if self.manager.is_some() {
            let (manager, manager_url) = self.manager.take().unwrap();
            println!("Killing manager {} ...", manager_url);
            kill_manager(manager);
        }
    }
}


fn get_cli_executable_path() -> String {
    if cfg!(debug_assertions) {
        "./target/debug/tss_cli".to_string()
    } else {
        "./target/release/tss_cli".to_string()
    }
}

fn vector_all_the_same<E: PartialEq>(vector: &Vec<E>) -> bool {
    vector.iter().all(|x| x == &vector[0])
}

fn kill_manager(mut manager: Child) {
    // Kill manager
    let _ = manager.kill();
    let _ = manager.wait();

    //Wait for killing:
    thread::sleep(Duration::from_secs(2));
}

fn clean_up_files(keyfiles: Vec<String>) {
    // Clean up
    for i in keyfiles.iter() {
        let _ = std::fs::remove_file(i);
    }
}

fn parse_sign_output(response: String) -> Result<HashMap<String, String>, String> {
    let last_line = response.lines().last().unwrap();
    // Try parsing it as JSON
    match serde_json::from_str::<Value>(last_line) {
        Ok(json) => {
            let required_keys = ["x", "y", "msg_int", "r", "s", "status"];
            let map_out = json.as_object().map(|obj| {
                required_keys.iter()
                    //.filter_map(|&key| obj.get(key).map(|v| (key.to_string(), v.to_string())))
                    .filter_map(|&key| {
                        obj.get(key).map(|v| {
                            let val = if let Some(s) = v.as_str() {
                                s.to_string()
                            } else {
                                v.to_string() // fallback to JSON serialization
                            };
                            (key.to_string(), val)
                        })
                    })
                    .collect::<HashMap<String, String>>()
            }).unwrap();
            //println!("Sign Output:\n{}", serde_json::to_string_pretty(&json).unwrap());
            Ok(map_out)
        }
        Err(e) => {
            eprintln!("Failed to parse JSON: {}", e);
            println!("Raw output:\n{}", response);
            Err(e.to_string())
        }
    }
}

fn random_string(length: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Scans the given directory and returns a Vec of absolute paths
/// to files whose names start with prefix
pub fn find_prefixed_files(dir: &str, prefix: &str) -> Result<Vec<String>, String> {
    let dir = Path::new(dir);
    let mut result = Vec::new();

    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        // Ensure it's a file and name starts with "ec-"
        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.starts_with(prefix) {
                    let abs_path = path.canonicalize().map_err(|e| e.to_string())?; // Absolute path as PathBuf
                    if let Some(path_str) = abs_path.to_str() {
                        result.push(path_str.to_string()); // Convert to String
                    }
                }
            }
        }
    }
    Ok(result)
}
