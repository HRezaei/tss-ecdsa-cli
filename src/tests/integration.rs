use std::{fs, process::Command, thread, time::Duration};
use std::collections::HashMap;
use std::fs::File;
use std::net::TcpStream;
use std::process::{Child, Stdio};
use std::sync::mpsc;
use rand::distr::Alphanumeric;
use rand::Rng;
use std::option::Option;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::Value;
use crate::common::{sha256_digest, DKGSignScheme, TSS_CLI_POLL_TIMEOUT_VAR};
use crate::tests::{ecdsa, get_cli_executable_path, get_next_manager_port, kill_manager, parse_sign_output, vector_all_the_same, TestResourcesCleanUp};
use crate::tests::eddsa;

const MANAGER_ADDRESS: &str = "127.0.0.1";
pub(crate) const MANAGER_PORT: u16 = 8000;


fn _prepare_manager_no_retry(manager_addr: &str, manager_port: u16) -> (Child, String) {
    let manager_url = format!("http://{}:{}", manager_addr, manager_port);

    // Start the manager
    let manager = Command::new(get_cli_executable_path())
        .arg("manager")
        .env("ROCKET_ADDRESS", manager_addr)
        .env("ROCKET_PORT", manager_port.to_string())
        .spawn()
        .expect("Failed to start manager");

    // Give manager time to start
    thread::sleep(Duration::from_secs(1));

    (manager, manager_url)
}

/// Attempts to start the manager, retrying with incremented ports if the initial port is in use.
fn prepare_manager(manager_addr: &str) -> (Child, String, PathBuf) {
    const MAX_ATTEMPTS: u16 = 100;
    let mut last_tried_port = 0;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("Time went backwards").as_secs().to_string();

    for _ in 0..MAX_ATTEMPTS {
        let port = get_next_manager_port();
        last_tried_port = port;
        let manager_url = format!("http://{}:{}", manager_addr, port);

        // Check if the port is already in use
        if TcpStream::connect((manager_addr, port as u16)).is_ok() {
            eprintln!("Port {} is already in use, trying next...", port);
            continue;
        }

        // 1. Build the output directory path
        let mut output_dir = PathBuf::from("/tmp");
        output_dir.push(manager_addr.to_string() + timestamp.clone().as_str());
        output_dir.push(port.to_string());

        // 2. Create the directory if it doesn't exist
        fs::create_dir_all(&output_dir).unwrap();

        // 3. Create the output file
        let output_file_path = output_dir.join("output.log");
        let output_file = File::create(&output_file_path).unwrap();
        let error_file_path = output_dir.join("error.log");
        let error_file = File::create(&error_file_path).unwrap();
        // Attempt to spawn the manager process
        match Command::new(get_cli_executable_path())
            .arg("manager")
            .env("ROCKET_ADDRESS", manager_addr)
            .env("ROCKET_PORT", port.to_string())
            .stdout(Stdio::from(output_file))
            .stderr(Stdio::from(error_file))
            .spawn()
        {
            Ok(manager) => {
                thread::sleep(Duration::from_secs(3)); // Allow time to start
                return (manager, manager_url, output_dir);
            }
            Err(e) => {
                eprintln!("Failed to start manager on port {}: {}", port, e);
                continue;
            }
        }
    }

    panic!(
        "Unable to start manager after {} attempts (last tried port:{})",
        MAX_ATTEMPTS,
        last_tried_port,
    );
}


pub(crate) fn prepare_manager_and_keys(threshold: i32, n_parties: i32, algorithm: DKGSignScheme)
                                       -> Option<(Child, Vec<String>, String)> {
    // Generate a random 8-character alphanumeric string
    let random_str: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(4)
        .map(char::from)
        .collect();

    let curve_prefix = match algorithm {
        DKGSignScheme::ECDSA => "ecdsa",
        DKGSignScheme::EdDSA => "eddsa"
    };
    let key_name = curve_prefix.to_string() + "-key-" + &random_str;
    let keyfile_prefix = "/tmp/".to_string() + key_name.clone().as_str() + "-";
    let keyfile_extension = ".json";
    let mut keyfiles = Vec::new();

    // Start the manager
    let (manager, manager_url, manager_output_dir) = prepare_manager(MANAGER_ADDRESS);

    let params = format!("{}/{}", threshold, n_parties);

    let mut handles = vec![];

    for i in 1..=n_parties {
        let manager_url = manager_url.clone();
        let params = params.clone();
        let keyfile = format!("{}{}{}", keyfile_prefix, i, keyfile_extension);
        keyfiles.push(keyfile.clone());

        let output_file_path = manager_output_dir.join(key_name.clone() + i.to_string().as_str() + "_keygen_output.log");
        let output_file = File::create(&output_file_path).unwrap();
        let error_file_path = manager_output_dir.join(key_name.clone() + i.to_string().as_str() + "_keygen_error.log");
        let error_file = File::create(&error_file_path).unwrap();

        let handle = thread::spawn(move || {
            let status = Command::new(get_cli_executable_path())
                .arg("keygen")
                .arg(&keyfile)
                .arg(&params)
                .arg("-a")
                .arg(&manager_url)
                .arg("-l")
                .arg(curve_prefix)
                .env(TSS_CLI_POLL_TIMEOUT_VAR, "100")
                .stdout(Stdio::from(output_file))
                .stderr(Stdio::from(error_file))
                .status()
                .expect("Failed to run keygen");

            assert!(status.success(), "Keygen for party {} failed. Manager: {}, Keyfile: {}",
                    i, manager_url, keyfile);
        });

        handles.push(handle);
        thread::sleep(Duration::from_millis(10)); // avoid race
    }
    // Wait for all threads
    for handle in handles {
        match handle.join() {
            Ok(_) => { /* continue */ }
            Err(_) => {
                eprintln!("Thread panicked. Manager: {}", manager_url);
                kill_manager(manager);
                return None;
            }
        }
    }

    Some((manager, keyfiles, manager_url))
}

fn run_pubkey_command(keyfile: &str, args: Vec<&str>) -> Result<HashMap<String, String>, String> {
    let output = Command::new(get_cli_executable_path())
        .arg("pubkey")
        .arg(keyfile)
        .args(args)
        .output()
        .expect("Failed to execute command");

    // Check if the command was successful
    if output.status.success() {
        // Parse stdout as a string
        let stdout = str::from_utf8(&output.stdout)
            .expect("Output was not valid UTF-8");

        // Try parsing it as JSON
        match serde_json::from_str::<Value>(stdout) {
            Ok(json) => {
                let required_keys = ["x", "y", "chain_code", "path"];
                let map_opt = json.as_object().map(|obj| {
                    required_keys.iter()
                        .filter_map(|&key| obj.get(key).map(|v| (key.to_string(), v.to_string())))
                        .collect::<HashMap<String, String>>()
                }).unwrap();
                //println!("Output of pubkey command on {}:\n{}", keyfile, serde_json::to_string_pretty(&json).unwrap());
                Ok(map_opt)
            }
            Err(e) => {
                eprintln!("Failed to parse output of pubkey command: {}", e);
                println!("Raw output:\n{}", stdout);
                Err(e.to_string())
            }
        }
    } else {
        let stderr = str::from_utf8(&output.stderr)
            .unwrap_or("Could not decode output of pubkey command");
        eprintln!("Command failed:\n{}", stderr);
        Err(stderr.to_string())
    }
}

pub fn check_keygen_t_of_n(threshold: i32, n_parties: i32, algorithm: DKGSignScheme) {

    if let Some((mut manager, keyfiles, _manager_url)) =
        prepare_manager_and_keys(threshold, n_parties, algorithm.clone()) {
        let _ = manager.kill();
        let _ = manager.wait();

        let algorithm_arg = match algorithm {
            DKGSignScheme::ECDSA => {"-lecdsa"}
            DKGSignScheme::EdDSA => {"-leddsa"}
        };
        let arguments = vec!["-p0/1/2", "-hlegacy", algorithm_arg];
        let mut maps: Vec<HashMap<String, String>> = vec![];
        for i in keyfiles.iter() {
            let output = run_pubkey_command(i, arguments.clone());
            assert!(output.is_ok());
            maps.push(output.unwrap());
        }

        let _cleanup = TestResourcesCleanUp {
            keyfiles,
            manager: None,
        };

        assert!(vector_all_the_same(&maps));
    }
    else {
        assert!(false, "Failed to prepare manager and key files.")
    };
}

pub fn check_sign_t_of_n_generate(threshold: i32, n_parties: i32, algorithm: DKGSignScheme) {
    match prepare_manager_and_keys(threshold, n_parties, algorithm.clone()) {
        Some((manager, keyfiles, manager_url)) => {
            let _cleanup = TestResourcesCleanUp {
                keyfiles: keyfiles.clone(),
                manager: Some((manager, manager_url.clone())),
            };

            check_sign_t_of_n(threshold, n_parties, keyfiles, manager_url, algorithm);
        }
        None => assert!(false, "Failed to prepare manager and key files."),
    }
}


/// Runs N commands in parallel threads, each taking a set of arguments.
/// Returns a Vec of strings collected from stdout.
pub fn run_commands_in_parallel(
    commands_args: Vec<Vec<String>>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::with_capacity(commands_args.len());

    for command_arguments in commands_args.iter() {
        let args = command_arguments.clone(); // makes an owned String
        let tx = tx.clone();
        let handle = thread::spawn(move || {
            let output = Command::new(&get_cli_executable_path())
                .env(TSS_CLI_POLL_TIMEOUT_VAR, "100")
                .args(args.clone())
                .output();

            let result = match output {
                Ok(output) if output.status.success() => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    Ok(stdout.to_string())
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(format!("Command failed for {:?}: {}", args, stderr))
                }
                Err(e) => Err(
                    format!("Failed to execute command {:?} The error was: {}", args, e)),
            };

            tx.send(result).expect("Failed to send result from thread");
        });

        handles.push(handle);
    }

    // Wait for threads to finish
    drop(tx); // Close the sending end so the iterator finishes
    let mut results = Vec::new();

    for received in rx {
        match received {
            Ok(parsed_json) => results.push(parsed_json),
            Err(e) => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))),
        }
    }

    // Ensure all threads have finished
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    Ok(results)
}

fn check_sign_t_of_n(
    threshold: i32,
    n_parties: i32,
    keyfiles: Vec<String>,
    manager_url: String,
    algorithm: DKGSignScheme,
) {
    let message = "hello world";
    let message_hash = sha256_digest(message.as_bytes());
    let curve_prefix = match algorithm {
        DKGSignScheme::ECDSA => "ecdsa",
        DKGSignScheme::EdDSA => "eddsa"
    };

    let setup_str = format!("{}/{}", threshold, n_parties);
    let mut commands: Vec<Vec<String>> = Vec::new();
    for keyfile in keyfiles {
        let arguments: Vec<String> = vec![
            "sign".to_string(),
            keyfile,
            setup_str.clone(),
            message_hash.clone(),
            "-p0/1/2".to_string(),
            "-hlegacy".to_string(),
            "-a".to_string(),
            manager_url.clone(),
            "-l".to_string(),
            curve_prefix.to_string(),
        ];

        commands.push(arguments);
        if commands.len() == (threshold+1) as usize {
            break;
        }
    }
    let mut r_vector: Vec<String> = vec![];
    let mut s_vector: Vec<String> = vec![];
    let outputs = run_commands_in_parallel(commands).unwrap();
    let mut one_output: HashMap<String, String> = HashMap::new();
    for output in outputs.iter() {
        let output = parse_sign_output(output.to_string()).unwrap();
        let r = output.get("r").unwrap();
        r_vector.push(r.to_string());
        s_vector.push(output.get("s").unwrap().to_string());
        one_output = output;
    }

    assert!(vector_all_the_same(&r_vector));
    assert!(vector_all_the_same(&s_vector));

    let r_hex = one_output.get("r").unwrap().to_string();
    let s_hex = one_output.get("s").unwrap().to_string();

    let x_hex = one_output.get("x").unwrap().to_string();
    let y_hex = one_output.get("y").unwrap().to_string();

    match algorithm {
        DKGSignScheme::ECDSA => ecdsa::integration::verify_signature(r_hex, s_hex, message_hash, x_hex, y_hex),
        DKGSignScheme::EdDSA => eddsa::verify_signature(r_hex, s_hex, message_hash, x_hex, y_hex)
    }
}
