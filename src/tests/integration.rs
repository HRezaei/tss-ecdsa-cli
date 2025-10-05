use std::{process::Command, thread, time::Duration};
use std::collections::HashMap;
use std::net::TcpStream;
use std::process::Child;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use curv::arithmetic::Converter;
use curv::BigInt;
use rand::distr::Alphanumeric;
use rand::Rng;
use serde_json::Value;
use crate::common::{sha256_digest, TSS_CLI_POLL_TIMEOUT_VAR};
use crate::protocols::ecdsa::{sum_of_fragment_files, FE, GE};
use crate::tests::ecdsa::check_sig;

const MANAGER_ADDRESS: &str = "127.0.0.1";
const MANAGER_PORT: u16 = 8000;


// Rust runs tests in parallel. We want to prevent separate tests from using the same port:
static MANAGER_PORT_COUNTER: AtomicUsize = AtomicUsize::new(MANAGER_PORT as usize);

fn get_next_manager_port() -> usize {
    MANAGER_PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
}

fn get_cli_executable_path() -> String {
    if cfg!(debug_assertions) {
        println!("DEBUGDEBUG");
        "./target/debug/tss_cli".to_string()
    } else {
        println!("RELEASERELEASE");
        "./target/release/tss_cli".to_string()
    }
}


#[test]
fn test_keygen_2_of_5() {
    check_keygen_t_of_n(2, 5);
}

#[test]
fn test_keygen_1_of_3() {
    check_keygen_t_of_n(1, 3);
}

#[test]
fn test_sign_1_of_3() {
    check_sign_t_of_n_generate(1, 3);
}

#[test]
fn test_sign_2_of_5() {
    check_sign_t_of_n_generate(2, 5);
}

fn vector_all_the_same<E: PartialEq>(vector: &Vec<E>) -> bool {
    vector.iter().all(|x| x == &vector[0])
}

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
fn prepare_manager(manager_addr: &str) -> (Child, String) {
    const MAX_ATTEMPTS: u16 = 100;
    let mut last_tried_port = 0;
    for _ in 0..MAX_ATTEMPTS {
        let port = get_next_manager_port();
        last_tried_port = port;
        let manager_url = format!("http://{}:{}", manager_addr, port);

        // Check if the port is already in use
        if TcpStream::connect((manager_addr, port as u16)).is_ok() {
            eprintln!("Port {} is already in use, trying next...", port);
            continue;
        }

        // Attempt to spawn the manager process
        match Command::new(get_cli_executable_path())
            .arg("manager")
            .env("ROCKET_ADDRESS", manager_addr)
            .env("ROCKET_PORT", port.to_string())
            .spawn()
        {
            Ok(manager) => {
                thread::sleep(Duration::from_secs(3)); // Allow time to start
                return (manager, manager_url);
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

fn kill_manager(mut manager: Child) {
    // Kill manager
    let _ = manager.kill();
    let _ = manager.wait();

    //Wait for killing:
    thread::sleep(Duration::from_secs(2));
}

fn prepare_manager_and_keys(threshold: i32, n_parties: i32) -> (Child, Vec<String>, String) {
    // Generate a random 8-character alphanumeric string
    let random_str: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(4)
        .map(char::from)
        .collect();

    let keyfile_prefix = "/tmp/ec-key-".to_string() + &random_str + "-";
    let keyfile_extension = ".json";
    let mut keyfiles = Vec::new();

    // Start the manager
    let (manager, manager_url) = prepare_manager(MANAGER_ADDRESS);

    let params = format!("{}/{}", threshold, n_parties);

    let mut handles = vec![];

    for i in 1..=n_parties {
        let manager_url = manager_url.clone();
        let params = params.clone();
        let keyfile = format!("{}{}{}", keyfile_prefix, i, keyfile_extension);
        keyfiles.push(keyfile.clone());
        let handle = thread::spawn(move || {
            let status = Command::new(get_cli_executable_path())
                .arg("keygen")
                .arg(&keyfile)
                .arg(&params)
                .arg("-a")
                .arg(&manager_url)
                .env(TSS_CLI_POLL_TIMEOUT_VAR, "100")
                .status()
                .expect("Failed to run keygen");

            assert!(status.success(), "Keygen for party {} failed", i);
        });

        handles.push(handle);
        thread::sleep(Duration::from_millis(10)); // avoid race
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    (manager, keyfiles, manager_url)
}

fn run_pubkey_command(keyfile: &str, args: Vec<&str>) -> Result<HashMap<String, String>, String> {
    // Run the command
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
                println!("Output of pubkey command on {}:\n{}", keyfile, serde_json::to_string_pretty(&json).unwrap());
                Ok(map_opt)
            }
            Err(e) => {
                eprintln!("Failed to parse output of pubkey command: {}", e);
                println!("Raw output:\n{}", stdout);
                Err(e.to_string())
            }
        }
    } else {
        // Print stderr if the command failed
        let stderr = str::from_utf8(&output.stderr)
            .unwrap_or("Could not decode output of pubkey command");
        eprintln!("Command failed:\n{}", stderr);
        Err(stderr.to_string())
    }
}

fn check_keygen_t_of_n(threshold: i32, n_parties: i32) {

    let (mut manager, keyfiles, _manager_url) =
        prepare_manager_and_keys(threshold, n_parties);

    // Kill manager
    let _ = manager.kill();
    let _ = manager.wait();

    let arguments = vec!["-p0/1/2", "-hlegacy"];
    let mut maps: Vec<HashMap<String, String>> = vec![];
    for i in keyfiles.iter() {
        let output = run_pubkey_command(i, arguments.clone());
        assert!(output.is_ok());
        maps.push(output.unwrap());
    }

    assert!(vector_all_the_same(&maps));

    clean_up_files(keyfiles);
}

fn check_sign_t_of_n_generate(threshold: i32, n_parties: i32) {
    let (manager, keyfiles, manager_url) =
        prepare_manager_and_keys(threshold, n_parties);

    check_sign_t_of_n(threshold, n_parties, keyfiles.clone(), manager_url);

    kill_manager(manager);

    clean_up_files(keyfiles);
}

fn clean_up_files(keyfiles: Vec<String>) {
    // Clean up
    for i in keyfiles.iter() {
        let _ = std::fs::remove_file(i);
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

fn check_sign_t_of_n(threshold: i32, n_parties: i32, keyfiles: Vec<String>, manager_url: String) {
    let message = "hello world";
    let message_hash = sha256_digest(message.as_bytes());

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

    let r_bytes = hex::decode(one_output.get("r").unwrap()).unwrap();
    let r_scalar = FE::from_bytes(r_bytes.as_slice()).unwrap();

    let s_bytes = hex::decode(one_output.get("s").unwrap()).unwrap();
    let s_scalar = FE::from_bytes(s_bytes.as_slice()).unwrap();

    let msg_bigint = BigInt::from_str_radix(message_hash.as_str(), 16).unwrap();

    let x_hex = one_output.get("x").unwrap();
    let y_hex = one_output.get("y").unwrap();
    let x_bigint = BigInt::from_str_radix(x_hex, 16).unwrap();
    let y_bigint = BigInt::from_str_radix(y_hex, 16).unwrap();
    let public_key = GE::from_coords(&x_bigint, &y_bigint).unwrap();

    check_sig(&r_scalar, &s_scalar, &msg_bigint, &public_key);
}

#[test]
fn test_keys_summation() {
    let (manager, keyfiles, _manager_url) =
        prepare_manager_and_keys(1, 3);
    kill_manager(manager);

    match sum_of_fragment_files(keyfiles.clone()) {
        Ok((summation_pub_key, files_pub_key)) => {
            assert_eq!(summation_pub_key, files_pub_key);
        }
        Err(error) => {
            assert!(false, "Error in summing keys: {}", error);
        }
    }

    clean_up_files(keyfiles);
}