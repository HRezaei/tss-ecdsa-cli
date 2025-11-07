use std::collections::HashMap;
use std::io::Read;
use std::{fs, thread};
use std::time::Duration;
use serde_json::Value;
use crate::run_main;
use gag::BufferRedirect;
use rand::distr::Alphanumeric;
use rand::Rng;
use rocket::futures::executor::block_on;
use crate::common::{sha256_digest, DKGSignScheme, OfflineClient, OFFLINE_MANAGER_ADDRESS};
use crate::common::manager::build_manager;
use crate::protocols::HdImplementation;
use crate::tests::{ecdsa, eddsa, parse_sign_output, random_string, vector_all_the_same, TestResourcesCleanUp, CLI_NAME};


pub async fn init_client() -> &'static OfflineClient {
    crate::common::OFFLINE_CLIENT.get_or_init(|| async {
        let rocket = build_manager().unwrap();
        OfflineClient::tracked(rocket)
            .await
            .expect("valid Rocket client")
    }).await
}

pub(crate) fn prepare_manager_and_keys_offline(threshold: i32, n_parties: i32, algorithm: DKGSignScheme)
                                       -> Option<Vec<String>> {
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

    block_on(init_client());
    //let manager_output_dir = "/tmp/local_offline_manager";
    let params = format!("{}/{}", threshold, n_parties);

    let mut handles = vec![];

    for i in 1..=n_parties {
        let params = params.clone();
        let keyfile = format!("{}{}{}", keyfile_prefix, i, keyfile_extension);
        keyfiles.push(keyfile.clone());

        /*let output_file_path = manager_output_dir.join(key_name.clone() + i.to_string().as_str() + "_keygen_output.log");
        let output_file = File::create(&output_file_path).unwrap();
        let error_file_path = manager_output_dir.join(key_name.clone() + i.to_string().as_str() + "_keygen_error.log");
        let error_file = File::create(&error_file_path).unwrap();
         */

        let handle = thread::Builder::new()
            .name(format!("worker-{}", i))
            .spawn(move || {
                let args = vec![
                    CLI_NAME,
                    "keygen",
                    keyfile.as_str(),
                    params.as_str(),
                    "-l",
                    curve_prefix,
                    "-a",
                    OFFLINE_MANAGER_ADDRESS
                ];
                run_main(args)
            }).unwrap();

        handles.push(handle);
        thread::sleep(Duration::from_secs(10)); // avoid race
    }

    // Wait for all threads
    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("Thread panicked")) // unwrap JoinResult
        .collect();

    let mut all_ok = true;
    for (index, result) in results.iter().enumerate() {
        match result {
            Ok(_) => {}
            Err(error) => {
                eprintln!("Party {} failed with error: {}", index, error);
                all_ok = false;
            }
        }
    }

    all_ok.then(|| keyfiles)
}

pub fn run_pubkey_function(keyfile: &str, args: Vec<&str>) -> Result<HashMap<String, String>, String> {
    let mut args = args.clone();
    args.insert(0, keyfile);
    args.insert(0, "pubkey");
    args.insert(0, CLI_NAME);

    let (printed_stdout, _exit_code) = capture_stdout(|| run_main(args));

    // Try parsing it as JSON
    match serde_json::from_str::<Value>(printed_stdout.as_str()) {
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
            println!("Raw output:\n{}", printed_stdout);
            Err(e.to_string())
        }
    }
}

fn capture_stdout<F, R>(f: F) -> (String, R)
where
    F: FnOnce() -> R,
{
    // Redirect stdout
    let mut buf = BufferRedirect::stdout().unwrap();
    let result = f(); // call the function (can take args)

    // Read captured output
    let mut output = String::new();
    buf.read_to_string(&mut output).unwrap();
    (output, result)
}

pub fn check_sign_t_of_n_offline(
    threshold: i32,
    n_parties: i32,
    keyfiles: Vec<String>,
    algorithm: DKGSignScheme,
    hd_path: String,
    hd_implementation: HdImplementation
) {
    //Add random string to create a separate room in manager, when running test threads in parallel:
    let message = "hello world ".to_string() + random_string(4).as_str();
    let message_hash = sha256_digest(message.as_bytes());
    let curve_prefix = match algorithm {
        DKGSignScheme::ECDSA => "ecdsa",
        DKGSignScheme::EdDSA => "eddsa"
    };
    let hd_implementation = match hd_implementation {
        HdImplementation::Legacy => "legacy",
        HdImplementation::Bip32 => "bip32"
    };
    let setup_str = format!("{}/{}", threshold, n_parties);
    let mut commands: Vec<Vec<String>> = Vec::new();
    let mut output_paths: Vec<String> = Vec::new();
    for keyfile in keyfiles {
        let output_path = format!("{}.sign_output", keyfile);
        let mut arguments: Vec<String> = vec![
            CLI_NAME.to_string(),
            "sign".to_string(),
            keyfile,
            setup_str.clone(),
            message_hash.clone(),
            "-h".to_string(),
            hd_implementation.to_string(),
            "-a".to_string(),
            OFFLINE_MANAGER_ADDRESS.to_string(),
            "-l".to_string(),
            curve_prefix.to_string(),
            "-o".to_string(),
            output_path.clone()
        ];
        if !hd_path.is_empty() {
            arguments.push("-p".to_string());
            arguments.push(hd_path.clone());
        }
        commands.push(arguments);
        output_paths.push(output_path);
        if commands.len() == (threshold+1) as usize {
            break;
        }
    }
    let mut r_vector: Vec<String> = vec![];
    let mut s_vector: Vec<String> = vec![];

    run_main_in_parallel(commands);
    let mut outputs = Vec::new();
    for output_path in output_paths.clone() {
        let data = fs::read_to_string(output_path.clone()).expect(
            format!("Unable to read output file of sign: {}", output_path).as_str(),
        );
        outputs.push(data);
    }
    let _cleanup = TestResourcesCleanUp {
        keyfiles: output_paths,
        manager: None,
    };
    let mut one_output: HashMap<String, String> = HashMap::new();
    for output in outputs.iter().clone() {
        //assert_eq!(*exit_code, 0, "Party {} failed with exit code {}", output, exit_code);

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


pub fn run_main_in_parallel(
    commands_args: Vec<Vec<String>>,
) {
    let mut handles = Vec::new();

    for (index, command_arguments) in commands_args.iter().enumerate() {
        let main_args = command_arguments.clone();
        let handle = thread::Builder::new()
            .name(format!("worker-{}", index))
            .spawn(move || {
                let args = main_args.clone(); // makes an owned String
                run_main(args)
            }).unwrap();

        handles.push(handle);
        thread::sleep(Duration::from_secs(10)); // avoid race
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

pub fn check_keygen_t_of_n_offline(threshold: i32, n_parties: i32, algorithm: DKGSignScheme) {

    if let Some(keyfiles) =
        prepare_manager_and_keys_offline(threshold, n_parties, algorithm.clone()) {

        let algorithm_arg = match algorithm {
            DKGSignScheme::ECDSA => {"-lecdsa"}
            DKGSignScheme::EdDSA => {"-leddsa"}
        };
        let arguments = vec!["-p0/1/2", "-hlegacy", algorithm_arg];
        let mut maps: Vec<HashMap<String, String>> = vec![];
        for i in keyfiles.iter() {
            let output = run_pubkey_function(i, arguments.clone());
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

pub fn check_sign_t_of_n_generate_offline(
    threshold: i32,
    n_parties: i32,
    algorithm: DKGSignScheme,
    hd_path: String,
    hd_implementation: HdImplementation
) {
    match prepare_manager_and_keys_offline(threshold, n_parties, algorithm.clone()) {
        Some( keyfiles) => {
            check_sign_t_of_n_offline(
                threshold,
                n_parties,
                keyfiles.clone(),
                algorithm,
                hd_path.clone(),
                hd_implementation,
            );
            let _cleanup = TestResourcesCleanUp {
                keyfiles: keyfiles.clone(),
                manager: None,
            };
        }
        None => assert!(false, "Failed to prepare manager and key files."),
    }
}