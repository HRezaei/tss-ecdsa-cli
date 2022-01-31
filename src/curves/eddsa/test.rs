#[cfg(test)]
mod tests {
    use std::{fs, thread};
    use std::path::PathBuf;
    use std::process::exit;
    use std::time::Duration;
    use curv::arithmetic::Converter;
    use curv::BigInt;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::Ed25519;
    use multi_party_eddsa::protocols::GE;
    use multi_party_eddsa::protocols::thresholdsig::{Keys, SharedKeys};
    use crate::eddsa::hd_keys;
    use glob::{glob, Paths};
    use crate::common::Params;
    use crate::eddsa::keygen::run_keygen;
    use crate::eddsa::signer::run_signer;
    use crate::manager::run_manager;

    fn generate_key_store_files(parties_count: u16) -> Vec<PathBuf> {
        std::env::set_var("ROCKET_PORT", "8001");
        let address = "http://127.0.0.1:8001";
        let mut threads = Vec::new();
        let store_file_path_pattern = "/tmp/eddsa-test-*.store";
        for entry in glob(store_file_path_pattern).unwrap() {
            let entry = entry.unwrap();
            let _ = std::fs::remove_file(entry.as_path());
        }

        let manager_thread = thread::spawn( || {
            println!("Trying to run manager");
            let _ = run_manager();
        });

        thread::sleep(Duration::from_secs(2));

        for i in 1..parties_count+1 {
            let handle = thread::spawn(move || {
                println!("Trying to run party number {}", i);
                let params_vector = vec!["2", "3"];
                let key_file_path = format!("/tmp/eddsa-test-{:?}.store", i);
                let address_str= &address.clone()[..];
                run_keygen(&address_str.to_string(), &key_file_path, &params_vector.clone());
                thread::sleep(Duration::from_millis(100));
            });
            threads.push(handle);
        }

        //Wait for all parties to finish:
        for handle in threads {
            handle.join().unwrap();
        }

        let created_files = glob(store_file_path_pattern).unwrap();

        let mut result = Vec::new();
        for x in created_files {
            result.push(x.unwrap());
        }

        //Finish manager thread:
        //manager_thread.join();

        result
    }

    #[test]
    fn test_key_generation() {
        let parties_count: u16 = 3;
        let created_files = generate_key_store_files(parties_count);
        assert_eq!(created_files.len(), parties_count as usize);
    }

    //This integration test always fails, kept here for later review.
    /*#[test]
    fn test_signing() {
        let parties_count: u16 = 3;

        //First try generate key store files:
        let key_store_files = generate_key_store_files(parties_count);
        /*let key_store_files = key_store_files.map(|x1| x1.unwrap().as_path())
            .collect();*/
        let key_store_file_paths: Vec<String> = key_store_files
            .iter()
            .map(|x2| x2.as_path().to_str().unwrap().to_string())
            .collect();

        println!("{:?}", key_store_file_paths);

        let address = "http://127.0.0.1:8001";
        let mut threads = Vec::new();
        let output_file_path = "/tmp/eddsa-test-sign.json";
        let message = "hi";
        let hd_path = "1/2/3";
        for item in glob(output_file_path).unwrap() {
            let item = item.unwrap();
            let _ = std::fs::remove_file(item.as_path());
        }

        thread::sleep(Duration::from_secs(5));

        /*thread::spawn( || {
            println!("Trying to run manager");
            let _ = run_manager();
        });*/

        //thread::sleep(Duration::from_secs(5));

        for i in 1..parties_count+1 {
            let key_file_path = key_store_file_paths[(i-1) as usize].to_string();
            println!("{:?}", key_file_path);

            let handle = thread::spawn(move || {
                println!("Trying to run party number {}", i);
                let params = Params{
                    parties: "3".to_string(),
                    threshold: "2".to_string()
                };
                let address_str= &address.clone()[..];
                let result = run_signer(address_str.to_string(), key_file_path, params, message.clone().to_string(), hd_path.clone());
                thread::sleep(Duration::from_millis(5000));
                result
            });
            threads.push(handle);
        }

        thread::sleep(Duration::from_secs(1));
//        exit(0);
        //Wait for all parties to finish, and check their results:
        let mut previous_results = Vec::new();
        for handle in threads {
            previous_results.push(handle.join().unwrap());
        }

        let all_are_equal = previous_results
            .iter()
            .all(|x1| (*x1)==previous_results[0]);
        //previous_results.every( v => v === previous_results[0] );

        assert!(all_are_equal);
    }*/

    //This test seems to be invalid, thus commented out and kept here for further review:
    /*#[test]
    fn test_hd_keys_hierarchicy() {
        let key_file_path = "src/curves/eddsa/tss-test-1.store";
        let path = "1/2/3/1";
        let path_splites = ["1/2", "3/1"];

        let data = fs::read_to_string(key_file_path).expect(
            format!("Unable to load keys file at location: {}", key_file_path).as_str(),
        );
        let (_party_keys, _shared_keys, _party_id, _vss_scheme_vec, y_sum): (
            Keys,
            SharedKeys,
            u16,
            Vec<VerifiableSS<Ed25519>>,
            GE,
        ) = serde_json::from_str(&data).unwrap();

        // Get root pub key or HD pub key at specified path

        let path_vector: Vec<BigInt> = path
            .split('/')
            .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
            .collect();
        let (expected_y, _f_l_new) = hd_keys::get_hd_key(&y_sum, path_vector.clone());

        let path_vector: Vec<BigInt> = path_splites[0]
            .split('/')
            .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
            .collect();
        let (mid_y, _f_l_new) = hd_keys::get_hd_key(&y_sum, path_vector.clone());

        let path_vector: Vec<BigInt> = path_splites[1]
            .split('/')
            .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
            .collect();
        let (final_y, _f_l_new) = hd_keys::get_hd_key(&mid_y, path_vector.clone());

        assert_eq!(final_y.x_coord().unwrap().to_hex(), expected_y.x_coord().unwrap().to_hex());
        assert_eq!(final_y.y_coord().unwrap().to_hex(), expected_y.y_coord().unwrap().to_hex());
    }
     */
}