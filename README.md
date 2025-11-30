# TSS ECDSA/EdDSA CLI utility

[![Build Status](https://travis-ci.com/cryptochill/tss-ecdsa-cli.svg?branch=master)](https://travis-ci.com/cryptochill/tss-ecdsa-cli)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This project is an example usage of https://github.com/KZen-networks/multi-party-ecdsa library which is a Rust implementation of {t,n}-threshold ECDSA. 

Includes support for HD keys ([BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)). HD support based on https://github.com/trepca/multi-party-ecdsa/tree/hd-support.

This branch also includes EdDSA based on https://github.com/ZenGo-X/multi-party-eddsa with an experimental support of HD keys.
## Setup

1.  Install [Rust](https://rustup.rs/) nightly ([Rocket](https://rocket.rs/v0.4/guide/getting-started/) requires the latest version of Rust nightly).

    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    rustup default nightly
    ``` 

2. Clone & build.

    ```sh
    git clone git@github.com:HRezaei/tss-ecdsa-cli.git 
    cd tss-ecdsa-cli
    git checkout feature/chain-code-arg 
    cargo build --release
    ```

## Configuration

Here is a list of environment variables used to configure the tool:

| Name                            | Default    | Description                                                                                                                                                                                                        | 
|---------------------------------|------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| TSS_LOG_LEVEL                   | production | If set to debug, some logged messages and errors will be more informative                                                                                                                                          |
| TSS_CLI_POLL_TIMEOUT            | 30         | The number of seconds to retry receiving messages from other parties.                                                                                                                                              |
| TSS_CLI_SIGNUP_TIMEOUT          | 30         | The number of seconds to wait for all other parties to join the room.                                                                                                                                              |
| TSS_CLI_MANAGER_TTL             | 300        | The number of seconds to keep data of a room. After this time, the room won't be available anymore.                                                                                                                |
| TSS_MANAGER_MAX_PARTIES         | 10         | The maximum allowed value for the "n" parameter in "t of n TSS"                                                                                                                                                    |
| TSS_MANAGER_HTTP_AUTH_KEY_PAIRS | NA         | A string like user1name=user1password,user2name=user2password                                                                                                                                                      |
| TSS_MANAGER_SIGNUP_TIMEOUT      | 2          | The number of seconds manager allows each party to remain offline. If after of this number of seconds no request is received from a party, the manager considers that party as dead/crashed.                       |
| TSS_HTTP_AUTH_JWT_TTL           | 10         | The number of seconds the http JWT tokens will remain valid.                                                                                                                                                       |
| TSS_PARTY_JWT_APIKEY            | NA         | The API key (username) of each individual party which must be set in the environment specific to that party. It also needs to be included in the value for TSS_MANAGER_HTTP_AUTH_KEY_PAIRS on the manager machine. |
| TSS_PARTY_JWT_SECRET            | NA         | The password for signing JWT tokens. Must be specific for each party. It also needs to be included in the value for TSS_MANAGER_HTTP_AUTH_KEY_PAIRS on the manager machine.                                        |
| ROCKET_ADDRESS                  | 127.0.0.1  | The IP on which Manager is going to be accessible.                                                                                                                                                                 |
| ROCKET_PORT                     | 8000       | The port on which Manager is going to be accessible.                                                                                                                                                               |



## Keygen

1. Run state manager which is managing the communication between parties:

    ```sh 
    ./target/release/tss_cli manager
    ```
   
    To run on different host/port adjust Rocket.toml or override using [env vars](https://api.rocket.rs/v0.4/rocket/config/index.html#environment-variables). 
    ```sh
    ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8008 ./target/release/tss_cli manager
    ```

   2. Run keygen:

       ```sh
       USAGE:
           tss_cli keygen [OPTIONS] <keysfile> <params>

       OPTIONS:
           -a, --addr <manager_addr>    URL to manager. E.g. http://127.0.0.2:8002
           -l, --alg <algorithm>        Either ecdsa (default) or eddsa
           -r, --room_id <room_id>      Optional unique string to avoid interference between two or more groups of 
                                        parties doing keygen concurrently.

      ARGS:
        <keysfile>    Target keys file
        <params>      Threshold params: threshold/parties (t+1/n). E.g. 1/3 for 2 of 3 schema. The parameter n must not
                      be greater than the value set for env var TSS_MANAGER_MAX_PARTIES (default: 10). Also, t must be
                      greater than 0 and less than or equal to n, i.e. 0 < t < n <= TSS_MANAGER_MAX_PARTIES.  

   
    # Run keygen for each party
    t=1 && n=3; for i in $(seq 1 $n)
    do
        echo "key gen for client $i out of $n"
        ./target/release/tss_cli keygen keys$i.store $t/$n &
        sleep 2
    done
    ```

## Get derived public key for path

Output will return X and Y coordinates of a public key at specified path.

```sh
USAGE:
    tss_cli pubkey [OPTIONS] <keysfile>

OPTIONS:
    -p, --path <path>    Derivation path
    -l, --alg <algorithm>    Either ecdsa (default) or eddsa
    -c, --cc <chain_code>    Hex representation of chain_code
    -h, --hd <hd_implementation> Either legacy (default) or bip32 which uses crates for HD (Hierarchical Deterministic) key derivation
ARGS:
    <keysfile>    Keys file

./target/release/tss_cli pubkey keys1.store
# Output: {"path":"","x":"20d6d63f5baa237c747c33dd85170e186d31fa2948b3bb4615e7d08045f05614","y":"6b4ae2e5a65f750f911e92f365f8f4733949f4681efb9ebfa8d9d8fec258e96"}

./target/release/tss_cli pubkey keys1.store -p 0/1/2
# Output: {"path":"0/1/2","x":"973dba2e6c622d0d62626b5cc20e9561dd6123afca96d7b811f637900e68d99e","y":"7c1b2d91cdbfd6e9ceab48dc94aedfd021e314f4d90d18cbb8a4b40d543f85cd"}
```

## Sign message

Run state manager and run as many signer parties as you configured when used keygen.

```sh
USAGE:
    tss_cli sign [OPTIONS] <keysfile> <params> <message>

OPTIONS:
    -a, --addr <manager_addr>    URL to manager
    -p, --path <path>            Derivation path
    -l, --alg <algorithm>        Either ecdsa (default) or eddsa
    -c, --cc <chain_code>        Hex representation of chain_code
    -h, --hd <hd_implementation> Either legacy (default) or bip32 which uses crates for HD (Hierarchical Deterministic) key derivation
ARGS:
    <keysfile>    Keys file
    <params>      Threshold params: threshold/parties (t+1/n). E.g. 1/3 for 2 of 3 schema. The parameter n must not be
                  greater than the value set for env var TSS_MANAGER_MAX_PARTIES (default: 10). Also, t must be
                  greater than 0 and less than or equal to n, i.e. 0 < t < n <= TSS_MANAGER_MAX_PARTIES.  

    <message>     Message to sign in hex format. It has to be at least 32 chars long.


./target/release/tss_cli sign keys1.store -p 0/1/2 -a http://127.0.0.1:8001 1/2 SignMe
./target/release/tss_cli sign keys2.store -p 0/1/2 -a http://127.0.0.1:8001 1/2 SignMe

# If all is correct, last line of the output should be json string, something like this:
{ 
   "status":"signature_ready",
   "r":"20863a51eb7b0e0fb95480ca7c11edef79bd08e40199f91821df02982f8e5af1",
   "s":"ba8f2b6eff824796bf1812667642d9d65ec6d8dead09b7c2c157a6317947249",
   "recid":0,
   "x":"973dba2e6c622d0d62626b5cc20e9561dd6123afca96d7b811f637900e68d99e",
   "y":"7c1b2d91cdbfd6e9ceab48dc94aedfd021e314f4d90d18cbb8a4b40d543f85cd"
}
```

## Keyfile Safety Check
Checks a given key file against small prime factors to make sure it's not vulnerable to Paillier Key Vulnerability 
[CVE-2023-33241]. See [here](https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report) 
for more details. This check is designed only for ECDSA key files.

```shell
USAGE:
    tss_cli safety_check [OPTIONS] <input_file>

OPTIONS:
    --max_first <max_first>    Maximum number of first small primes to check against. Default: 33554432 (2^25)
ARGS:
    <input_file>    Keys file. It only accepts ECDSA keys.
    

./target/release/tss_cli safety_check keys1.store 
# Output: 
# max_first primes is set to: 33554432
# Checking paillier_key_vector[..].n
# Key file check successful!


./target/release/tss_cli safety_check keys1.store 121270018
# Output:
# max_first primes is set to: 121270018
# Checking paillier_key_vector[..].n
# Key file check successful!

```

## Running Automated Tests
There are two types of tests:
* Integration tests that run manager and parties each in a separate process and check their
outputs. To run them, use the command below:
```shell
cargo test integration
```
*  Tests that run manager and parties all within the same process but using separate threads,
To run them, here's the command:
```shell
cargo test unit
```

### Checking Test Coverage
Using the command below, you can run the tests and check what proportion of codes are covered by tests:
```shell
cargo +nightly llvm-cov test --open --ignore-run-fail --bin tss_cli  --branch
```
The above runs all tests concurrently which is faster but may cause some of the tests to interfere in manager and fail.
But if you add the option `-- --test-threads=1` to the above command, it will run tests one by one, thus all should pass.
In general, even concurrent tests must pass, the work is in progress in this regard.