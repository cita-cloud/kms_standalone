# KMS standalone

The KMS service for CITA-Cloud. It can be used as a standalone sevice.

It currently only supports 国密(Chinese Cryptographic Standards) and MySQL database for encrypted accounts.

WARNING:
Private keys are cached unencrypted in memory, and it's not zeroized during construction and after drop.

The former is for performance, the later needs to patch the crypto library.

Secret memory are zeroized otherwise possible.

## Usage

```
$ kms run --help

kms-run

run kms service

USAGE:
    kms run [FLAGS] [OPTIONS] [config]

ARGS:
    <config>    the kms config [default: config.toml]

FLAGS:
    -h, --help       Print help information
        --stdout     if specified, log to stdout
    -V, --version    Print version information

OPTIONS:
    -d, --log-dir <log-dir>                the log dir
    -f, --log-file-name <log-file-name>    the log file name
```

Here's an example config. MySQL must be available and the database exists.

```toml
[kms_standalone]
grpc_listen_port = 50005

# File path to corresponding config.
# It's pretty awkward to do config this way.
# And it'll be much better if we can just:
# db_url = "mysql://user:password@host:port/db"
# master_password = "master password"
db_url_path = "/path/to/db_url" # mysql://host:port/db
db_user_path = "/path/to/db_user" # user
db_password_path = "/path/to/db_password" # password
master_password_path = "/path/to/master_password" # master password

# Optional and default to
db_conn_timeout_millis = 10000  # 10 seconds
db_conn_idle_timeout_millis = 20000 # 20 seconds
db_max_connections = 1024
max_cached_accounts = 1024
```

It provides service via gRPC.

Please refer to [cita_cloud_proto](https://github.com/cita-cloud/cita_cloud_proto/blob/v6.2.0/protos/kms.proto).


```protobuf
service KmsService {
    // Get crypto info
    rpc GetCryptoInfo(common.Empty) returns (GetCryptoInfoResponse);

    // Generate a KeyPair
    rpc GenerateKeyPair(GenerateKeyPairRequest) returns (GenerateKeyPairResponse);

    // Hash data
    rpc HashData(HashDataRequest) returns (HashDataResponse);

    // Verify hash of data
    rpc VerifyDataHash(VerifyDataHashRequest) returns (common.SimpleResponse);

    // Sign a message
    rpc SignMessage(SignMessageRequest) returns (SignMessageResponse);

    // Recover signature
    rpc RecoverSignature(RecoverSignatureRequest) returns (RecoverSignatureResponse);
}
```

## Benchmark
Note that it's a poor benchmark with many disturbing factors.

CPU: amd r7 3800x 8 cores

```sh
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

```
$ ./ghz --proto ./proto/kms.proto --call kms.KmsService/SignMessage -d '{ "keyId": "0", "msg": "zF1F5xUhveGShe28Q+Dc/D5R2B3xQBXCWwj+asMLg70="}' --insecure -c 128 -n 1000000 127.0.0.1:50005

Summary:
  Count:        1000000
  Total:        39.58 s
  Slowest:      23.17 ms
  Fastest:      0.18 ms
  Average:      3.07 ms
  Requests/sec: 25262.68

Response time histogram:
  0.176  [1]      |
  2.476  [374945] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  4.775  [511343] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  7.075  [99884]  |∎∎∎∎∎∎∎∎
  9.374  [12644]  |∎
  11.674 [1003]   |
  13.973 [131]    |
  16.273 [30]     |
  18.572 [12]     |
  20.872 [6]      |
  23.171 [1]      |

Latency distribution:
  10 % in 1.45 ms
  25 % in 2.07 ms
  50 % in 2.86 ms
  75 % in 3.81 ms
  90 % in 4.93 ms
  95 % in 5.71 ms
  99 % in 7.39 ms

Status code distribution:
  [OK]   1000000 responses
```

```
$ ./ghz --proto ./proto/kms.proto --call kms.KmsService/RecoverSignature -d '{ "msg": "zF1F5xUhveGShe28Q+Dc/D5R2B3xQBXCWwj+asMLg70=", "signature": "m0mAIri0Bpkk86SS8orFMKsSH+ghYxhCbVMGpZBR+Pj1jwhGDGVxVJHrBAX1JRJAzNbkP/HcpsKzkLVfahYj18p6ZcQQbvUauA1hZUfqmKKsHMJiVeM8wnQT6mtSieaPKN07xOavLwpChbLNbXm/BCKG7nNBlzSZbg945Q719cA="}' --insecure -c 128 -n 1000000 127.0.0.1:50005

Summary:
  Count:        1000000
  Total:        58.13 s
  Slowest:      26.33 ms
  Fastest:      0.37 ms
  Average:      5.08 ms
  Requests/sec: 17201.55

Response time histogram:
  0.370  [1]      |
  2.966  [170929] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  5.563  [440181] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  8.159  [309165] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  10.755 [68552]  |∎∎∎∎∎∎
  13.351 [9795]   |∎
  15.947 [1150]   |
  18.543 [178]    |
  21.139 [39]     |
  23.735 [4]      |
  26.331 [6]      |

Latency distribution:
  10 % in 2.39 ms
  25 % in 3.50 ms
  50 % in 4.96 ms
  75 % in 6.41 ms
  90 % in 7.83 ms
  95 % in 8.80 ms
  99 % in 10.88 ms

Status code distribution:
  [OK]   1000000 responses

```
