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
  Total:        39.97 s
  Slowest:      24.73 ms
  Fastest:      0.18 ms
  Average:      3.19 ms
  Requests/sec: 25021.37

Response time histogram:
  0.178  [1]      |
  2.633  [384807] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  5.088  [514062] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  7.544  [90352]  |∎∎∎∎∎∎∎
  9.999  [10066]  |∎
  12.454 [589]    |
  14.909 [103]    |
  17.364 [14]     |
  19.820 [0]      |
  22.275 [5]      |
  24.730 [1]      |

Latency distribution:
  10 % in 1.54 ms
  25 % in 2.19 ms
  50 % in 2.99 ms
  75 % in 3.94 ms
  90 % in 5.10 ms
  95 % in 5.92 ms
  99 % in 7.61 ms

Status code distribution:
  [OK]   1000000 response
```

