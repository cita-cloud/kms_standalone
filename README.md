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
# BEWARE THE TRAILING CONTROL CHARACTERS LIKE `\r\n` IN THE FILE.
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
cargo build --release
```

### Sign
```
$ ./ghz --proto ./proto/kms.proto --call kms.KmsService/SignMessage -d '{ "keyId": "0", "msg": "zF1F5xUhveGShe28Q+Dc/D5R2B3xQBXCWwj+asMLg70="}' --insecure -c 128 -n 1000000 127.0.0.1:50005

Summary:
  Count:        1000000
  Total:        36.35 s
  Slowest:      20.86 ms
  Fastest:      0.14 ms
  Average:      2.76 ms
  Requests/sec: 27513.18

Response time histogram:
  0.143  [1]      |
  2.214  [383116] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  4.286  [491184] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  6.358  [108826] |∎∎∎∎∎∎∎∎∎
  8.430  [14998]  |∎
  10.501 [1702]   |
  12.573 [125]    |
  14.645 [31]     |
  16.717 [9]      |
  18.788 [7]      |
  20.860 [1]      |

Latency distribution:
  10 % in 1.27 ms
  25 % in 1.83 ms
  50 % in 2.53 ms
  75 % in 3.45 ms
  90 % in 4.54 ms
  95 % in 5.29 ms
  99 % in 6.86 ms

Status code distribution:
  [OK]   1000000 responses
```

### Verify

```
$ ./ghz --proto ./proto/kms.proto --call kms.KmsService/RecoverSignature -d '{ "msg": "zF1F5xUhveGShe28Q+Dc/D5R2B3xQBXCWwj+asMLg70=", "signature": "m0mAIri0Bpkk86SS8orFMKsSH+ghYxhCbVMGpZBR+Pj1jwhGDGVxVJHrBAX1JRJAzNbkP/HcpsKzkLVfahYj18p6ZcQQbvUauA1hZUfqmKKsHMJiVeM8wnQT6mtSieaPKN07xOavLwpChbLNbXm/BCKG7nNBlzSZbg945Q719cA="}' --insecure -c 128 -n 1000000 127.0.0.1:50005

Summary:
  Count:        1000000
  Total:        43.98 s
  Slowest:      20.95 ms
  Fastest:      0.23 ms
  Average:      3.54 ms
  Requests/sec: 22736.60

Response time histogram:
  0.229  [1]      |
  2.301  [224556] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  4.373  [516155] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  6.444  [207474] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  8.516  [43887]  |∎∎∎
  10.588 [6971]   |∎
  12.660 [740]    |
  14.732 [175]    |
  16.803 [31]     |
  18.875 [8]      |
  20.947 [2]      |

Latency distribution:
  10 % in 1.69 ms
  25 % in 2.41 ms
  50 % in 3.35 ms
  75 % in 4.42 ms
  90 % in 5.62 ms
  95 % in 6.49 ms
  99 % in 8.27 ms

Status code distribution:
  [OK]   1000000 responses

```

### Hash

```
$ ./ghz --proto ./proto/kms.proto --call kms.KmsService/HashData -d '{"data": "zF1F5xUhveGShe28Q+Dc/D5R2B3xQBXCWwj+asMLg70="}' --insecure -c 128 -n 1000000 127.0.0.1:50005

Summary:
  Count:        1000000
  Total:        30.92 s
  Slowest:      25.59 ms
  Fastest:      0.08 ms
  Average:      2.19 ms
  Requests/sec: 32343.47

Response time histogram:
  0.079  [1]      |
  2.630  [697280] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  5.181  [278285] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  7.732  [23057]  |∎
  10.282 [1289]   |
  12.833 [66]     |
  15.384 [13]     |
  17.935 [3]      |
  20.486 [4]      |
  23.036 [1]      |
  25.587 [1]      |

Latency distribution:
  10 % in 0.86 ms
  25 % in 1.26 ms
  50 % in 1.93 ms
  75 % in 2.87 ms
  90 % in 3.91 ms
  95 % in 4.58 ms
  99 % in 5.99 ms

Status code distribution:
  [OK]   1000000 responses

```
