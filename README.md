# KMS standalone

**这个版本的KMS为适配其它组件做了一些改动，如果你不知道它在适配什么，别用。**

KMS服务。

警告: 私钥会以未加密的形式缓存在内存中（为了更好的性能），并且在初始化过程中和析构以后都没有将这些敏感数据的内存置为0（这需要修改`efficient-sm2`）。

除此之外的所有碰过私钥的内存用完后都会被填充成0。

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

配置样例，MySQL的数据库必须事先创建好。

```toml
[kms_standalone]
grpc_listen_port = 50005

db_url = "mysql://user:password@host:port/db"
master_password = "0x12345678901234567890123456" # 必须是个长度为26的十六进制字符串（即转为二进制后为13字节），开头的0x可加可不加。

# 以下参数是可选的，有默认值。
db_conn_timeout_millis = 10000  # 10 seconds
db_conn_idle_timeout_millis = 20000 # 20 seconds
db_max_connections = 32
```


```protobuf
syntax = "proto3";

package kms;

message SignRequest {
    string account_id = 1;
    repeated bytes messages = 2;
}

message SignResponse {
    repeated bytes signatures = 1;
}

message GetAccountAddressRequest {
    string account_id = 1;
}

message GetAccountAddressResponse {
    string address = 1;
}

message InsertAccountRequest {
    string id = 1;

    // 加密后的私钥，加密方法是master_password转成的13字节+盐的3字节总共16字节作为key，全零的16字节作为iv。
    bytes encrypted_privkey = 2;
    // 长度必须为三个字节
    bytes salt = 3;
}

message InsertAccountResponse { }

service Kms {
    rpc Sign(SignRequest) returns (SignResponse);
    rpc GetAccountAddress(GetAccountAddressRequest) returns (GetAccountAddressResponse);
    rpc InsertAccount(InsertAccountRequest) returns (InsertAccountResponse);
}

```
