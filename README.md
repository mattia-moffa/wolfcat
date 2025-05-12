# wolfcat

`wolfcat` is a barebones `netcat` clone that runs on top of a TLS session based on [WolfSSL](https://github.com/wolfSSL/wolfssl).

## Building

```
git clone https://github.com/mattia-moffa/wolfcat.git
cd wolfcat
mkdir build
cd build
cmake ..
make
```

If WolfSSL is installed in a non-standard path, you can specify it via `cmake .. -DWOLFSSL_ROOT=/path/to/wolfssl`.

## Installing

```
sudo make install
```

## Usage

```
Usage: wolfcat [OPTIONS...] <hostname> <port>

<hostname> is an IPv4 address, an IPv6 address or a hostname.
<port> is a TCP port number.

Available options:
    -h                      Print this help message.
    -k                      After a connection is terminated, listen for another
                            one. Requires -l.
    -l                      Listen for incoming connections (server mode).
                            In this mode, <hostname> and <port> identify the
                            interface and port to listen on.
    --ca-cert <filename>    Use this CA certificate. Use this option multiple
                            times to specify multiple certificates.
    --ca-cert-dir <dirname> Scan directory  <dirname> for CA certificates.
    --cert <filename>       Use this server certificate. Requires -l.
    --key <filename>        Use this server private key. Requires -l.
```

## Example

```
# On the server side:
wolfcat -l localhost 5000 --ca-cert ca-cert.pem --cert cert.pem --key key.pem

# On the client side:
echo "Hello world!" | wolfcat localhost 5000 --ca-cert ca-cert.pem
```

After this, the server will print `Hello world!` to standard output and both peers will exit. It is also possible to instruct the server to listen for more clients instead with the `-k` option.

The same effect can also be achieved in the opposite direction:

```
# On the server side:
echo "Hello world!" | wolfcat -l localhost 5000 --ca-cert ca-cert.pem --cert cert.pem --key key.pem

# On the client side:
wolfcat localhost 5000 --ca-cert ca-cert.pem
```

In this second case, the client will immediately print `Hello world!` to standard output and both peers will exit.
