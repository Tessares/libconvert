# libconvert [![Build Status](https://travis-ci.com/Tessares/libconvert.svg?branch=master)](https://travis-ci.com/Tessares/libconvert)

Libraries to work with 0-RTT TCP Convert Protocol ([RFC 8803](https://datatracker.ietf.org/doc/draft-ietf-tcpm-converters)).
* `libconvert_util`: A library to parse and write Convert messages.
* `libconvert_client`: An `LD_PRELOAD` library that turns an existing client, using TCP sockets, into a Convert client.

This is work in progress. The `libconvert_util` library currently only supports the Connect TLV and the Error TLV. This repository does not yet include a server-side Transport Converter.

Future work:
* Sample server-side Transport Converter
* Support Extended TCP Header TLV and Converter bypass.
* Support Info TLV and the Supported TCP Extensions TLV.
* Support Cookie TLV.

### Requirements

* Requires Linux >= 4.5 (leverages the TCP Fast Open infrastructure).
* Configure `$ sysctl -w net.ipv4.tcp_fastopen=5` to enable sending data in the opening SYN, regardless of cookie availability.

### Build

Fetch the Git submodules:
```
$ git submodule init && git submodule update
```

The easiest way to build both libraries and run the tests is with the provided Dockerfile (which contains all deps):
```
$ docker build -t tessares.net/libconvert .
$ docker run --cap-add=NET_ADMIN --sysctl net.ipv4.tcp_fastopen=5 -v $PWD:/lc -t tessares.net/libconvert /bin/bash -c "mkdir -p /lc/build && cd /lc/build && cmake .. && make && make test"
```

Otherwise, assuming all deps are installed, build and run the tests with CMake as follows:
```
$ mkdir -p build && cd build && cmake .. && make && make test
```

### Usage & dependencies of `libconvert_client`

#### Runtime dependencies

 * libcapstone -- the disassembly engine used by used under the hood by `lib_syscall_intercept`.

#### Usage

To use the `libconvert_client` lib (assuming a Transport Converter listening at 192.0.2.1:1234):
```
$ CONVERT_ADDR=192.0.2.1 CONVERT_PORT=1234 LD_LIBRARY_PATH=$PWD/build LD_PRELOAD=libconvert_client.so curl https://www.tessares.net
```

The library supports IPv6 as well.

Currently tested with `curl` & `wget` on both Centos 7 and Ubuntu {16,18,19}.

### Contributing

Code contributions are more than welcome.

Upon change, please run `uncrustify` (0.68) and validate that `cppcheck` is still happy:
```
$ uncrustify -c uncrustify.cfg -l C --replace --no-backup convert*.{h,c}
$ cppcheck -I/usr/include -q --language=c --std=c99 --enable=warning,style,performance,portability -j "$(nproc)" --suppress=unusedStructMember ./convert*.{h,c}
```

To ease troubleshooting, download the 0-RTT TCP Convert [Wireshark dissector plugin](https://github.com/Tessares/convert-wireshark-dissector).

### Contact

* [Gregory Vander Schueren](mailto:gregory.vanderschueren@tessares.net)
* [Gregory Detal](mailto:gregory.detal@tessares.net)
* [Olivier Bonaventure](mailto:olivier.bonaventure@tessares.net)

### License

This project is licensed under the 3-Clause BSD License - see the
[LICENSE](LICENSE) file for details.
