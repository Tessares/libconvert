# libconvert [![Build Status](https://travis-ci.com/Tessares/libconvert.svg?branch=master)](https://travis-ci.com/Tessares/libconvert)

An `LD_PRELOAD` library that turns an existing client, using TCP sockets, into
a Convert client. See the IETF draft [draft-ietf-tcpm-converters-05](https://datatracker.ietf.org/doc/draft-ietf-tcpm-converters) for more information.

This is work in progress. The `LD_PRELOAD` client and the underlying library currently only support the Connect TLV and the Error TLV. This repository does not yet include a server-side Transport Converter.

Future work:
* Sample server-side Transport Converter
* Support Extended TCP Header TLV and Converter bypass.
* Support Info TLV and the Supported TCP Extensions TLV.
* Support Cookie TLV.

### Requirements

* Requires Linux >= 4.5 (leverages the TCP Fast Open infrastructure).
* Configure `$ sysctl -w net.ipv4.tcp_fastopen=5` to enable sending data in the
opening SYN, regardless of cookie availability.
* Check the [CI build script](.travis.yml) for a complete list of deps (based on Ubuntu Xenial).

### Build & usage

Build with CMake:
```
$ git submodule init && git submodule update
$ mkdir build && cd build && cmake .. && make
```

Usage (assuming a Transport Converter listening at 192.0.2.1:1234):
```
$ CONVERT_ADDR=192.0.2.1 CONVERT_PORT=1234 LD_PRELOAD=./libconvert_client.so curl https://www.tessares.net
```

Currently tested with `curl` & `wget` on both Centos 7 and Ubuntu 18.

### Running the tests

Requirements: check the [CI build script](.travis.yml) for complete list.

In particular, it requires Python 3 and Scapy (make sure Scapy can run with root privileges).
Also requires uncrustify, cppcheck and scan-build for the linting checks.

Run as root as we need to sniff the loopback iface:
```
$ sudo make test
```

### Contributing

Code contributions are more than welcome.

Upon change, please run `uncrustify` (0.62) and validate that `cppcheck` is still happy:
```
$ uncrustify -c uncrustify.cfg -l C --replace --no-backup convert*.{h,c}
$ cppcheck -I/usr/include -q --language=c --std=c99 --enable=warning,style,performance,portability -j "$(nproc)" --suppress=unusedStructMember ./convert*.{h,c}
```

To contribute to the Convert protocol, see this [Github repository](https://github.com/obonaventure/draft-tcp-converters), which tracks the evolution of the 0-RTT TCP Converter
Internet draft.

To ease troubleshooting, download the 0-RTT TCP Convert [Wireshark dissector plugin](https://github.com/Tessares/convert-wireshark-dissector).

### Contact

* [Gregory Vander Schueren](mailto:gregory.vanderschueren@tessares.net)
* [Gregory Detal](mailto:gregory.detal@tessares.net)
* [Olivier Bonaventure](mailto:olivier.bonaventure@tessares.net)

### License

This project is licensed under the 3-Clause BSD License - see the
[LICENSE](LICENSE) file for details.
