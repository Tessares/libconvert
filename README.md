# libconvert

An `LD_PRELOAD` library that turns an existing client, using TCP sockets, into
a Convert client. See the IETF draft [draft-ietf-tcpm-converters-05](https://datatracker.ietf.org/doc/draft-ietf-tcpm-converters) for more information.

This is work in progress. Currently supports the Connect TLV and the Error TLV.

Future work may add support for:
* Extended TCP Header TLV and Converter bypass.
* Info TLV and the Supported TCP Extensions TLV.
* Cookie TLV.

### Requirements

* Requires Linux >= 4.5 (leverages the TCP Fast Open infrastructure).
* Configure `$ sysctl -w net.ipv4.tcp_fastopen=5` to enable sending data in the
opening SYN, regardless of cookie availability.

### Build & usage

Build with CMake:
```
$ git submodule init && git submodule update
$ mkdir build && cd build && cmake .. && make
```

Usage:
```
$ CONVERT_ADDR=192.0.2.1 CONVERT_PORT=1234 LD_PRELOAD=./libconvert.so curl https://www.tessares.net
```

Currently tested with `curl` & `wget` on both Centos 7 and Ubuntu 18.

### Running the tests

Requires Python 3 and Scapy (make sure Scapy can run with root privileges).

Run as root as we need to sniff the lopoback iface:
```
$ sudo make test
```

### Contributing

Code contributions are more than welcome.

To contribute to the Convert protocol, see this [Github repository](https://github.com/obonaventure/draft-tcp-converters), which tracks the evolution of the 0-RTT TCP Converter
Internet draft.

### Contact

* [Gregory Vander Schueren](mailto:gregory.vanderschueren@tessares.net)
* [Gregory Detal](mailto:gregory.detal@tessares.net)
* [Olivier Bonaventure](mailto:olivier.bonaventure@tessares.net)

### License

This project is licensed under the 3-Clause BSD License - see the
[LICENSE](LICENSE) file for details.
