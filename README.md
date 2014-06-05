#Sendd
Sendd is a user space implementation of SEcure Neighbor Discovery (SEND) protocol for IPv6. This package also includes tools for generating and verifying Cryptographically Generated Addresses (CGAs) and Extensions for IP Addresses for X.509 certificates.

This work is based on discontinued DoCoMo SEND project. The netfilter module was added so the ip6tables command is not required. Dependancy on old libipq was replaced by new libnetfilter_queue library and code was updated for current versions of openssl and Linux kernel. New version of sendd utilizes netlink protocol for communication with kernel. This protocol is used for IP address operations and replaces deprecated ioctl. The number of bugs was fixed along the way.

Project is in beta stage and there is a lot of work to do. Currently only the Linux platform is supported. Support for another platforms is planned in future.
