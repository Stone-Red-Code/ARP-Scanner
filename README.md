# ARP-Scanner

> A lightweight cross-platform IP scanner

## Usage

1. Download the latest release
   - Chocolatey (Windows): `choco install arp-scanner --version=0.2.0`
   - Snapcraft (Linux): `snap install arp-scanner` and `snap connect arp-scanner:network-control` to give it permission to send arp requests
   - GitHub (Windows/Linux): https://github.com/Stone-Red-Code/ARP-Scanner/releases
1. Start `arp-scanner` with the IP range it should scan as parameter (e.g. `192.168.1.0 - 192.168.1.255`)

> Note: This programm may not work on all linux distributions because the [ArpLookup](https://github.com/georg-jung/ArpLookup) library has some [limitations](https://github.com/georg-jung/ArpLookup#supported-platforms)

## Example
![ARP-Scanner-Example](https://user-images.githubusercontent.com/56473591/236293969-4e8a65d2-86a3-4f10-8837-2b1aa0490252.png)


## Third party licenses
- [ArpLookup](https://github.com/georg-jung/ArpLookup) - [MIT](https://github.com/georg-jung/ArpLookup/blob/master/LICENSE.txt)
- [IPAddressRange](https://github.com/jsakamoto/ipaddressrange) - [MPL-2.0](https://github.com/jsakamoto/ipaddressrange/blob/master/LICENSE)
