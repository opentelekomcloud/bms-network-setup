# bms-network-setup
Script to parse network_data.json and configure ifcfg-* files from it.

## How it works
This is a much more limited and much simpler script to enable networking on OTC Bare Metal instances.
Bare Metal instances have a ConfigDrive that contains meta_data.json and network_data.json.
The meta_data.json is unfortunately not fully correct at this point (wrong hostname) and user_data is missing,
so we prefer to use the network OpenStack DataSource via the normal cloud-init mechanism.
However, to even get networking working, we need to parse and evaluate network_data.json.
This scripts does this by parsing it and then writing out the network ifcfg-* files and then leaves
it to the standard distribution networking mechanisms (wicked, ifup, NetworkManager, ...) to do the network setup.

In our package (on OpenBuildService 
in [home:garloff:OTC](https://build.opensuse.org/package/show/home:garloff:OTC/bms-network-setup)), 
we also have the mechanism to dynamically disable the
ConfigDrive data source IF running on an OTC BMS.

## Other options
This is a different approach from [bms-network-config](https://github.com/bms-network/bms-network-config).
bms-network-config does a lot more and duplicates some of the things that cloud-init and the
distro network setup scripts/NM/wickedd do.

## Examples
network_data.json
```json
{
  "services": [
    {
      "type": "dns",
      "address": "100.125.4.25"
    }, {
      "type": "dns",
      "address": "8.8.8.8"
    } ],
  "networks": [
    {
      "network_id": "fc282960-6dd3-4797-8e6d-33389de9671d",
      "link": "interface0",
      "type": "ipv4_dhcp",
      "id": "network0",
      "gateway": "192.168.66.1"
    }, {
      "network_id": "a90ad03f-4cb4-4cb3-8b10-a8aa571a169f",
      "link": "interface1",
      "type": "ipv4_dhcp",
      "id": "network1",
      "gateway": "192.168.70.1"
    }, {
      "network_id": "fbddc7a6-6d2b-4957-a880-aa89238ab011",
      "type": "ipv4",
      "netmask": "255.255.252.0",
      "link": "interface2",
      "routes": [],
      "ip_address": "192.168.81.99",
      "id": "network2"
    } ],
  "links": [
    {
      "type": "phy",
      "ethernet_mac_address": "2c:55:d3:9a:06:35",
      "id": "eth0",
      "name": "eth0",
      "mtu": 8888
    }, {
      "type": "phy",
      "ethernet_mac_address": "2c:55:d3:9a:06:36",
      "id": "eth1",
      "name": "eth1",
      "mtu": 8888
    }, {
      "bond_miimon": 100,
      "ethernet_mac_address": "fa:16:3e:3f:15:55",
      "mtu": 8888,
      "bond_mode": "1",
      "bond_links": [ "eth0", "eth1" ],
      "type": "bond",
      "id": "interface0"
    }, {
      "ethernet_mac_address": "fa:16:3e:87:0b:67",
      "mtu": 8888,
      "vlan_link": "interface0",
      "vlan_id": 2315,
      "type": "vlan",
      "id": "interface1",
      "vlan_mac_address": "fa:16:3e:87:0b:67"
    }, {
      "ethernet_mac_address": "fa:16:3e:fc:a9:28",
      "mtu": 8888,
      "vlan_link": "interface0",
      "vlan_id": 3966,
      "type": "vlan",
      "id": "interface2",
      "vlan_mac_address": "fa:16:3e:fc:a9:28"
    } ]
}
```
bms-network-setup.py creates the ifcfg-eth0, -eth1, -bond0, -vlan2315, and -vlan3996 files.
bond0 will enslave eth0 and eth1, creating an LACP (802.1ad) link.
vlan2315 and vlan3996 are VLANs on this bond0 device, the former configured with DHCP
while the latter has a static configuration.
