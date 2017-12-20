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

In our package (on OpenBuildService in home:garloff:OTC), we also have the mechanism to dynamically disable the
ConfigDrive data source IF running on an OTC BMS.

## Other options
This is a different approach from bms-network-config, that does a lot more and duplicates some of the things that
cloud-init does.

## Examples
network_data.json
```json
{
  "services": [
    {
      "type": "dns",
      "address": "100.125.4.25"
    },
    {
      "type": "dns",
      "address": "8.8.8.8"
    }
  ],
  "networks": [
    {
      "network_id": "fc282960-6dd3-4797-8e6d-33389de9671d",
      "link": "interface0",
      "type": "ipv4_dhcp",
      "id": "network0",
      "gateway": "192.168.66.1"
    }
  ],
  "links": [
    {
      "type": "phy",
      "ethernet_mac_address": "2c:55:d3:c4:9c:0f",
      "id": "eth0",
      "name": "eth0",
      "mtu": 8888
    },
    {
      "type": "phy",
      "ethernet_mac_address": "2c:55:d3:c4:9c:10",
      "id": "eth1",
      "name": "eth1",
      "mtu": 8888
    },
    {
      "bond_miimon": 100,
      "ethernet_mac_address": "fa:16:3e:ab:cf:f3",
      "mtu": 8888,
      "bond_mode": "1",
      "bond_links": [
        "eth0",
        "eth1"
      ],
      "type": "bond",
      "id": "interface0"
    }
  ]
}
```

This creates the ifcfg-eth0, -eth1 and -bond0 files that enslave the two ethX devices
to do bonding (LACP aka 802.1ad) on bond0.
