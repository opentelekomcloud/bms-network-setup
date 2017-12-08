#!/usr/bin/env python
# 
# Simple script to parse network_data.json and derive working ifcfg- files
# This is a minimalistic version for supporting OTC bare metal networks.
# Losely based on Huawei's bms-network-config.
#
# (c) Kurt Garloff <kurt@garloff.de>, 12/2017
# License: CC-BY-SA 3.0

import os
import sys
import json
import logging
import base64
import six
import commands


IS_SUSE = os.path.exists("/etc/SuSE-release")
DEBUG = 0
# Arg parsing
for arg in sys.argv[1:]:
    if arg == "-d":
        DEBUG = 1
    elif arg == "-s":
        IS_SUSE = 1
    else:
        print >>sys.stderr, "UNKNOWN ARG %s" % arg
        sys.exit(1)


NETCONFPATH = "."
WICKEDCONFPATH = "."
CONFDIR="."
if not DEBUG:
    if IS_SUSE:
        NETCONFPATH = "/etc/sysconfig/network/"
    else:
	NETCONFPATH = "/etc/sysconfig/network-scripts/"
    WICKEDCONFPATH = "/etc/wicked/ifconfig/"
    CONFDIR = "/etc"
OS_LATEST = 'latest'
#FS_TYPES = ('vfat', 'iso9660')
LABEL = 'config-2'


LOG = logging.getLogger()
if DEBUG:
    handler = logging.FileHandler("bms-network-setup.log")
else:
    handler = logging.FileHandler("/var/log/bms-network-setup.log")
formatter = logging.Formatter('%(asctime)s - '
                              '%(filename)s[%(levelname)s]: %(message)s')
handler.setFormatter(formatter)
LOG.addHandler(handler)
LOG.setLevel(logging.INFO)


def decode_binary_hw(blob, encoding='utf-8'):
    if isinstance(blob, six.text_type):
        return blob
    return blob.decode(encoding)


def load_json_hw(text, root_types=(dict,)):
    decoded = json.loads(decode_binary_hw(text))
    if not isinstance(decoded, tuple(root_types)):
        expects = ", ".join([str(t) for t in root_types])
        raise TypeError("(%s) root types expected, got %s instead"
                        % (expects, type(decoded)))
    return decoded


# Unused
def write_wicked_conf_hw():
    cmd = '/usr/sbin/wicked convert --output %s %s' % (WICKEDCONFPATH, NETCONFPATH)
    (status, output) = commands.getstatusoutput(cmd)
    LOG.info("convert wicked conf status is  %s, output is  %s" % (status, output))
    if status:
        LOG.error("convert wicked conf error, because %s" % output)
        return False
    return True

# Unused
VLAN_CONF = ['LLADDR', 'USERCONTRL', 'ETHERDEVICE', 'MTU',
             'STARTMODE', 'NM_CONTROLLED', 'BOOTPROTO',
             'DEVICE', 'TYPE', 'VLAN_ID', 'IPADDR', 'NETMASK', 'GATEWAY']

# Marker for filling in the templates
# Optional and Mandatory fields that can be taken literally from JSON
OPT=0
MAND=1
# Hardcoded value
HARD=2
# dhcp or none, depending on whether interface is enslaved
MAYBEDHCP=3
# special fn to compose module options (mode, miimon)
BONDMODOPTS=4
# special fn to create BONDING_SLAVEn entries
BONDSLAVEX=5
# special fn to create bondX name
BONDNM=6
# special fn to list bond master
BONDMASTER=7

# Transformation rules
IFCFG_PHY_SUSE = (
    ('LLADDR', 'ethernet_mac_address', OPT),
#    ('USERCONTROL', 'no', HARD),
    ('MTU', 'mtu', OPT),
    ('STARTMODE', 'auto', HARD),
    ('NM_CONTROLLED', 'no', HARD),
    ('BOOTPROTO', '', MAYBEDHCP),
    ('DEVICE', 'name', MAND),
    ('TYPE', 'Ethernet', HARD),
#    ('VLAN_ID', 'vlan_id', OPT),
#    ('IPADDR', 'address', OPT),
#    ('NETMASK', 'netmask', OPT),
    ('GATEWAY', 'gateway', OPT)
)

IFCFG_BOND_SUSE = (
    ('LLADDR', 'ethernet_mac_address', OPT),
#    ('USERCONTROL', 'no', HARD),
#    ('MTU', 'mtu', OPT),
    ('BONDING_MASTER', 'yes', HARD),
    ('STARTMODE', 'auto', HARD),
    ('NM_CONTROLLED', 'no', HARD),
    ('BOOTPROTO', 'dhcp', HARD),
    ('DEVICE', 'name', BONDNM),
    ('TYPE', 'Bond', HARD),
#    ('IPADDR', 'address', OPT),
#    ('NETMASK', 'netmask', OPT),
    ('GATEWAY', 'gateway', OPT),
    ('BONDING_MODULE_OPTS', '', BONDMODOPTS),
    ('BONDING_SLAVEx', '', BONDSLAVEX)
)

IFCFG_PHY_REDHAT = (
#    ('MACDDR', 'ethernet_mac_address', OPT),
    ('USERCTL', 'no', HARD),
    ('MTU', 'mtu', OPT),
    ('ONBOOT', 'yes', HARD),
    ('NM_CONTROLLED', 'no', HARD),
    ('BOOTPROTO', '', MAYBEDHCP),
    ('DEVICE', 'name', MAND),
    ('TYPE', 'Ethernet', HARD),
#    ('VLAN_ID', 'vlan_id', OPT),
#    ('IPADDR', 'address', OPT),
#    ('NETMASK', 'netmask', OPT),
    ('GATEWAY', 'gateway', OPT),
    ('MASTER', '', BONDMASTER),
#    ('SLAVE', 'yes', HARD),
)

IFCFG_BOND_REDHAT = (
    ('MACADDR', 'ethernet_mac_address', OPT),
    ('USERCTL', 'no', HARD),
 #   ('MTU', 'mtu', OPT),
    ('BONDING_MASTER', 'yes', HARD),
    ('ONBOOT', 'yes', HARD),
    ('NM_CONTROLLED', 'no', HARD),
    ('BOOTPROTO', 'dhcp', HARD),
    ('BONDING_OPTS', '', BONDMODOPTS),
    ('DEVICE', 'name', BONDNM),
    ('TYPE', 'Bond', HARD),
#    ('IPADDR', 'address', OPT),
#    ('NETMASK', 'netmask', OPT),
    ('GATEWAY', 'gateway', OPT)
)

#TODO: Check for other well-defined parameters (cloud-init? OpenStack standards)


def maybedhcp(dev):
    global bond_slaves
    if dev in bond_slaves:
        return "none"
    else:
        return "dhcp"

BOND_TPL_OPTS = tuple([
    ('bond_mode', "mode=%s"),
    ('bond_xmit_hash_policy', "xmit_hash_policy=%s"),
    ('bond_miimon', "miimon=%s"),
])
def bondmodopts(bjson):
    modpar=''
    for jopt, mopt in BOND_TPL_OPTS:
        try:
            val = bjson[jopt]
            if modpar:
                modpar += " "
            modpar += mopt % val
        except:
            pass
    return '"%s"' % modpar

def bondslavex(btpl):
    out=''
    no=0
    for name in btpl:
        out += "BONDING_SLAVE%i=%s\n" % (no, name)
        no += 1
    return out

def bondnm(iface):
    return "bond%s" % iface[9:]

def bondmaster(dev):
    global bond_map
    for bnm in bond_map.keys():
        if dev in bond_map[bnm]:
            return bnm
    return None

def process_template(template, njson):
    out='#Note: File autogenerated by bms-network-setup.py from network_data.json\n'
    for key, val, mode in template:
        if mode == HARD:
            out += "%s=%s\n" % (key, val)
        elif mode == OPT or mode == MAND:
            try:
                jval = njson[val]
                out += "%s=%s\n" % (key, jval)
            except:
                if mode == MAND:
                    LOG.error("Mandatory value %s not found for %s setting" % (val, key))
        elif mode == MAYBEDHCP:
            # FIXME: Error handling
            out += "%s=%s\n" % (key, maybedhcp(njson["name"]))
        elif mode == BONDMODOPTS:
            out += "%s=%s\n" % (key, bondmodopts(njson))
        elif mode == BONDSLAVEX:
            # FIXME: Error handling
            out += bondslavex(njson["bond_links"])
        elif mode == BONDNM:
            # FIXME: Error handling
            out += "%s=%s\n" % (key, bondnm(njson["id"]))
        elif mode == BONDMASTER:
            master = bondmaster(njson["name"])
            if master:
                out += "%s=%s\n" % (key, master)
                out += "SLAVE=yes\n"
    return out


def mount(dev, path):
    cmd = 'mount -o ro %s %s' % (dev, path)
    (status, output) = commands.getstatusoutput(cmd)
    return status

def umount(path):
    cmd = 'umount %s' % path
    (status, output) = commands.getstatusoutput(cmd)
    return status


def is_mounted(dev):
    f = open("/proc/mounts", "r")
    for ln in f:
        mfields = ln.split()
        if mfields[0] == dev:
            return mfields[1]
    return None

def read_json(path):
    f = open(path, "r")
    txt = f.read()
    return 0, load_json_hw(txt)

def get_network_json_hw():
    if (len(sys.argv) > 1 and sys.argv[1] == "-d"):
        return read_json("network_data.json")
    labelpath = "/dev/disk/by-label/%s" % LABEL
    if not os.path.exists(labelpath):
        LOG.error("No config drive with label %s found" % LABEL)
        return -1, None
    realpath = os.path.realpath(labelpath)
    mountpoint = is_mounted(realpath)
    if mountpoint:
        return read_json(mountpoint + "/openstack/%s/network_data.json" % OS_LATEST)
    else:
        if mount(realpath, "/mnt"):
            LOG.error("Failed to mount %s on /mnt" % realpath)
            return -1, None
        ret, json = read_json("/mnt/openstack/%s/network_data.json" % OS_LATEST)
        umount("/mnt")
        return ret, json

def process_network_hw():
    global bond_slaves
    global bond_map
    bond_slaves=[]
    bond_map = {}
    ret, network_json = get_network_json_hw()
    if ret:
        try:
            os.unlink("%s/is_bms" % CONFDIR)
        except:
            pass
        print >>sys.stderr, "Not running on BMS"
        sys.exit(0)
    file("%s/is_bms" % CONFDIR, "w")
    for ljson in network_json["links"]:
        if ljson["type"] == "bond":
            bond_slaves += ljson["bond_links"]
            bond_map[bondnm(ljson["id"])] = ljson["bond_links"]
    print >>sys.stderr, "Set up bonding: %s" % bond_map
    if IS_SUSE:
        IFCFG_PHY  = IFCFG_PHY_SUSE
        IFCFG_BOND = IFCFG_BOND_SUSE 
    else:
        IFCFG_PHY  = IFCFG_PHY_REDHAT
        IFCFG_BOND = IFCFG_BOND_REDHAT
    #print network_json
    for ljson in network_json["links"]:
        if ljson["type"] == "phy":
            f = file("%s/ifcfg-%s" % (NETCONFPATH, ljson["name"]), "w")
            print >>f, process_template(IFCFG_PHY, ljson)
        elif ljson["type"] == "bond":
            f = file("%s/ifcfg-%s" % (NETCONFPATH, bondnm(ljson["id"])), "w")
            print >>f, process_template(IFCFG_BOND, ljson)


def main(argv):
	process_network_hw()

if __name__ == "__main__":
	main(sys.argv)
