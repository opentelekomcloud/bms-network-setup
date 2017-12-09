#!/usr/bin/env python
# vi:set ts=4 sw=4:
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
import subprocess


def usage():
	six.print_("Usage: bms-network-setup.py [-d] [-s]", file=sys.stderr)
	six.print_(" -d: Debug: reads network_data.json and writes ifcfg-* in current dir", file=sys.stderr)
	six.print_(" -s: SuSE: assume we run on a SuSE distribution", file=sys.stderr)
	sys.exit(1)

# Global settings
IS_SUSE = os.path.exists("/etc/SuSE-release")
DEBUG = 0
# Arg parsing
for arg in sys.argv[1:]:
	if arg == "-d":
		DEBUG = 1
	elif arg == "-s":
		IS_SUSE = 1
	else:
		six.print_("UNKNOWN ARG %s" % arg, file=sys.stderr)
		usage()

NETCONFPATH = "."
WICKEDCONFPATH = "."
CONFDIR="."
if not DEBUG:
	WICKEDCONFPATH = "/etc/wicked/ifconfig/"
	CONFDIR = "/etc"
	if IS_SUSE:
		NETCONFPATH = "/etc/sysconfig/network/"
	else:
		NETCONFPATH = "/etc/sysconfig/network-scripts/"
OS_LATEST = 'latest'
#FS_TYPES = ('vfat', 'iso9660')
LABEL = 'config-2'

# Logging
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
	"decode to plain text if neede"
	if isinstance(blob, six.text_type):
		return blob
	return blob.decode(encoding)


def load_json_hw(text, root_types=(dict,)):
	"build json dict from text representation"
	decoded = json.loads(decode_binary_hw(text))
	if not isinstance(decoded, tuple(root_types)):
		expects = ", ".join([str(t) for t in root_types])
		raise TypeError("(%s) root types expected, got %s instead"
						% (expects, type(decoded)))
	return decoded


# Unused
def write_wicked_conf_hw():
	"rebuild wicked configuration"
	cmd = '/usr/sbin/wicked convert --output %s %s' % (WICKEDCONFPATH, NETCONFPATH)
	status = 0
	try:
		output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as exc:
		status = exc.returncode
	LOG.info("convert wicked conf status is	 %s, output is	%s" % (status, output))
	if status:
		LOG.error("convert wicked conf error, because %s" % output)
		return False
	return True


# Markers for filling in the templates
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
# Template for ifcfg-eth* on SuSE
IFCFG_PHY_SUSE = (
	('LLADDR', 'ethernet_mac_address', OPT),
#	 ('USERCONTROL', 'no', HARD),
	('MTU', 'mtu', OPT),
	('STARTMODE', 'auto', HARD),
	('NM_CONTROLLED', 'no', HARD),
	('BOOTPROTO', '', MAYBEDHCP),
	('DEVICE', 'name', MAND),
	('TYPE', 'Ethernet', HARD),
#	 ('VLAN_ID', 'vlan_id', OPT),
#	 ('IPADDR', 'address', OPT),
#	 ('NETMASK', 'netmask', OPT),
	('GATEWAY', 'gateway', OPT)
)

# Template for ifcfg-bond* on SuSE
IFCFG_BOND_SUSE = (
	('LLADDR', 'ethernet_mac_address', OPT),
#	 ('USERCONTROL', 'no', HARD),
#	 ('MTU', 'mtu', OPT),
	('BONDING_MASTER', 'yes', HARD),
	('STARTMODE', 'auto', HARD),
	('NM_CONTROLLED', 'no', HARD),
	('BOOTPROTO', 'dhcp', HARD),
	('DEVICE', 'name', BONDNM),
	('TYPE', 'Bond', HARD),
#	 ('IPADDR', 'address', OPT),
#	 ('NETMASK', 'netmask', OPT),
	('GATEWAY', 'gateway', OPT),
	('BONDING_MODULE_OPTS', '', BONDMODOPTS),
	('BONDING_SLAVEx', '', BONDSLAVEX)
)

# Template for ifcfg-eth* on RedHat
IFCFG_PHY_REDHAT = (
#	 ('MACADDR', 'ethernet_mac_address', OPT),
	('USERCTL', 'no', HARD),
	('MTU', 'mtu', OPT),
	('ONBOOT', 'yes', HARD),
	('NM_CONTROLLED', 'no', HARD),
	('BOOTPROTO', '', MAYBEDHCP),
	('DEVICE', 'name', MAND),
	('TYPE', 'Ethernet', HARD),
#	 ('VLAN_ID', 'vlan_id', OPT),
#	 ('IPADDR', 'address', OPT),
#	 ('NETMASK', 'netmask', OPT),
	('GATEWAY', 'gateway', OPT),
	('MASTER', '', BONDMASTER),
#	 ('SLAVE', 'yes', HARD),
)

# Template for ifcfg-bond* on RedHat
IFCFG_BOND_REDHAT = (
	('MACADDR', 'ethernet_mac_address', OPT),
	('USERCTL', 'no', HARD),
 #	 ('MTU', 'mtu', OPT),
	('BONDING_MASTER', 'yes', HARD),
	('ONBOOT', 'yes', HARD),
	('NM_CONTROLLED', 'no', HARD),
	('BOOTPROTO', 'dhcp', HARD),
	('BONDING_OPTS', '', BONDMODOPTS),
	('DEVICE', 'name', BONDNM),
	('TYPE', 'Bond', HARD),
#	 ('IPADDR', 'address', OPT),
#	 ('NETMASK', 'netmask', OPT),
	('GATEWAY', 'gateway', OPT)
)

#TODO: Check for other well-defined parameters (cloud-init? OpenStack standards)


def maybedhcp(dev):
	"return dhcp if dev is not a bond slave, none otherwise"
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
	"transform json settings to bond module parameters"
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
	"output BONDING_SLAVEn=... lines"
	out=''
	no=0
	for name in btpl:
		out += "BONDING_SLAVE%i=%s\n" % (no, name)
		no += 1
	return out

def bondnm(iface):
	"derive bondN name from interfaceN string"
	return "bond%s" % iface[9:]

def bondmaster(dev):
	"Find bond master from slave device name"
	global bond_map
	for bnm in bond_map.keys():
		if dev in bond_map[bnm]:
			return bnm
	return None

def process_template(template, njson):
	"Create ifcfg-* file from templates and json"
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
			# TODO: Error handling
			out += "%s=%s\n" % (key, maybedhcp(njson["name"]))
		elif mode == BONDMODOPTS:
			out += "%s=%s\n" % (key, bondmodopts(njson))
		elif mode == BONDSLAVEX:
			# TODO: Error handling
			out += bondslavex(njson["bond_links"])
		elif mode == BONDNM:
			# TODO: Error handling
			out += "%s=%s\n" % (key, bondnm(njson["id"]))
		elif mode == BONDMASTER:
			master = bondmaster(njson["name"])
			if master:
				out += "%s=%s\n" % (key, master)
				out += "SLAVE=yes\n"
	return out


def mount(dev, path):
	"mount filesystem on dev at path"
	cmd = 'mount -o ro %s %s' % (dev, path)
	return subprocess.call(cmd)

def umount(path):
	"umount filesystem at path"
	cmd = 'umount %s' % path
	return subprocess.call(cmd)


def is_mounted(dev):
	"check whether device is already mounted and return mountpoint"
	f = open("/proc/mounts", "r")
	for ln in f:
		mfields = ln.split()
		if mfields[0] == dev:
			return mfields[1]
	return None

def read_json(path):
	"read json file and return decoded json dict"
	f = open(path, "r")
	txt = f.read()
	return 0, load_json_hw(txt)

def get_network_json_hw():
	"read json from config drive if possible"
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
	"get network_data.json and process it"
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
		six.print_("Not running on BMS", file=sys.stderr)
		sys.exit(0)
	open("%s/is_bms" % CONFDIR, "w")
	for ljson in network_json["links"]:
		if ljson["type"] == "bond":
			bond_slaves += ljson["bond_links"]
			bond_map[bondnm(ljson["id"])] = ljson["bond_links"]
	six.print_("Set up bonding: %s" % bond_map, file=sys.stderr)
	if IS_SUSE:
		IFCFG_PHY  = IFCFG_PHY_SUSE
		IFCFG_BOND = IFCFG_BOND_SUSE 
	else:
		IFCFG_PHY  = IFCFG_PHY_REDHAT
		IFCFG_BOND = IFCFG_BOND_REDHAT
	#six.print_(network_json)
	for ljson in network_json["links"]:
		if ljson["type"] == "phy":
			f = open("%s/ifcfg-%s" % (NETCONFPATH, ljson["name"]), "w")
			six.print_(process_template(IFCFG_PHY, ljson), file=f)
		elif ljson["type"] == "bond":
			f = open("%s/ifcfg-%s" % (NETCONFPATH, bondnm(ljson["id"])), "w")
			six.print_(process_template(IFCFG_BOND, ljson), file=f)

# Entry point
if __name__ == "__main__":
	process_network_hw()
