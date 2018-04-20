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
	six.print_("Usage: bms-network-setup.py [-d] [-s|u|r]", file=sys.stderr)
	six.print_(" -d: Debug: reads network_data.json and writes ifcfg-* in current dir", file=sys.stderr)
	six.print_(" -s: SuSE: assume we run on a SuSE distribution", file=sys.stderr)
	six.print_(" -u: Debian: assume we run on a Debian/Ubuntu distribution", file=sys.stderr)
	six.print_(" -r: RedHat: assume we run on a RedHat/CentOS distribution", file=sys.stderr)
	sys.exit(1)

# Global settings
IS_SUSE  = os.path.exists("/etc/SuSE-release")
IS_EULER = os.path.exists("/etc/euleros-release")
IS_DEB   = os.path.exists("/etc/debian_version")
DEBUG = 0
# Arg parsing
for arg in sys.argv[1:]:
	if arg == "-d":
		DEBUG = True
	elif arg == "-s":
		IS_SUSE = True; IS_DEB = False; IS_EULER = False
	elif arg == "-u":
		IS_DEB = True; IS_SUSE = False; IS_EULER = False
	elif arg == "-r":
		IS_DEB = False; IS_SUSE = False; IS_EULER = False
	else:
		six.print_("UNKNOWN ARG %s" % arg, file=sys.stderr)
		usage()

NETCONFPATH = "."
WICKEDCONFPATH = "."
CONFDIR="."
if not DEBUG:
	WICKEDCONFPATH = "/etc/wicked/ifconfig/"
	CONFDIR = "/etc"
	if IS_DEB:
		NETCONFPATH = "/etc/network/interfaces.d/"
	elif IS_SUSE:
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
		output = subprocess.check_output(cmd.split(" "), stderr=subprocess.STDOUT)
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
# special fn to list bond master (and set SLAVE=yes)
BONDMASTER=7
# special fn to set DHCP / STATIC for bond
BONDDHCP=8
# special fn to set up nameservers
NAMESERVERS=9
# special fn to compose vlan name vlan$ID
VLANNAME=10
# special fn to compose vlan name vlan$ID
DEBNMMODE=11
# deb bond slave list
BONDSLAVES=12

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
)

# Template for ifcfg-bond* on SuSE
IFCFG_BOND_SUSE = (
	('LLADDR', 'ethernet_mac_address', OPT),
#	('USERCONTROL', 'no', HARD),
#	('MTU', 'mtu', OPT),
	('BONDING_MASTER', 'yes', HARD),
	('STARTMODE', 'auto', HARD),
	('NM_CONTROLLED', 'no', HARD),
	('BOOTPROTO', 'dhcp', BONDDHCP),
	('DEVICE', 'id', BONDNM),
	('TYPE', 'Bond', HARD),
	('BONDING_MODULE_OPTS', '', BONDMODOPTS),
	('BONDING_SLAVEx', '', BONDSLAVEX)
)

# Template for vlans
IFCFG_VLAN_SUSE = (
	('LLADDR', 'vlan_mac_address', MAND),
#	('USERCONTROL', 'no', HARD),
	('MTU', 'mtu', OPT),
	('BOOTPROTO', 'dhcp', BONDDHCP),
	('NAME', 'vlan_id', VLANNAME),
	('TYPE', 'vlan', HARD),
	('VLAN', 'yes', HARD),
	('STARTMODE', 'auto', HARD),
	('ETHERDEVICE', 'vlan_link', BONDNM)
)

# Snippets for static address config
IFCFG_STATIC_SUSE = (
	('BOOTPROTO', 'static', HARD),
	('IPADDR', 'ip_address', MAND),
	('NETMASK', 'netmask', MAND),
	('GATEWAY', 'gateway', OPT),
)
# Template for ifcfg-eth* on RedHat
IFCFG_PHY_REDHAT = (
#	('MACADDR', 'ethernet_mac_address', OPT),
	('HWADDR', 'ethernet_mac_address', OPT),
	('USERCTL', 'no', HARD),
	('MTU', 'mtu', OPT),
	('ONBOOT', 'yes', HARD),
	('NM_CONTROLLED', 'yes', HARD),
	('BOOTPROTO', '', MAYBEDHCP),
	('DEVICE', 'name', MAND),
	('TYPE', 'Ethernet', HARD),
#	 ('VLAN_ID', 'vlan_id', OPT),
	('MASTER', '', BONDMASTER),
)

# Template for ifcfg-bond* on RedHat
IFCFG_BOND_REDHAT = (
	('MACADDR', 'ethernet_mac_address', OPT),
#	('HWADDR', 'ethernet_mac_address', OPT),
	('USERCTL', 'no', HARD),
#	('MTU', 'mtu', OPT),
	('BONDING_MASTER', 'yes', HARD),
	('ONBOOT', 'yes', HARD),
	('NM_CONTROLLED', 'yes', HARD),
	('BOOTPROTO', 'dhcp', BONDDHCP),
	('BONDING_OPTS', '', BONDMODOPTS),
	('DEVICE', 'id', BONDNM),
	('TYPE', 'Bond', HARD),
)

# Template for vlans
IFCFG_VLAN_REDHAT = (
	('VLAN', 'yes', HARD),
	('VLAN_NAME_TYPE', 'VLAN_PLUS_VID_NO_PAD', HARD),
	('MACADDR', 'vlan_mac_address', MAND),
	('USERCTL', 'no', HARD),
	('MTU', 'mtu', OPT),
	('ONBOOT', 'yes', HARD),
	('BOOTPROTO', 'dhcp', BONDDHCP),
	('DEVICE', 'vlan_id', VLANNAME),
	('PHYSDEV', 'vlan_link', BONDNM)
)

IFCFG_STATIC_REDHAT = (
	('BOOTPROTO', 'none', HARD),	# static?
	('IPADDR', 'ip_address', MAND),	# ADDRESS?
	('NETMASK', 'netmask', MAND),
	('GATEWAY', 'gateway', OPT),
	('DNSx', '', NAMESERVERS),
)


# Template for interface cfg on Deb
IFCFG_PHY_DEBIAN = (
	('iface', 'name', DEBNMMODE),
	('mtu', 'mtu', OPT),
#	('hwaddress', 'ethernet_mac_address', OPT),
#	('address', 'no', MAYBEDHCP)
)

# Template for bond interface cfg on Deb
IFCFG_BOND_DEBIAN = (
	('iface', 'id', DEBNMMODE),
	('mtu', 'mtu', OPT),
	('hwaddress', 'ethernet_mac_address', OPT),
	('bond-slaves', 'no', BONDSLAVES),
	('bond-opts', 'no', BONDMODOPTS)
)
# Template for vlans
IFCFG_VLAN_DEBIAN = (
	('iface', 'name', DEBNMMODE),
	('mtu', 'mtu', OPT),
	('hwaddress', 'vlan_mac_address', OPT),
#	('address', 'no', MAYBEDHCP),
	('vlan_raw_device', 'vlan_link', BONDNM)
)

IFCFG_STATIC_DEBIAN = (
	('address', 'ip_address', MAND),
	('netmask', 'netmask', MAND),
	('gateway', 'gateway', OPT),
	('dns-nameservers', '', NAMESERVERS)
)

SFMT = "%s=%s\n"
#TODO: Check for other well-defined parameters (cloud-init? OpenStack standards)

if IS_DEB:
	IFCFG_PHY  = IFCFG_PHY_DEBIAN
	IFCFG_BOND = IFCFG_BOND_DEBIAN
	IFCFG_STAT = IFCFG_STATIC_DEBIAN
	IFCFG_VLAN = IFCFG_VLAN_DEBIAN
	SFMT = "\t%s %s\n"
elif IS_SUSE:
	IFCFG_PHY  = IFCFG_PHY_SUSE
	IFCFG_BOND = IFCFG_BOND_SUSE
	IFCFG_STAT = IFCFG_STATIC_SUSE
	IFCFG_VLAN = IFCFG_VLAN_SUSE
else:
	IFCFG_PHY  = IFCFG_PHY_REDHAT
	IFCFG_BOND = IFCFG_BOND_REDHAT
	IFCFG_STAT = IFCFG_STATIC_REDHAT
	IFCFG_VLAN = IFCFG_VLAN_REDHAT


def maybedhcp(dev):
	"return dhcp if dev is not a bond slave, none otherwise"
	global bond_slaves
	if dev in bond_slaves:
		return "none"
	else:
		return "dhcp"

if IS_DEB:
	BOND_TPL_OPTS = tuple([
		('bond_mode', "bond-mode %s"),
		('bond_xmit_hash_policy', "bond-xmit-hash-policy %s"),
		('bond_miimon', "bond-miimon %s"),
	])
	BSEP='\n\t'
else:
	BOND_TPL_OPTS = tuple([
		('bond_mode', "mode=%s"),
		('bond_xmit_hash_policy', "xmit_hash_policy=%s"),
		('bond_miimon', "miimon=%s"),
	])
	BSEP=' '

def bondmodopts(bjson):
	"transform json settings to bond module parameters"
	modpar=''
	for jopt, mopt in BOND_TPL_OPTS:
		try:
			val = bjson[jopt]
			if modpar:
				modpar += BSEP
			modpar += mopt % val
		except:
			pass
	if IS_DEB:
		return modpar
	else:
		return '"%s"' % modpar

def bondslavex(btpl):
	"output BONDING_SLAVEn=... lines (SUSE)"
	out=''
	no=0
	for name in btpl:
		out += "BONDING_SLAVE%i=%s\n" % (no, name)
		no += 1
	return out

def bondnm(iface):
	"derive bondN name from interfaceN string"
	if iface[:9] == "interface":
		return "bond%s" % iface[9:]
	else:
		return iface

def bondmaster(dev):
	"Find bond master from slave device name"
	global bond_map
	for bnm in bond_map.keys():
		if dev in bond_map[bnm]:
			return bnm
	return None

def nameservers(sjson):
	"Output nameserver settings from services section (unused)"
	out = ''
	dns = 0
	for svc in sjson:
		if svc["type"] == "dns":
			dns += 1
			if IS_DEB:
				out += " " + svc["address"]
			else:
				out += "DNS%i=%s\n" % (dns, svc["address"])
	if dns > 0:
		if not IS_DEB:
			out += "PEERDNS=yes\n"
		else:
			out = "\tdns-nameservers%s\n" % out
	return out

def bonddhcp(njson, sjson):
	"BOOTPROTO=dhcp or static config from network settings"
	#six.print_(njson)
	if njson["type"][-4:] == "dhcp":
		return "BOOTPROTO=dhcp\n"
	return process_template(IFCFG_STAT, njson, njson, sjson, False)

def vlanname(ljson):
	"return vlanNNN name"
	# TODO: Error handling
	return "vlan%s" % ljson["vlan_id"]

def ifname(ljson):
	"return iface name"
	tp = ljson["type"]
	if tp == "bond":
		return bondnm(ljson["id"])
	elif tp == "vlan":
		return vlanname(ljson)
	else:
		return ljson["id"]

def splist(ljson):
	"output space separated list"
	out =""
	for el in ljson:
		out += str(el) + " "
	return out

def debiface(ljson, njson, sjson):
	"generate interface first line incl. static network config if needed"
	nm = ifname(ljson)
	if nm in bond_slaves:
		return "auto %s\niface %s inet manual\n\tbond-master %s\n" % \
			(nm, nm, bondmaster(nm))
	elif njson and njson["type"] and njson["type"][-4:] == "dhcp":
		return "auto %s\niface %s inet dhcp\n" % (nm, nm)
	else:
		return "auto %s\niface %s inet static\n%s" % \
			(nm, nm, process_template(IFCFG_STAT, njson, njson, sjson, False))

def process_template(template, ljson, njson, sjson, note = True, nm = None):
	"Create ifcfg-* file from templates and json"
	out = ''
	if note:
		out += '#Note: File autogenerated by bms-network-setup.py from network_data.json\n'
	# Fill default name
	try:
		if not nm:
			nm = ljson["name"]
	except:
		pass
	# Find network of interface
	net = None
	try:
		link = ljson["id"]
		for nets in njson:
			if nets["link"] == link:
				net = nets
				break
	except:
		pass
	#six.print_("Device ID %s: network %s" % (link, net))
	for key, val, mode in template:
		if mode == HARD:
			out += SFMT % (key, val)
		elif mode == OPT or mode == MAND:
			try:
				jval = ljson[val]
				out += SFMT % (key, jval)
			except:
				if mode == MAND:
					LOG.error("Mandatory value %s not found for %s setting" % (val, key))
		elif mode == MAYBEDHCP:
			# TODO: Error handling
			out += SFMT % (key, maybedhcp(nm))
		elif mode == BONDMODOPTS:
			if IS_DEB:
				out += '\t' + bondmodopts(ljson) + '\n'
			else:
				out += SFMT % (key, bondmodopts(ljson))
		elif mode == BONDSLAVEX:
			# TODO: Error handling
			out += bondslavex(ljson["bond_links"])
		elif mode == BONDNM:
			# TODO: Error handling
			out += SFMT % (key, bondnm(ljson[val]))
		elif mode == BONDMASTER:
			master = bondmaster(nm)
			if master:
				out += SFMT % (key, master)
				out += "SLAVE=yes\n"
		elif mode == BONDDHCP:
			out += "%s" % bonddhcp(net, sjson)
		elif mode == NAMESERVERS:
			out += "%s" % nameservers(sjson)
		elif mode == VLANNAME:
			out += SFMT % (key, vlanname(ljson))
		elif mode == VLANNAME:
			out += SFMT % (key, vlanname(ljson))
		elif mode == DEBNMMODE:
			out += debiface(ljson, net, sjson)
		elif mode == BONDSLAVES:
			out += "\t%s %s\n\tbond-primary %s\n" % (key, splist(ljson["bond_links"]), 
				ljson["bond_links"][0])
		else:
			LOG.error("Unsupported template %i for %s/%s" % (mode, key, val))
	return out


def mount(dev, path):
	"mount filesystem on dev at path"
	cmd = 'mount -o ro %s %s' % (dev, path)
	return subprocess.call(cmd.split(" "))

def umount(path):
	"umount filesystem at path"
	cmd = 'umount %s' % path
	return subprocess.call(cmd.split(" "))


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
	if DEBUG:
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

def rename_if(old, new):
	# Change name of network interface using ip link set dev name
	six.print_("Rename %s -> %s" % (old, new), file=sys.stderr)
	#ljson["name"] = dev
	cmd1 = "ip link set dev %s down" % old
	cmd2 = "ip link set dev %s name %s" % (old, new)
	#cmd3 = "ip link set dev %s up" % new
	out = ""
	try:
		out = subprocess.check_output(cmd1.split(" "), stderr=subprocess.STDOUT)
		out = subprocess.check_output(cmd2.split(" "), stderr=subprocess.STDOUT)
	except:
		six.print_("FAIL: %s" % out, file=sys.stderr)


def fix_name(ljson, renameIF = True):
	"""Find real name of eth device with mac address and rename interface
	   If renameIF is not set, we will change the name in JSON instead."""
	nm = ljson["name"]
	mac = ljson["ethernet_mac_address"]
	if os.access("/sys/class/net/%s/address" % nm, os.R_OK):
		devmac = open("/sys/class/net/%s/address" % nm, "r").read().rstrip()
		if devmac == mac:
			return
	for dev in os.listdir("/sys/class/net/"):
		try:
			devmac = open("/sys/class/net/%s/address" % dev, "r").read().rstrip()
			if devmac == mac:
				if renameIF:
					rename_if(dev, nm)
				else:
					ljson["name"] = dev
				return
		except:
			pass


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
		six.print_("Not running on BMS, exiting", file=sys.stderr)
		sys.exit(0)
	for ljson in network_json["links"]:
		if ljson["type"] == "bond":
			bond_slaves += ljson["bond_links"]
			bond_map[bondnm(ljson["id"])] = ljson["bond_links"]
	if not bond_slaves:
		six.print_("No BMS bond devices configured, exiting", file=sys.stderr)
		sys.exit(0)

	six.print_("Set up bonding: %s" % bond_map, file=sys.stderr)
	sjson = {}
	njson = {}
	try:
		sjson = network_json["services"]
		njson = network_json["networks"]
	except:
		pass
	open("%s/is_bms" % CONFDIR, "w")
	#six.print_(network_json)
	for ljson in network_json["links"]:
		tp = ljson["type"]
		if tp == "phy":
			if not IS_SUSE and not IS_EULER:
				fix_name(ljson, True)
			else:
				fix_name(ljson, False)
		nm = ifname(ljson)
		if tp == "phy":
			IFCFG_TMPL = IFCFG_PHY
			PRE = "60-" if IS_DEB else ""
		elif tp == "bond":
			IFCFG_TMPL = IFCFG_BOND
			PRE = "61-" if IS_DEB else ""
		elif tp == "vlan":
			IFCFG_TMPL = IFCFG_VLAN
			PRE = "62-" if IS_DEB else ""
		else:
			six.print_("Unknown network type %s" % tp, file=sys.stderr)

		f = open("%s/%sifcfg-%s" % (NETCONFPATH, PRE, nm), "w")
		six.print_(process_template(IFCFG_TMPL, ljson, njson, sjson, True, nm), file=f)

# Entry point
if __name__ == "__main__":
	process_network_hw()
