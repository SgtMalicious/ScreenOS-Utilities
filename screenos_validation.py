#!/usr/bin/env python
#
# Copyright (c) 2011 William Allison
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Script for validating ScreenOS configuration file.
# 	Finds duplicate address book entries with identical networks or names
# 	Finds unused address book entries
# 	Finds address book entries with hostnames that don't resolve

import sys
import re
from struct import unpack
from socket import inet_aton, gethostbyname

class screenService(object):
	"""Class for a Screen OS Service or Group Service Entry"""
	def __init__(self,name=None):
		if name == None:
			raise ValueError,"missing service name"

		self.name = name
		self.policies = []
		self.groups = []
		self.is_group = False

	def add_policy(self,policy_id = None):
		if policy_id == None:
			raise ValueError,"no policy id given"

		if policy_id in self.policies:
			return

		self.policies.append(policy_id)

	def get_policies(self):
		return self.policies

	def is_group(self):
		return self.is_group

	def set_group(self):
		self.is_group = True

	def add_group(self,name=None):
		if self.is_group:
			return

		if name in self.groups:
			return

		self.groups.append(name)

	def get_groups(self):
		return self.groups


class screenPolicy(object):
	"""Class for a Screen OS Policy"""
	def __init__(self,id=None,src_zone=None,dst_zone=None):
		if id == None or src_zone == None or dst_zone == None:
				raise ValueError,"missing policy information"

		self.id = id
		self.src_zone = src_zone
		self.dst_zone = dst_zone

class screenGroup(object):
	"""Class for a Screen OS Group Address Entry"""
	def __init__(self,name = None,zone = None):
		if name == None or zone == None:
			raise ValueError,"missing initialization value"

		self.name = name
		self.zone = zone

		self.duplicate = False

		self.policies = []

	def add_policy(self,policy_id = None):
		if policy_id == None:
			raise ValueError,"no policy id given"

		if policy_id in self.policies:
			return

		self.policies.append(policy_id)

	def get_policies(self):
		return self.policies

	def set_duplicate(self):
		self.duplicate = True

class screenAddress(screenGroup):
	"""Class for Screen OS Address Entry"""

	def __init__(self,name = None,zone = None,ipv4_addr = None,ipv4_mask = None,description = None):
		super(screenAddress,self).__init__(name,zone)
		if ipv4_addr == None or ipv4_mask == None:
			raise ValueError,"missing initialization value"

		self.ip = ipv4_addr
		self.mask = ipv4_mask

		self.hostname = None

		self.has_clone = False
		self.clone = None


		try:
			self.raw_ip = unpack("!L",inet_aton(self.ip))[0]
			self.raw_mask = unpack("!L",inet_aton(self.mask))[0]
			self.network = self.raw_ip & self.raw_mask
		except IOError,e:
			self.hostname = ipv4_addr # this address entry is DNS resolved

		self.description = description

		self.groups = []

	def add_group(self,group_name = None):
		if group_name == None:
			raise ValueError,"no group name given"

		if group_name in self.groups:
			return

		self.groups.append(group_name)

	def get_sizes(self):
		return [len(self.policies),len(self.groups)]

	def get_groups(self):
		return self.groups

	def in_my_network(self,ip):
		if self.hostname == None:
			return ip & self.raw_mask == self.network

	def in_your_network(self,network,mask):
		if self.hostname == None:
			return self.raw_ip & mask == network

	def set_clone(self,clone):
		self.has_clone = True
		self.clone = clone


def mark_duplicate_addresses(addresses = []):
	for entry_a in addresses:
		if isinstance(entry_a,screenAddress):
			for entry_b in addresses:
				if isinstance(entry_b,screenAddress):
					if entry_a is entry_b or entry_a is entry_b.clone:
						continue
					try:
						if entry_a.network == entry_b.network:
							entry_a.set_clone(entry_b)
					except:
						pass

def mark_duplicate_names(zone_dict = {}):
	zone_list = zone_dict.keys()
	# zone to zone comparisons
	for i in range(0,len(zone_list)):
		addr_list = zone_dict[zone_list[i]].keys()
		for n in range(0,len(zone_list)):
			if not n == i:
				for name in zone_dict[zone_list[n]].keys():
					if name in addr_list:
						zone_dict[zone_list[n]][name].set_duplicate()

def validate_entry(entry = None):
	if len(entry.get_policies()) == 0:
		if isinstance(entry,screenAddress):
			if len(entry.get_groups()) == 0:
				unused_entries.append(entry)
			elif not [ len(zone_dict[entry.zone][x].get_policies()) for x in entry.get_groups() ][0] > 0:
				unused_entries.append(entry)
		else:
			unused_entries.append(entry)

	if entry.duplicate:
		dupe_names.append(entry)

	if isinstance(entry,screenAddress) and entry.has_clone:
		dupe_networks.append(entry)

	if isinstance(entry,screenAddress) and not entry.hostname == None:
		try:
			gethostbyname(entry.hostname)
		except:
			nodns_entries.append(entry)

def validate_service(service = None):
	if len(service.get_policies()) == 0:
		if service.is_group:
			unused_services.append(service)
		elif len(service.get_groups()) == 0:
			unused_services.append(service)
		elif not [ len(service_dict[x].get_policies()) for x in service.get_groups() ][0] > 0:
			unused_services.append(service)

def print_results(type = 0, entries = [], title = ""):
	print """
===========================================================================================================================================================================================================================================
%s (Total %d)
===========================================================================================================================================================================================================================================
""" % (title,len(entries))

	if type == 1 and len(entries):
		print "%-55s %-20s %-15s %-15s   %-55s %-20s %-15s %-15s" % ("Name","Zone","IP","Mask","Name","Zone","IP","Mask")
		print "___________________________________________________________________________________________________________________________________________________________________________________________________________________________________________"
		for entry in entries:
			print "%-55s %-20s %-15s %-15s %s %-55s %-20s %-15s %-15s %s" % (entry.name,entry.zone,entry.ip,entry.mask,"+" if entry.duplicate else "-",entry.clone.name,entry.clone.zone,entry.clone.ip,entry.clone.mask,"+" if entry.clone.duplicate else "-")

	elif type == 2 and len(entries):
		print "%-55s %-20s %-15s" % ("Name","Zone","IP")
		print "__________________________________________________________________________________________"
		for entry in entries:
			if isinstance(entry,screenAddress):
				print "%-55s %-20s %-15s" % (entry.name,entry.zone,entry.ip)
			else:
				print "%-55s %-20s %-15s" % (entry.name,entry.zone,"N/A")

	elif type == 3 and len(entries):
		print "%-55s %-20s %-15s" % ("Name","Zone","Type")
		print "__________________________________________________________________________________________"
		for entry in entries:
			print "%-55s %-20s %-15s" % (entry.name,entry.zone,"Address" if isinstance(entry,screenAddress) else "Group")

	elif type == 4 and len(entries):
		print "%-55s %-20s %-15s" % ("Name","Zone","Hostname")
		print "__________________________________________________________________________________________"
		for entry in entries:
			if isinstance(entry,screenAddress):
				print "%-55s %-20s %-15s" % (entry.name,entry.zone,entry.hostname)

	elif type == 5 and len(entries):
		print "%-55s %-15s" % ("Name","Type")
		print "__________________________________________________________________________________________"
		for entry in entries:
			print "%-55s %-15s" % (entry.name,"Group" if (entry.is_group) else "Service")


if __name__ == '__main__':

	if len(sys.argv) != 2:
		sys.stderr.write("Usage: %s <screenos config>\n" % sys.argv[0])
		sys.exit(1)

	config = []
	zone_dict = {} # contains dictionaries of zones containing dictionaries of addresses
	policy_dict = {} # container for policy information
	service_dict = {} # container for service information

	dupe_names = []
	dupe_networks = []
	unused_entries = []
	unused_services = []
	nodns_entries = []

	address_regex = re.compile('^set address "(.*?)" "(.*?)" (.*?) (.*?)(?: "(.*?)")?$')
	group_regex = re.compile('^set group address "(.*?)" "(.*?)" add "(.*?)"$')

	policy_regex_full = re.compile('^set policy(?: global)? id (\d+)(?: name "(.*?)")? from "(.*?)" to "(.*?)"\s+"(.*?)" "(.*?)" "(.*?)" (.*?) (.*?)$')
	policy_regex_begin = re.compile('^set policy id (\d+)(?: (disable))?$')
	policy_regex_part = re.compile('^set (.*?) "(.*?)"$')

	service_regex = re.compile('^set service "(.*?)" .*?$')
	service_group_regex = re.compile('^set group service "(.*?)" add "(.*?)"$')

	sys.stdout.write("Loading configuration...")
	
	try:
		fd = open(sys.argv[1],'r')
		for line in fd.readlines():
			config.append(line[:-2]) # specific to the configuration item "set admin format dos", -1 otherwise...
		fd.close()
	except:
		sys.stderr.write("FATAL: unable to open file %s\n" % sys.argv[1] )
		sys.exit(1)


	config_iter = iter(config)
	for line in config_iter:
		# marks the beginning of a user-defined service entry
		x = service_regex.split(line)[1:-1]
		if len(x):
			service = screenService(x[0])

			if not service_dict.has_key(service.name):
				service_dict[service.name] = service

			continue

		# marks the beginning of a user-defined service group entry
		x = service_group_regex.split(line)[1:-1]
		if len(x):
			group_name = x[0]
			service_name = x[1]

			if service_dict.has_key(group_name):
				group = service_dict[group_name]
			else:
				group = screenService(group_name)
				group.set_group()
				service_dict[group_name] = group

			# add group to existing user-defined service entry
			if service_dict.has_key(service_name):
				service_dict[service_name].add_group(group_name)

			continue

		# marks the beginning of an address book entry
		x = address_regex.split(line)[1:-1]
		if len(x):
			zone = x[0]
			addr = screenAddress(x[1],x[0],x[2],x[3],x[4])

			if not zone_dict.has_key(zone):
				zone_dict[zone] = {}

			zone_entries = zone_dict[zone]

			# check for duplicate names in the same zone, this should never happen
			if zone_entries.has_key(addr.name):
				sys.stderr.write("Duplicate address entry detected: %-28s (%s/%s) -> (%s/%s)\n" % (addr.name,addr.zone,addr.ip,zone_entries[addr.name].zone,zone_entries[addr.name].ip))
				continue

			zone_entries[addr.name] = addr
			continue

		# marks the beginning of a group address book entry
		x = group_regex.split(line)[1:-1]
		if len(x):
			zone = x[0]
			addrname = x[2]
			group = screenGroup(x[1],x[0])

			if not zone_dict.has_key(zone):
				zone_dict[zone] = {}

			zone_entries = zone_dict[zone]

			if not zone_entries.has_key(group.name):
				zone_entries[group.name] = group

			# check that an address entry already exist, this should always be the case
			if not zone_entries.has_key(addrname):
				sys.stderr.write("Missing address entry in group detected: %-28s (%s) %s\n" % (group.name,group.zone,addrname))
			else:
				if isinstance(zone_entries[addrname],screenAddress):
					zone_entries[addrname].add_group(group.name)
				else:
					sys.stderr.write("Detected a nested address group: %s nested in %s\n" % (addrname,group.name))

			continue

		# marks the beginning of a complete policy line statement
		x = policy_regex_full.split(line)[1:-1] 
		if len(x):
			policy = screenPolicy(x[0],x[2],x[3])
			if policy_dict.has_key(policy.id):
				sys.stderr.write("Duplicate policy id entry detected: %s\n" % policy.id)
				continue

			# add policy to existing user-defined service entry
			if service_dict.has_key(x[6]):
				service_dict[x[6]].add_policy(policy.id)

			policy_dict[policy.id] = policy
			# ignore any policy addresses that refer to non-address entries
			if x[4][:3] not in ['Any','MIP','VIP']:
				zone_dict[policy.src_zone][x[4]].add_policy(policy.id)
			if x[5][:3] not in ['Any','MIP','VIP']:
				zone_dict[policy.dst_zone][x[5]].add_policy(policy.id)
			continue

		# marks the beginning of a policy statement with extra configuration items
		x = policy_regex_begin.split(line)[1:-1]
		if len(x): 
			id = x[0]
			# get the next line to finish processing until 'exit' is found indicating the end of this policy configuation
			policy_line = config_iter.next()
			while policy_line != 'exit':
				y = policy_regex_part.split(policy_line)[1:-1]
				if len(y) and y[1][:3] != 'MIP':
					if y[0] == 'src-address':
						zone_dict[policy_dict[id].src_zone][y[1]].add_policy(id)
					elif y[0] == 'dst-address':
						zone_dict[policy_dict[id].dst_zone][y[1]].add_policy(id)
					elif y[0] == 'service':
						if service_dict.has_key(y[1]):
							service_dict[y[1]].add_policy(id)

				policy_line = config_iter.next()

	sys.stdout.write("loaded.\nMarking duplicate entries...")
	sys.stdout.flush()
	mark_duplicate_names(zone_dict)
	mark_duplicate_addresses([ item for sublist in [zone_dict[x].values() for x in zone_dict.keys()] for item in sublist])

	sys.stdout.write("complete.\nValidating entries...")
	sys.stdout.flush()
	for entry in [ item for sublist in [zone_dict[x].values() for x in zone_dict.keys()] for item in sublist]:
		validate_entry(entry)

	sys.stdout.write("complete.\nValidating services...")
	sys.stdout.flush()
	for service in service_dict.values():
		validate_service(service)

	dupe_names.sort()
	dupe_networks.sort()
	unused_entries.sort()
	unused_services.sort()
	sys.stdout.write("complete.\nPrinting results:\n\n")
	sys.stdout.flush()

	print_results(1,dupe_networks,"Duplicate Networks")
	print_results(2,dupe_names,"Duplicate Address Names")
	print_results(3,unused_entries,"Unreferenced Group/Address Book Entries")
	print_results(4,nodns_entries,"DNS Unresolvable Address Book Entries")
	print_results(5,unused_services,"Unreferenced Service Entries")
