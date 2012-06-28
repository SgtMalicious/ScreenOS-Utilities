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
# Script for viewing ScreenOS policies from an offline configuration file.

import sys
import re
from struct import unpack
from socket import inet_aton, gethostbyname
from datetime import datetime

try:
	from ordereddict import OrderedDict
except ImportError:
	sys.stderr.write("Unable to import OrderedDict collection class.\n")
	sys.exit(1)

class screenPolicy(object):
	"""Class for a Screen OS Policy"""
	def __init__(self,id=None,name=None,src_zone=None,dst_zone=None):
		if id == None or src_zone == None or dst_zone == None:
				raise ValueError,"missing policy information"

		self.id = id
		self.src_zone = src_zone
		self.dst_zone = dst_zone

		self.log = False
		self.count = False
		self.sb = True
		self.webauth = False
		self.nat = ""
		self.name = name

		self.action = ""

		self.disabled = False
		self.config = []

		self.src_addr = []
		self.dst_addr = []
		self.svc = []

	def set_nat(self,type):
		self.nat = type.upper()

	def set_action(self,action):
		self.action = action.capitalize()

	def add_svc(self,service):
		self.svc.append(service)

	def add_src(self,addr):
		self.src_addr.append(addr)

	def add_dst(self,addr):
		self.dst_addr.append(addr)

	def set_count(self):
		self.count = True
	
	def set_log(self):
		self.log = True
	
	def set_nosb(self):
		self.sb = False

	def set_webauth(self):
		self.webauth = True
	
	def get_config(self):
		return self.config

	def push_config(self,line=None):
		if line == None:
				raise ValueError,"missing policy information"

		self.config.append(line)

	def set_disable(self):
		self.disabled = True

def print_policy(policies=[]):
	print "[1;34m%5s %-15s %-15s %-25s %-25s %-15s %-15s %-12s %s %s[m" % ("ID","From","To","Src-address","Dst-address","Service","Action","State","ASTLCB","NAT")
	for p in policies:
		print "%5s %-15s %-15s %-25s %-25s %-15s %-15s %-20s ---%s%s%s  %s" % (p.id,p.src_zone[0:15],p.dst_zone[0:15],p.src_addr[0][0:25],p.dst_addr[0][0:25],p.svc[0][0:15],p.action,"[31mdisabled[m" if p.disabled else "[32menabled[m","X" if p.log else "-","X" if p.count else "-","X" if p.sb else "-",p.nat)
		
		array_max = max(len(p.src_addr),len(p.dst_addr),len(p.svc))
		if len(p.src_addr) < array_max:
			p.src_addr += [''] * (array_max - len(p.src_addr))
		if len(p.dst_addr) < array_max:
			p.dst_addr += [''] * (array_max - len(p.dst_addr))
		if len(p.svc) < array_max:
			p.svc += [''] * (array_max - len(p.svc))

		for i in range(1,array_max):
			print "%37s %-25s %-25s %-15s" % ('',p.src_addr[i][0:25],p.dst_addr[i][0:25],p.svc[i])


if __name__ == '__main__':

	if not len(sys.argv) >= 3:
		sys.stderr.write("Usage: %s <screenos config> [ <policy id> | <from zone> <to zone> ]\n" % sys.argv[0])
		sys.exit(1)

	config = []
	policy_dict = OrderedDict()

	policy_regex_full = re.compile('^set policy(?: global)? id (\d+)(?: name "(.*?)")? from "(.*?)" to "(.*?)"\s+"(.*?)" "(.*?)" "(.*?)" (.*?) (.*?)$')
	policy_regex_begin = re.compile('^set policy id (\d+)(?: (disable))?$')
	policy_regex_part = re.compile('^set (.*?) "(.*?)"$')

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
		# marks the beginning of a complete policy line statement
		# ['Id', 'Name', 'From-Zone', 'To-Zone"  "Src-Address', 'Dst-Address', 'Service', 'Action', 'Rest of line']
		x = policy_regex_full.split(line)[1:-1] 
		if len(x):
			policy = screenPolicy(x[0],x[1],x[2],x[3])
			policy.push_config(line)

			policy.add_src(x[4])
			policy.add_dst(x[5])
			policy.add_svc(x[6])
			policy.set_action(x[7])

			if policy.action.lower() == 'nat' and ( re.search('permit',x[8]) != None ):
				policy.set_action('permit')
				if re.search('dst',x[8]) != None:
					policy.set_nat('d')
				elif re.search('src',x[8]) != None:
					policy.set_nat('s')
			if re.search('log',x[8]) != None:
				policy.set_log()
			if re.search('count',x[8]) != None:
				policy.set_count()
			if re.search('no-session-backup',x[8]) != None:
				policy.set_nosb()
			if re.search('webauth',x[8]) != None:
				policy.set_webauth()
				policy.set_action(policy.action + "~")

			if policy_dict.has_key(policy.id):
				sys.stderr.write("Duplicate policy id entry detected: %s\n" % policy.id)
				continue

			policy_dict[policy.id] = policy
			continue

		# marks the beginning of a policy statement with extra configuration items
		# ['Id',None] 
		x = policy_regex_begin.split(line)[1:-1]
		if len(x): 
			id = x[0]
			if x[1] == "disable":
				policy_dict[id].set_disable()
				config_iter.next()
			policy_line = config_iter.next()
			while policy_line != 'exit':
				policy_dict[id].push_config(policy_line)
				# ['Item', 'Name']
				y = policy_regex_part.split(policy_line)[1:-1]
				if len(y):
					if y[0] == 'src-address':
						policy_dict[id].add_src(y[1])
					elif y[0] == 'dst-address':
						policy_dict[id].add_dst(y[1])
					elif y[0] == 'service':
						policy_dict[id].add_svc(y[1])

				policy_line = config_iter.next()

	# Print the saved config timestamp information. From Juniper KB19448.
	config_timestamp = datetime.fromtimestamp(852073200 + int(re.compile('.*? saved_cfg_timestamp:(\d+) ').split(config[0])[1:-1][0]))

	sys.stdout.write("comple. Configuration file dated: %s\n" % config_timestamp)

	if sys.argv[2].isdigit():	
		if policy_dict.has_key(sys.argv[2]):
			print_policy([policy_dict[sys.argv[2]],])
		else:
			sys.stderr.write("No such policy by that id: %s\n" % sys.argv[2])

	if len(sys.argv) == 4:
		policies = []
		for policy in policy_dict:
			if policy_dict[policy].src_zone.lower() == sys.argv[2].lower() and policy_dict[policy].dst_zone.lower() == sys.argv[3].lower():
				policies.append(policy_dict[policy])

		print_policy(policies)
