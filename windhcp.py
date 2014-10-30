#!/usr/bin/python
#coding=utf-8
import paramiko
import sys
import os
import argparse
from netaddr import *
import pprint


class dhcpwin:
	def __init__(self):
		print ('sono in init')
		#	self.username = username
		#	self.password = password
		#	self.dhcpserver = dhcpserver
		#	self.current_time = time.time()
	
	def SSHconnection(self,dhcpserver,username,password):
		global ssh
		#dichiarazione variabili
		ssh = paramiko.SSHClient()
		#Accetta sempre le chiavi host sconosciute
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		#print "Eseguo connessione SSH"
		ssh.connect(dhcpserver,22,username,password)
		return ssh

	def SSHclose():
		ssh.close()

	def GETScopes(self):
		#print "Eseguo GETdhcpScopes"
		#id della rete dello scope
		get_scopes = 'netsh dhcp server show scope'
		i=0
		#dichiara le liste (vettori)
		net_id_list = []
		netmask_list = []
		state_list = []
		scope_name_list = []
		comment_list = []
		stdin, stdout, stderr = ssh.exec_command(get_scopes)
		for line in stdout.read().splitlines():
			#prende solo le righe con gli scope Active
			if '-Active' in line:
				#splitta in colonne con delimitazione -			
				(net_id, netmask, state, scope_name, comment) = line.split(' -')
				#inserisce i valori delle singole righe nella lista e pulisce le variabili togliendo i whitespace a destra ed a sinistra (.strip)
				net_id = net_id.strip()
				netmask = netmask.strip()
				state = state.strip()
				scope_name = scope_name.strip()
				comment = comment.strip()
				#inserisce il valore pulito nella lista (.append)
				net_id_list.append(net_id)
				netmask_list.append(netmask)
				state_list.append(state)
				scope_name_list.append(scope_name)
				comment_list.append(comment)
				print net_id


	def GETdhcpRanges(self, netid):
		get_ranges = 'netsh dhcp server scope ' + netid + ' show iprange'
		stdin, stdout, stderr = ssh.exec_command(get_ranges)
		for line in stdout.read().splitlines():
		#prende solo le righe con i -
			if '-' in line:
				#prende le righe con i punti (solo quelle con indirizzi ip)
				if '.' in line:
					(start_range_ip, end_range_ip , range_type) = line.split(' - ')
					start_range_ip = start_range_ip.strip()
					end_range_ip = end_range_ip.strip()
					range_type = range_type.strip()
					print (start_range_ip , end_range_ip)

	def GETexclusions(self, netid):
		get_exclusions = 'netsh dhcp server scope ' + netid + ' show excluderange'
		stdin, stdout, stderr = ssh.exec_command(get_exclusions)
		for line in stdout.read().splitlines():
			#prende solo le righe con i -
			if '-' in line:
				#prende le righe con i punti (solo quelle con indirizzi ip)
				if '.' in line:
					(start_ex_ip, end_ex_ip) = line.split(' - ')
					start_ex_ip = start_ex_ip.strip()
					end_ex_ip = end_ex_ip.strip()
					print (start_ex_ip, end_ex_ip)	
	
	def GETclients(self, netid):
		get_clients = 'netsh dhcp server scope ' + netid + ' show clients'
		stdin, stdout, stderr = ssh.exec_command(get_clients)
		client_list = []
		netmask_list = []
		client_mac_list = []
		expiration_list = []
		client_type_list = []
		i = 0
		for line in stdout.read().splitlines():
			#prende solo le righe con i -
			if '-' in line:
				#prende le righe con i punti (solo quelle con indirizzi ip)
					if '.' in line:
						(client_ip, netmask, client_mac, expiration, client_type ) = line.split(' -')
						client_list.append(client_ip.strip())
						netmask_list.append(netmask.strip())
						client_mac_list.append(client_mac.strip())
						expiration_list.append(expiration.strip())
						client_type_list.append(client_type.strip())
						#print (client_list[i] + ' ' + netmask_list[i] + ' ' + client_mac_list[i] + ' ' + expiration_list[i] + ' ' + client_type_list[i])
						i = i + 1
		return client_list
		return netmask_list
		return client_mac_list
		return expiration_list

	def GETfreehosts(self, netid):
		client_list = dhcpwin.GETclients(netid)
		#print client_list[0]
		get_scopes = 'netsh dhcp server show scope'
		stdin, stdout, stderr = ssh.exec_command(get_scopes)
		i = 0
		r = 0
		for line in stdout.read().splitlines():
			#prende solo le righe con gli scope Active
			if '-Active' in line:
				#splitta in colonne con delimitazione -			
				(net_id, netmask, state, scope_name, comment) = line.split(' -')
				net_id = net_id.strip()
				netmask = netmask.strip()
				if netid in net_id:
					netmask = IPAddress(netmask)#converto netmask in un valore di tipo IPAddress per lavorarci
					CIDR=netmask.bits().count('1')#somma gli 1 del vaolre in bits del netmask per ottenere il CIDR della subnet selezionata
					CIDR=str(CIDR) # setta cidr come stringa sennò si arrabbia
					#network = IPNetwork ( check_net_id + '/' + CIDR ) #setta network come tipo IP 
					for ip in IPNetwork( netid + '/' + CIDR ).iter_hosts():
						ip = str(ip)
						if ip in client_list:
							#print ( ip + ' is present ' + ip)
							r = r + 1
						else:
							print ( ip + ' is not present ' + ip)
							i = i + 1
		print ('there are %s free ip') % i
		print ('there are %s occupied ip') % r

	def ADDdhcpentry(self,netid,ip_addr,mac_addr,description):
		add_reservation = 'netsh dhcp server scope ' + netid + ' add reservedip ' + ip_addr + ' ' + mac_addr + ' ' + description + ' ' +description
		stdin, stdout, stderr = ssh.exec_command(add_reservation)
		for line in stdout.read().splitlines():
			print line
		

	def DELETEdhcpentry(self,netid,ip_addr,mac_addr):
		delete_entry = 'netsh dhcp server scope ' + netid + ' delete reservedip ' + ip_addr + ' ' + mac_addr 
		stdin, stdout, stderr = ssh.exec_command(delete_entry)
		for line in stdout.read().splitlines():
			print line
		
		

	
if __name__ == "__main__":
	# parse arguments
	parser = argparse.ArgumentParser(description = "Get information from a Windows DHCP Server.")

	subparsers = parser.add_subparsers()

	parser_scopes = subparsers.add_parser('scopes', help='Get the active scopes from the DHCP server')
	parser_scopes.add_argument('dhcpserver',type=str, help='Hostname or IP Address of the DHCP server')
	parser_scopes.add_argument("username",type=str, help="Username for the SSH Connection")
	parser_scopes.add_argument("password",type=str, help="Password for the SSH Connection")
	parser_scopes.set_defaults(which='scopes')

	parser_exclusions = subparsers.add_parser ('exclusions', help='Get the exclusions')
	parser_exclusions.add_argument('dhcpserver',type=str, help='Hostname or IP Address of the DHCP server')
	parser_exclusions.add_argument("username",type=str, help="Username for the SSH Connection")
	parser_exclusions.add_argument("password",type=str, help="Password for the SSH Connection")
	parser_exclusions.add_argument("netid", type=str, help="The scope to inspect (eg. 192.168.1.0)")
	parser_exclusions.set_defaults(which='exclusions')

	parser_range = subparsers.add_parser ('ranges', help='Get the ranges')
	parser_range.add_argument('dhcpserver',type=str, help='Hostname or IP Address of the DHCP server')
	parser_range.add_argument("username",type=str, help="Username for the SSH Connection")
	parser_range.add_argument("password",type=str, help="Password for the SSH Connection")
	parser_range.add_argument("netid", type=str, help="The scope to inspect (eg. 192.168.1.0)")
	parser_range.set_defaults(which='range')

	parser_clients = subparsers.add_parser ('clients', help='Get the registered clients in the scope')
	parser_clients.add_argument('dhcpserver',type=str, help='Hostname or IP Address of the DHCP server')
	parser_clients.add_argument("username",type=str, help="Username for the SSH Connection")
	parser_clients.add_argument("password",type=str, help="Password for the SSH Connection")
	parser_clients.add_argument("netid", type=str, help="The scope to inspect (eg. 192.168.1.0)")
	parser_clients.set_defaults(which='clients')	

	parser_free = subparsers.add_parser ('free', help='Get a list of IPs not allocated in the specified scope')
	parser_free.add_argument('dhcpserver',type=str, help='Hostname or IP Address of the DHCP server')
	parser_free.add_argument("username",type=str, help="Username for the SSH Connection")
	parser_free.add_argument("password",type=str, help="Password for the SSH Connection")
	parser_free.add_argument("netid", type=str, help="The scope to inspect (eg. 192.168.1.0)")
	parser_free.set_defaults(which='free')

	parser_delete = subparsers.add_parser ('delete', help='Delete an IP Address in the scope')
	parser_delete.add_argument('dhcpserver',type=str, help='Hostname or IP Address of the DHCP server')
	parser_delete.add_argument("username",type=str, help="Username for the SSH Connection")
	parser_delete.add_argument("password",type=str, help="Password for the SSH Connection")
	parser_delete.add_argument("netid", type=str, help="The scope to work with (eg. 192.168.1.0)")
	parser_delete.add_argument("ip_addr",type=str, help="IP Address of the host to delete from the scope")
	parser_delete.add_argument("mac_addr",type=str, help="MAC Address of the host to delete from the scope")
	parser_delete.set_defaults(which='delete')
	
	parser_add = subparsers.add_parser ('add', help='Add an IP Address in the scope')
	parser_add.add_argument('dhcpserver',type=str, help='Hostname or IP Address of the DHCP server')
	parser_add.add_argument("username",type=str, help="Username for the SSH Connection")
	parser_add.add_argument("password",type=str, help="Password for the SSH Connection")
	parser_add.add_argument("netid", type=str, help="The scope to work with (eg. 192.168.1.0)")
	parser_add.add_argument("ip_addr",type=str, help="IP Address of the host to add to the scope")
	parser_add.add_argument("mac_addr",type=str, help="MAC Address of the host to add to the scope")
	parser_add.add_argument("description",type=str, help="Description of the host to add to the scope")
	parser_add.set_defaults(which='add')

	args = parser.parse_args()
	if args.which is 'scopes':
		dhcpwin=dhcpwin()
		dhcpwin.SSHconnection(args.dhcpserver,args.username,args.password)
		dhcpwin.GETScopes(args.dhcpserver)
		dhcpwin.SSHclose
	else:
		if args.which is 'exclusions':
			dhcpwin=dhcpwin()
			dhcpwin.SSHconnection(args.dhcpserver,args.username,args.password)
			dhcpwin.GETexclusions(args.dhcpserver,args.netid)
			dhcpwin.SSHclose
		else:
			if args.which is 'ranges':
				dhcpwin=dhcpwin()
				dhcpwin.SSHconnection(args.dhcpserver,args.username,args.password)
				dhcpwin.GETdhcpRanges(args.dhcpserver,args.netid)
				dhcpwin.SSHclose
			else:
				if args.which is 'clients':
					dhcpwin=dhcpwin()
					dhcpwin.SSHconnection(args.dhcpserver,args.username,args.password)
					dhcpwin.GETclients(args.dhcpserver,args.netid)
					dhcpwin.SSHclose
				else:
					if args.which is 'free':
						dhcpwin=dhcpwin()
						dhcpwin.SSHconnection(args.dhcpserver,args.username,args.password)				
						dhcpwin.GETfreehosts(args.dhcpserver,args.netid)
						dhcpwin.SSHclose
					else:
						if args.which is 'delete':
							dhcpwin=dhcpwin()
							dhcpwin.SSHconnection(args.dhcpserver,args.username,args.password)
							dhcpwin.DELETEdhcpentry(args.dhcpserver,args.netid,args.ip_addr,args.mac_addr)
							dhcpwin.SSHclose
						else:
							if args.which is 'add':
								dhcpwin=dhcpwin()
								dhcpwin.SSHconnection(args.dhcpserver,args.username,args.password)
								dhcpwin.GETclients(args.dhcpserver,args.netid)
								dhcpwin.ADDdhcpentry(args.dhcpserver,args.netid,args.ip_addr,args.mac_addr,args.description)
								dhcpwin.SSHclose
	
