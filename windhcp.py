#!/usr/bin/python
#coding=utf-8
import paramiko
import sys
import os
import argparse
from netaddr import *
import pprint

class windhcp:
	
	def SSHconnection(self,dhcpserver,username,password):
		#dichiarazione variabili
		ssh = paramiko.SSHClient()
		#Accetta sempre le chiavi host sconosciute
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		#print "Eseguo connessione SSH"
		ssh.connect(dhcpserver,22,username,password)
		return ssh

	def SSHclose():
		ssh.close()

	def GETscopes(self,dhcpserver):
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
				#(net_id[1:10], netmask[11:20], state[21:30], scope_name[31:40],comment[40:50]) = line.split()
				net_id=line[1:16]
				netmask=line[18:33]
				state=line[34:48]
				scope_name=line[49:70]
				comment=line[71:90]
				#pulisce le variabili togliendo i whitespace a destra ed a sinistra (.strip)
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
		#print net_id_list
		return (net_id_list, netmask_list, state_list, scope_name_list, comment_list)

	def GETdhcpRanges(self, dhcpserver, netid):
		start_range_ip_list = []
		end_range_ip_list = []
		range_type_list = []
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
					start_range_ip_list.append(start_range_ip)
					end_range_ip_list.append(end_range_ip)
					range_type_list.append(range_type)
					print (start_range_ip , end_range_ip)
		return (start_range_ip_list, end_range_ip_list, range_type_list)

	def GETexclusions(self, dhcpserver, netid):
		start_ex_ip_list = []
		end_ex_ip_list = []
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
					start_ex_ip_list.append(start_ex_ip)
					end_ex_ip_list.append(end_ex_ip)
					print (start_ex_ip, end_ex_ip)
		return (start_ex_ip_list, end_ex_ip_list)
	
	def GETclients(self, dhcpserver, netid):
		get_clients = 'netsh dhcp server scope ' + netid + ' show clients'
		stdin, stdout, stderr = ssh.exec_command(get_clients)
		client_ip_list = []
		netmask_list = []
		client_mac_list = []
		expiration_list = []
		client_type_list = []
		for line in stdout.read().splitlines():
			#prende solo le righe con i -
			if '-' in line:
				#prende le righe con i punti (solo quelle con indirizzi ip)
				if '.' in line:
					(client_ip, netmask, client_mac, expiration, client_type ) = line.split(' -')
					client_ip = client_ip.strip()
					netmask = netmask.strip()
					client_mac = client_mac.strip()
					expiration = expiration.strip()
					client_type = client_type.strip()
					client_ip_list.append(client_ip)
					netmask_list.append(netmask)
					client_mac_list.append(client_mac)
					expiration_list.append(expiration)
					client_type_list.append(client_type)
		return (client_ip_list, netmask_list, client_mac_list, expiration_list, client_type_list)

	def GETfreehosts(self, dhcpserver, netid):
		free_ip_list = []
		occupied_ip_list = []
		client_ip_list, netmask_list, client_mac_list, expiration_list, client_type_list = windhcp.GETclients( dhcpserver, netid)
		#print client_list[0]
		net_id_list, netmask_list, state_list, scope_name_list, comment_list = windhcp.GETscopes(dhcpserver)
		i = 0
		r = 0
		match=net_id_list.index(netid)
		netmask = IPAddress(netmask_list[match])#converto netmask in un valore di tipo IPAddress per lavorarci
		CIDR=netmask.bits().count('1')#somma gli 1 del vaolre in bits del netmask per ottenere il CIDR della subnet selezionata
		CIDR=str(CIDR) # setta cidr come stringa sennò si arrabbia
		#network = IPNetwork ( check_net_id + '/' + CIDR ) #setta network come tipo IP 
		for ip in IPNetwork( netid + '/' + CIDR ).iter_hosts():
			ip = str(ip)
			try :
				match = client_ip_list.index(ip)
				occupied_ip_list.append(client_ip_list[match])
				r = r + 1
			except:
				free_ip_list.append(ip)
				i = i + 1
		#print occupied_ip_list
		#print free_ip_list
		print ('there are %s free ip') % i
		print ('there are %s occupied ip') % r
		return (occupied_ip_list, free_ip_list)
		

	def ADDdhcpentry(self,dhcpserver,netid,ip_addr,mac_addr,description):
		add_reservation = 'netsh dhcp server scope ' + netid + ' add reservedip ' + ip_addr + ' ' + mac_addr + ' ' + description + ' ' +description
		stdin, stdout, stderr = ssh.exec_command(add_reservation)
		for line in stdout.read().splitlines():
			print line
	def DELETEdhcpentry(self,dhcpserver,netid,ip_addr,mac_addr):
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
		windhcp=windhcp()
		ssh = windhcp.SSHconnection(args.dhcpserver,args.username,args.password)
		windhcp.GETscopes(args.dhcpserver)
		windhcp.SSHclose
	elif args.which is 'exclusions':
		windhcp=windhcp()
		ssh = windhcp.SSHconnection(args.dhcpserver,args.username,args.password)
		windhcp.GETexclusions(args.dhcpserver,args.netid)
		windhcp.SSHclose
	elif args.which is 'ranges':
		windhcp=windhcp()
		ssh = windhcp.SSHconnection(args.dhcpserver,args.username,args.password)
		windhcp.GETdhcpRanges(args.dhcpserver,args.netid)
		windhcp.SSHclose
	elif args.which is 'clients':
		windhcp=windhcp()
		ssh = windhcp.SSHconnection(args.dhcpserver,args.username,args.password)
		windhcp.GETclients(args.dhcpserver,args.netid)
		windhcp.SSHclose
	elif args.which is 'free':
		windhcp=windhcp()
		ssh = windhcp.SSHconnection(args.dhcpserver,args.username,args.password)				
		windhcp.GETfreehosts(args.dhcpserver,args.netid)
		windhcp.SSHclose
	elif args.which is 'delete':
		windhcp=windhcp()
		ssh = windhcp.SSHconnection(args.dhcpserver,args.username,args.password)
		windhcp.DELETEdhcpentry(args.dhcpserver,args.netid,args.ip_addr,args.mac_addr)
		windhcp.SSHclose
	elif args.which is 'add':
		windhcp=windhcp()
		ssh = windhcp.SSHconnection(args.dhcpserver,args.username,args.password)
		windhcp.GETclients(args.dhcpserver,args.netid)
		windhcp.ADDdhcpentry(args.dhcpserver,args.netid,args.ip_addr,args.mac_addr,args.description)
		windhcp.SSHclose

