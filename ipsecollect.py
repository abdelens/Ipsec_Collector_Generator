import sys
import csv
import os
from linecache import getline

peers = []
psks =[]
ike_pol=[]
ike2_pol=[]
TS =[]
ipsec_prop=[]
peer_psk=[]
ikev='0'
i=0
#inputfile = input("Enter your vpn config file: ")
inputfile='config.txt'
f=open('output/'+inputfile.split(".")[0]+'_VPN.csv','w')
p=open('output/'+inputfile.split(".")[0]+'_ike.csv','w')
f.write("Partner"+";"+"ike version"+";"+"Peer primary"+";"+"Peer secondary"+";"+"Local PSK"+";"+"Remote PSK"+";"+"Prop P2"+";"+"P2 Lifetime"+";"+"PFS"+";"+"DH groupe"+";"+"Action"+";"+"Local Enc Domain"+";"+"Remote Enc Domain"+"\n")
with open ('input/'+inputfile, 'rt') as myfile:
		for ind,line in enumerate(myfile,1):
			if "crypto isakmp key" in line:
				ikev='1'
				if len(line.split()) == 6:
					peers.append(line.split()[5]+";"+ikev)
					psks.append(line.split()[3]+";"+line.split()[3])
				elif len(line.split()) == 7:
					peers.append(line.split()[6]+";"+ikev)
					psks.append(line.split()[4]+";"+line.split()[4])
			elif "crypto ikev2 keyring" in line:
				ikev='2'
				if (getline(myfile.name,ind+2).startswith('  ')):
					peers.append(getline(myfile.name,ind+2).split()[1]+";"+ikev)
					psks.append((getline(myfile.name,ind+3).split()[2])+";"+(getline(myfile.name,ind+4).split()[2]))
		for i in range(len(peers)):
			peer_psk.append(peers[i]+";"+psks[i])

with open ('input/'+inputfile, 'rt') as myfile:
		for ind,line in enumerate(myfile,1):
			if "crypto isakmp policy" in line:
				i=ind
				prop=[]
				hash=False
				auth=False
				lifetime=False
				#prop.append(getline(myfile.name,i).split()[3])
				while i < (ind+4):
					if "!" not in getline(myfile.name,i+1):
						if (getline(myfile.name,i+1).split()[0]) == "encr":
							prop.append("1")
							if len(getline(myfile.name,i+1).split()) == 3:
								prop.append((getline(myfile.name,i+1).split()[1])+"-"+(getline(myfile.name,i+1).split()[2]))
							else:
								prop.append(getline(myfile.name,i+1).split()[1])
						elif (getline(myfile.name,i+1).split()[0]) == "hash":
								prop.append((getline(myfile.name,i+1).split()[1]))
								hash=True
						elif (getline(myfile.name,i+1).split()[0]) == "authentication":
							if hash==True:
								prop.append((getline(myfile.name,i+1).split()[1]))
								auth=True
							else:
								prop.append("sha")
								prop.append((getline(myfile.name,i+1).split()[1]))
								auth=True
								hash=True
						elif (getline(myfile.name,i+1).split()[0]) == "group":
							if auth==True and hash == True:
								prop.append((getline(myfile.name,i+1).split()[1]))
							elif auth==False and hash == True:
								prop.append("pre-share")
								prop.append((getline(myfile.name,i+1).split()[1]))
							else:
								prop.append("sha")
								prop.append("pre-share")
								prop.append((getline(myfile.name,i+1).split()[1]))
						elif (getline(myfile.name,i+1).split()[0]) == "lifetime":
							prop.append((getline(myfile.name,i+1).split()[1]))
							lifetime=True

						i=i+1
					else:
						break
				if lifetime == False:
					prop.append("86400")
				if prop not in ike_pol:
					ike_pol.append(prop)
			elif "crypto ikev2 proposal" in line:
				i=ind
				prop2=[]
				while i < (ind+3):
					if (getline(myfile.name,i+1).split()[0]) == "encryption":
						#print(len(getline(myfile.name,i+1).split()),getline(myfile.name,i+1).split())
						prop2.append("2")
						prop2.append(getline(myfile.name,i+1).split()[1])
						k=2
						while k < len(getline(myfile.name,i+1).split()):
							prop2[1]=prop2[1]+" "+getline(myfile.name,i+1).split()[k]
							#prop2.append(getline(myfile.name,i+1).split()[k])
							k=k+1
					elif (getline(myfile.name,i+1).split()[0]) == "integrity":
						#print(len(getline(myfile.name,i+1).split()),getline(myfile.name,i+1).split())
						prop2.append(getline(myfile.name,i+1).split()[1])
						k=2
						while k < len(getline(myfile.name,i+1).split()):
							prop2[2]=prop2[2]+" "+getline(myfile.name,i+1).split()[k]
							#prop2.append(getline(myfile.name,i+1).split()[k])
							k=k+1
					elif (getline(myfile.name,i+1).split()[0]) == "group":
						#@print(len(getline(myfile.name,i+1).split()),getline(myfile.name,i+1).split())
						prop2.append("pre-share")
						prop2.append(getline(myfile.name,i+1).split()[1])
						k=2
						#print(len(getline(myfile.name,i+1).split()))
						while k < len(getline(myfile.name,i+1).split()):
							#print(getline(myfile.name,i+1).split()[k])
							prop2[4]=prop2[4]+" "+getline(myfile.name,i+1).split()[k]
							#prop2.append(getline(myfile.name,i+1).split()[k])
							k=k+1
						prop2.append("86400")
					i=i+1
				if prop2 not in ike2_pol:
					ike2_pol.append(prop2)
		#print(ike2_pol)

		t=0
		while t < len(ike_pol):
			#print(ike_pol[t])
			p.write(';'.join(ike_pol[t])+"\n")
			#print(ike_pol[t],"\n", file=open("output/"+inputfile.split(".")[0]+"ike_policy","a"))
			t=t+1
		t=0
		while t < len(ike2_pol):
			#print(ike2_pol[t])
			p.write(';'.join(ike2_pol[t])+"\n")
			t=t+1
with open ('input/'+inputfile, 'rt') as myfile:
		for line in myfile:
			if "crypto ipsec transform-set" in line:
				name = line.split()[3]
				enc = line.split()[4]
				hash="SHA"
				if "esp" not in line.split()[5]:
					enc = line.split()[4].split("-")[1].upper()+"-"+line.split()[5]
					if len(line.split()) == 6 and "esp" in line.split()[5]:
						hash = line.split()[5].split("-")[1].upper()
					elif len(line.split()) > 6:
						hash = line.split()[6].split("-")[1].upper()
				else:
					enc = line.split()[4].split("-")[1].upper()
					if len(line.split()) == 6 and "esp" in line.split()[5]:
						hash = line.split()[5].split("-")[1].upper()
					elif len(line.split()) > 6:
						hash = line.split()[6].split("-")[1].upper()
				ts=[name,enc,hash]
				TS.append(ts)

crypto_map=[]
with open ('input/'+inputfile, 'rt') as myfile:
		for ind,line in enumerate(myfile,1):
			if "crypto map" in line :
				i=ind
				fini=False
				desc=False
				crypmap=[]
				peer1='False'
				peersec='False'
				ts=False
				#Start loop to populate Crypto_map List
				while ((i < (ind+8)) and (getline(myfile.name,i+1).startswith(' '))):
					if ("Incomplete" in getline(myfile.name,i+1)): #if crypto map is incomplete Quit
						fini=True
						break
					elif (getline(myfile.name,i+1).split()[0]) == "description":
						crypmap.append(getline(myfile.name,i+1).split()[5].upper())
						desc=True
					elif (getline(myfile.name,i+1).split()[1]) == "peer":
						if desc==False:
							crypmap.append(str(getline(myfile.name,i+1).split()[2]))
						if peer1=='False' and peersec=='False':
							crypmap.append((getline(myfile.name,i+1).split()[2])+","+peersec)
							peer1='True'
						elif peer1=='True' and peersec=='False':
							crypmap[1]=getline(myfile.name,i).split()[2]+","+getline(myfile.name,i+1).split()[2]
							peersec='True'
							peer1='True'
						elif peer1=='True' and peersec=='True':
							crypmap[1]=getline(myfile.name,i-1).split()[2]+","+getline(myfile.name,i).split()[2]+","+getline(myfile.name,i+1).split()[2]
					elif (getline(myfile.name,i+1).split()[1]) == "security-association":
						crypmap.append("lifetime_"+(getline(myfile.name,i+1).split()[4]))
					elif (getline(myfile.name,i+1).split()[1]) == "transform-set":
						crypmap.append((getline(myfile.name,i+1).split()[2]))
						ts=True
					elif (getline(myfile.name,i+1).split()[1]) == "pfs":
						if ts == True:
							crypmap.append("pfs")
						else:
							crypmap.append("Default TS")
							crypmap.append("pfs")
						gp=getline(myfile.name,i+1).split()[2]
						if len(gp)==6:
							crypmap.append(gp[len(gp)-1])
						elif len(gp)==7:
							crypmap.append(gp[len(gp)-2]+gp[len(gp)-1])
					elif (getline(myfile.name,i+1).split()[1]) == "ikev2-profile":
						crypmap.append((getline(myfile.name,i+1).split()[2]))
					elif (getline(myfile.name,i+1).split()[0]) == "match":
						crypmap.append((getline(myfile.name,i+1).split()[2]))
					i=i+1
				if fini == False and crypmap != []:
					crypto_map.append(crypmap)

def convert_widcard(l):
	d=l.split(".")
	for i in range(len(d)):
		d[i]=str(255-int(d[i]))
	l=".".join(d)
	return l

ace=[]
acl=[]

with open ('input/'+inputfile, 'rt') as myfile:
		for line in myfile:
			if (("access-list" in line) and (len(line.split()) > 5)):
				idacl = line.split()[1]
				action = line.split()[2]

				if line.split()[4] == "any":
					local = line.split()[4]
					if line.split()[5] == "any":
						remote = line.split()[5]
					else:
						if "host" not in line.split()[5]:
							remote = line.split()[5]+" "+convert_widcard(line.split()[6])
						else:
							remote = line.split()[5]+" "+line.split()[6]
				elif "host" not in line.split()[4]:
					local = line.split()[4]+" "+convert_widcard(line.split()[5])
					if line.split()[6] == "any":
						remote = line.split()[6]
					elif "host" not in line.split()[6]:
						remote = line.split()[6]+" "+convert_widcard(line.split()[7])
					else:
						remote = line.split()[6]+" "+line.split()[7]
				else:
					local = line.split()[4]+" "+line.split()[5]
					if line.split()[6] == "any":
						remote = line.split()[6]
					elif "host" not in line.split()[6]:
						remote = line.split()[6]+" "+convert_widcard(line.split()[7])
					else:
						remote = line.split()[6]+" "+line.split()[7]

				ace = [idacl,action,local,remote]
				acl.append(ace)
t=0
c=len(acl)

while t < c-1:
	if acl[t+1][0] == acl[t][0]:
		for n in range(len(acl[t+1][2].split(";"))):
			if acl[t+1][2].split(";")[n] not in acl[t][2]:
				acl[t][2]=acl[t][2]+","+acl[t+1][2].split(";")[n]
		for m in range(len(acl[t+1][3].split(";"))):
			if acl[t+1][3].split(";")[m] not in acl[t][3]:
					acl[t][3]=acl[t][3]+","+acl[t+1][3].split(";")[m]
		acl.remove(acl[t+1])
		c=c-1
	else:
		t=t+1
i=0

while i < len(crypto_map):
	Config=[]
	peersec=False
	peerexist=False
	ike=False
	Config.append(crypto_map[i][0]) #Add partner name

	for l in range(len(crypto_map[i][1].split(','))):
		j=0
		while j < len(peer_psk):
			if (peer_psk[j].split(";")[0] == crypto_map[i][1].split(",")[l]) and (peer_psk[j].split(";")[1]=='1'):
				if ike==False:
					Config.append(peer_psk[j].split(";")[1])
					ike=True
				if peerexist == False and peersec == False:
					Config.append(crypto_map[i][1].split(",")[l]) #peer ip
					Config.append("No")
					Config.append(peer_psk[j].split(";")[2]) #add psk
					Config.append("No")
					peerexist=True
					break
				elif peerexist == True and peersec == False:
					Config[3] = crypto_map[i][1].split(",")[l]
					Config[5] = peer_psk[j].split(";")[2]
					peersec=True
					break
			elif (peer_psk[j].split(";")[0] == crypto_map[i][1].split(",")[l]) and peer_psk[j].split(";")[1]=='2':
				if ike==False:
					Config.append(peer_psk[j].split(";")[1])
					ike=True
				if peerexist == False and peersec == False:
					Config.append(crypto_map[i][1].split(",")[l]) #peer ip
					Config.append("No")
					Config.append(peer_psk[j].split(";")[2])
					Config.append(peer_psk[j].split(";")[3])
					peerexist=True
					break
				elif peerexist == True and peersec == False:
					Config[3] = crypto_map[i][1].split(",")[l]
					Config[5] = peer_psk[j].split(";")[3]
					peersec=True
					break
			j=j+1

		if peerexist==False and peersec==False:
			if ike==False:
				Config.append("1") #ikev default
				ike=True
			if l==0:
				Config.append(crypto_map[i][1].split(",")[0]) #add Peer IP
				Config.append("No")
				Config.append("not configured or auth by Certificat")
				Config.append("No")
				peerexist=True
			if l==1 and crypto_map[i][1].split(",")[l] != 'False':
				Config[3] = crypto_map[i][1].split(",")[l]
				Config[5] = "not configured or auth by Certificat"
				peersec==True
	k=0
	tsmatch=False
	while k < len(TS):
		if crypto_map[i][2]==TS[k][0]:
			Config.append(TS[k][1]+"_"+TS[k][2])
			tsmatch=True
			break
		elif crypto_map[i][3]==TS[k][0]:
			Config.append(TS[k][1]+"_"+TS[k][2])
			tsmatch=True
			break
		else:
			k=k+1
	if tsmatch==False:
		Config.append("3DES_SHA")
	if "lifetime" in crypto_map[i][2] and "pfs" in crypto_map[i]:
		Config.append(crypto_map[i][2].split("_")[1]) #lifetime p2
		Config.append("yes") #pfs (yes/no)
		Config.append(crypto_map[i][5])  #group p2
	elif "lifetime" in crypto_map[i][2] and "pfs" not in crypto_map[i]:
		Config.append(crypto_map[i][2].split("_")[1]) #lifetime p2
		Config.append("no") #pfs (yes/no)
		Config.append("none") #group p2
	elif "lifetime" not in crypto_map[i][2] and "pfs" in crypto_map[i]:
		Config.append("86400") #lifetime p2
		Config.append("yes") #pfs (yes/no)
		Config.append(crypto_map[i][4]) #group p2
	else:
		Config.append("86400") #lifetime p2
		Config.append("no") #pfs (yes/no)
		Config.append("none") #group p2
	l=0
	idacl = crypto_map[i][len(crypto_map[i])-1]
	while l < len(acl):
		if idacl==acl[l][0]:
			Config.append(acl[l][1]+";"+acl[l][2]+";"+acl[l][3])
			break
		else:
			l=l+1

	f.write(';'.join(Config)+"\n")
	i=i+1
