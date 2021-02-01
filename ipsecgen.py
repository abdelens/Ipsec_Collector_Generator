import sys
import csv
import os

#######################
# IKE policy config #
#######################


#with open('input/ipsecForm.csv','rt') as ipsecForm:
#		vpnForm = csv.reader(ipsecForm, delimiter = ',', quotechar = '|')
#		vpnForm = list(vpnForm)
#		ike_pol = vpnForm[1][4]
#		ike_lifetime = vpnForm[1][5]
#		list_prop = ike_pol.split('_')
#		enc = list_prop[0]
#		hash = list_prop[1]
#		grp = list_prop[2]

def create_ike_pol(id,ikev,enc,hash,grp,lifetime):
	print("starting ike_pol")
	if ikev == '1':
		print("crypto ikev1 policy ", id,file=open("output/ipsec.txt","a"))
		print("authentication pre-share",file=open("output/ipsec.txt","a"))
		print("encription",enc,file=open("output/ipsec.txt","a"))
		print("hash",hash,file=open("output/ipsec.txt","a"))
		print("groupe",grp,file=open("output/ipsec.txt","a"))
		print("lifetime",lifetime,file=open("output/ipsec.txt","a"))
		print("exit",file=open("output/ipsec.txt","a"))
	elif ikev =='2':
		print("crypto ikev2 policy ",id,file=open("output/ipsec.txt","a"))
		print("authentication pre-share",file=open("output/ipsec.txt","a"))
		print("encription",enc,file=open("output/ipsec.txt","a"))
		print("hash",hash,file=open("output/ipsec.txt","a"))
		print("groupe",grp,file=open("output/ipsec.txt","a"))
		print("prf",enc,file=open("output/ipsec.txt","a"))
		print("lifetime",lifetime,file=open("output/ipsec.txt","a"))
		#print("exit",file=open("output/ipsec.txt","a"))
	id=id+1

		
#######################
# tunnel-group config #
#######################

def tunnel_groupe(ikev,peer,psk1,pks2,keeplive,policyName):
	if ikev =='1':
		print("\ntunnel-group", peer, "type ipsec-l2l", file=open("output/ipsec.txt","a"))
		print("tunnel-group", peer, "general-attributes", file=open("output/ipsec.txt","a"))
		if	policyName != "default":
			print(" default-group-policy", policyName, file=open("output/ipsec.txt","a"))
		print("tunnel-group", peer, "ipsec-attributes", file=open("output/ipsec.txt","a"))
		print(" ikev1 pre-shared-key", psk1, file=open("output/ipsec.txt","a"))
		if	keeplive != "yes":
			print(" isakmp keepalive disable", file=open("output/ipsec.txt","a"))
		#print("exit", file=open("output/ipsec.txt","a"))
	elif ikev =='2':
		print("\ntunnel-group", peer, "type ipsec-l2l", file=open("output/ipsec.txt","a"))
		if	policyName != "default":
			print("tunnel-group", peer, "general-attributes", file=open("output/ipsec.txt","a"))
			print(" default-group-policy", policyName, file=open("output/ipsec.txt","a"))
		print("tunnel-group", peer, "ipsec-attributes", file=open("output/ipsec.txt","a"))
		print(" ikev2 remote-authentication pre-shared-key", psk2, file=open("output/ipsec.txt","a"))
		print(" ikev2 local-authentication pre-shared-key", psk1, file=open("output/ipsec.txt","a"))
		if	keeplive != "yes":
			print(" isakmp keepalive disable", file=open("output/ipsec.txt","a"))
		#print("exit", file=open("output/ipsec.txt","a"))
	else:
		print("erreur ike version")
   
def create_ipsec_pol(ikev,enc,hash):
	if ikev == '1':
		print("crypto ipsec ikev1 transform-set TS_IKEv1_"+enc.upper()+"_"+hash.upper(),"esp-"+enc.lower(),"esp-"+hash.lower()+"-hmac", file=open("output/ipsec.txt","a"))
		print("exit", file=open("output/ipsec.txt","a"))
	elif ikev =='2':
		print("crypto ipsec ikev2 ipsec-proposal TS_IKEv2_"+enc.upper()+"_"+hash.upper(), file=open("output/ipsec.txt","a"))
		print(" protocol esp encryption",enc.lower(), file=open("output/ipsec.txt","a"))
		print(" protocol esp integrity",hash.lower(), file=open("output/ipsec.txt","a"))
		#print("exit", file=open("output/ipsec.txt","a"))
	else:
		print("erreur ike version")

def enc_domain(name,local,remote):
	dom1=list(local.split(','))
	dom2=list(remote.split(','))
	k=0
	while k < len(local.split(',')):
		m=0
		while m < len(remote.split(',')):
			if (len(dom1[k].split(' ')) == 1) & (len(dom2[m].split(' ')) == 1):
				print("access-list", name.upper(),"extended permit ip host",dom1[k],"host",dom2[m], file=open("output/ipsec.txt","a"))
			elif (len(dom1[k].split(' ')) == 1) & (len(dom2[m].split(' ')) != 1):
				print("access-list", name.upper(),"extended permit ip host",dom1[k],dom2[m], file=open("output/ipsec.txt","a"))
			elif (len(dom1[k].split(' ')) != 1 & len(dom2[m].split(' ')) == 1):
				print("access-list", name.upper(),"extended permit ip",dom1[k],"host",dom2[m], file=open("output/ipsec.txt","a"))
			elif (len(dom1[k].split(' ')) != 1 & len(dom2[m].split(' ')) != 1):
				print("access-list", name.upper(),"extended permit ip",dom1[k],dom2[m], file=open("output/ipsec.txt","a"))
			m=m+1
		k=k+1
	#print("exit", file=open("output/ipsec.txt","a"))	

	
def create_crypto_map(id,crypname,ike,peer1,peer2,acl,prop2,pfs,grp):
	print("crypto map ",crypname.upper(), id,"annotation CryptoMap_"+name.upper(), file=open("output/ipsec.txt","a"))
	print("crypto map ",crypname.upper(), id,"match address",acl.upper(), file=open("output/ipsec.txt","a"))
	if peer2 !="":
		print("crypto map ",crypname.upper(), id,"set peer",peer1, peer2, file=open("output/ipsec.txt","a"))
	else:
		print("crypto map ",crypname.upper(), id,"set peer",peer1, file=open("output/ipsec.txt","a"))
	if ike == '1':
		print("crypto map ",crypname.upper(), id,"set ikev1 transform-set TS_IKEv1_"+prop2.upper(), file=open("output/ipsec.txt","a"))
	elif ike == '2':
		print("crypto map ",crypname.upper(), id,"set ikev2 transform-set TS_IKEv2_"+prop2.upper(), file=open("output/ipsec.txt","a"))
	if (pfs == "yes" or pfs =="y"):
		print("crypto map ",crypname.upper(), id,"set pfs group"+grp, file=open("output/ipsec.txt","a"))

def exist(a,b,c,d,e):
	if ((a == '1') and (b not in d) and (c not in d)):
		d.append(b)
		d.append(c)
		return 1
	elif ((a == '2') and (b not in e) and (c not in e)):
		e.append(b)
		e.append(c)
		return 2
	else:
		return 0

with open('input/ipsecForm.csv','rt') as ipsecForm:
		vpnForm = csv.reader(ipsecForm, delimiter = ';', quotechar = '|')
		vpnForm = list(vpnForm)
		i=1
		ikev1_liste = []
		ikev2_liste = []
		ipsec_liste_v1 = []
		ipsec_liste_v2 = []
		id_ikev1=10
		id_ikev2=10
		while i < len(vpnForm):
			cmapid = vpnForm[i][16]
			ikev = vpnForm[i][1]
			ike_pol = vpnForm[i][4]
			list_prop = ike_pol.split('_')
			lifetime = vpnForm[i][5]
			enc = list_prop[0]
			hash = list_prop[1]
			grp = list_prop[2]
			peer1 = vpnForm[i][2]
			peer2 = vpnForm[i][3]
			psk1 = vpnForm[i][6]
			psk2 = vpnForm[i][7]
			keeplive = vpnForm[i][8]
			P2Prop = vpnForm[i][10]
			list_P2prop = P2Prop.split('_')
			enc2 = list_P2prop[0]
			hash2 = list_P2prop[1]
			grp2 = vpnForm[i][13]
			policyName = vpnForm[i][9]
			name = vpnForm[i][0]
			local_net = vpnForm[i][17]
			remote_net = vpnForm[i][18]
			id_cmap = vpnForm[i][15]
			cmap = vpnForm[i][16]
			pfs = vpnForm[i][12]
			
			 
			print("!!!!!\n*****Create VPN IPSEC for Partner: ",name.upper(),"**************!!!!\n", file=open("output/ipsec.txt","a"))
			
			######create ipsec proposal######
			print("\n!!!!Create IKE proposal!!!!\n", file=open("output/ipsec.txt","a"))
			#verifier que le policy n'existe pas sinon la créer		
			if exist(ikev,ike_pol,grp,ikev1_liste,ikev2_liste) == 1:
				create_ike_pol(id_ikev1,ikev,enc,hash,grp,lifetime)
				id_ikev1=id_ikev1+1
			elif exist(ikev,ike_pol,grp,ikev1_liste,ikev2_liste) == 2:
				create_ike_pol(id_ikev2,ikev,enc,hash,grp,lifetime)
				id_ikev2=id_ikev2+1
			else:	
				print("!!!!",ike_pol, "already exist!!!!!\n", file=open("output/ipsec.txt","a"))
				
			######create ipsec proposal######
			print("\n!!!!Create ipsec proposal!!!!\n", file=open("output/ipsec.txt","a"))			
			if exist(ikev,P2Prop,grp2,ipsec_liste_v1,ipsec_liste_v2) != 0:
				print(P2Prop)
				create_ipsec_pol(ikev,enc2,hash2)
			else:
				print("!!!!",P2Prop, "already exist!!!!!\n", file=open("output/ipsec.txt","a"))
				
			######create Tunnel-group######
			print("\n!!!!Create Tunnel-group!!!!\n", file=open("output/ipsec.txt","a"))	
			tunnel_groupe(ikev,peer1,psk1,psk2,keeplive,policyName)
				
			######create Access-list######
			print("\n!!!!Create ACL for encryption domain!!!!\n", file=open("output/ipsec.txt","a"))
			enc_domain(name,local_net,remote_net)
			
			######create CryptoMap######
			print("\n!!!!Create CryptoMap!!!!\n", file=open("output/ipsec.txt","a"))
			create_crypto_map(id_cmap,cmap,ikev,peer1,peer2,name,P2Prop,pfs,grp2)
			i=i+1