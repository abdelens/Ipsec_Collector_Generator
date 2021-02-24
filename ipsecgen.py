import sys
import csv
import os
import os.path

source='config'
ikeinputfile='output/'+source+'_ike.csv'
configinputfile='output/'+source+'_VPN.csv'
outputpath='output/ASA_'+source+'.txt'

if os.path.isfile(outputpath):
	print("file ASA config already there")
	os.replace(outputpath, outputpath + '.old')
	outputfile=outputpath
else:
	outputfile=outputpath
def create_ike_pol(id,ikev,enc,hash,grp,lifetime,ikeout):
	#print("starting ike_pol")
	if ikev == '1':
		print("\ncrypto ikev1 policy", id, file=open(ikeout,'a'))
		print("authentication pre-share",file=open(ikeout,"a"))
		print("encryption",enc,file=open(ikeout,"a"))
		print("hash",hash,file=open(ikeout,"a"))
		print("group",grp,file=open(ikeout,"a"))
		print("lifetime",lifetime,file=open(ikeout,"a"))
		#print("exit\n",file=open(ikeout,"a"))
	elif ikev =='2':
		print("\ncrypto ikev2 policy",id,file=open(ikeout,"a"))
		#print("authentication pre-share",file=open(ikeout,"a"))
		print("encryption",enc,file=open(ikeout,"a"))
		print("integrity",hash,file=open(ikeout,"a"))
		print("group",grp,file=open(ikeout,"a"))
		print("prf",hash,file=open(ikeout,"a"))
		print("lifetime seconds",lifetime,file=open(ikeout,"a"))
		#print("exit\n",file=open("output/ipsec.txt","a"))
	id=id+1


#######################
# tunnel-group config #
#######################

def tunnel_groupe_v1(ikev,peer,psk1,keeplive,policyName):
	print("\ntunnel-group", peer, "type ipsec-l2l", file=open(outputfile,"a"))
	if	policyName != "default":
		print("tunnel-group", peer, "general-attributes", file=open(outputfile,"a"))
		print(" default-group-policy", policyName, file=open(outputfile,"a"))
	print("tunnel-group", peer, "ipsec-attributes", file=open(outputfile,"a"))
	print(" ikev1 pre-shared-key", psk1, file=open(outputfile,"a"))
	if	keeplive != "yes":
		print(" isakmp keepalive disable", file=open(outputfile,"a"))
		#print("exit\n", file=open(outputfile,"a"))
def tunnel_groupe_v2(ikev,peer,psk1,pks2,keeplive,policyName):
	print("\ntunnel-group", peer, "type ipsec-l2l", file=open(outputfile,"a"))
	if	policyName != "default":
		print("tunnel-group", peer, "general-attributes", file=open(outputfile,"a"))
		print("tunnel-group", peer, "general-attributes", file=open(outputfile,"a"))
		print(" default-group-policy", policyName, file=open(outputfile,"a"))
	print("tunnel-group", peer, "ipsec-attributes", file=open(outputfile,"a"))
	print(" ikev2 remote-authentication pre-shared-key", psk2, file=open(outputfile,"a"))
	print(" ikev2 local-authentication pre-shared-key", psk1, file=open(outputfile,"a"))
	if	keeplive != "yes":
		print(" isakmp keepalive disable", file=open(outputfile,"a"))
		#print("exit\n", file=open(outputfile,"a"))

def create_ipsec_pol(ikev,enc,hash):
	if ikev == '1':
		if hash=="sha256":	#sha256 is not supported in ASA for integrity
			hash="sha"
		print("crypto ipsec ikev1 transform-set TS_IKEv1_"+enc.upper()+"_"+hash.upper(),"esp-"+enc.lower(),"esp-"+hash.lower()+"-hmac", file=open(outputfile,"a"))
		#print("exit\n", file=open("output/ipsec.txt","a"))
	elif ikev =='2':
		if hash=="sha256":	#sha256 is not supported in ASA for integrity
			hash="sha-256"
		print("crypto ipsec ikev2 ipsec-proposal TS_IKEv2_"+enc.upper()+"_"+hash.upper(), file=open(outputfile,"a"))
		print(" protocol esp encryption",enc.lower(), file=open(outputfile,"a"))
		print(" protocol esp integrity",hash.lower(), file=open(outputfile,"a"))
		#print("exit\n", file=open("output/ipsec.txt","a"))
	else:
		print("erreur ike version\n", file=open(outputfile,"a"))

def enc_domain(name,local,remote):
	dom1=list(local.split(','))
	dom2=list(remote.split(','))
	k=0
	while k < len(local.split(',')):
		m=0
		while m < len(remote.split(',')):
			if (len(dom1[k].split(' ')) == 1) & (len(dom2[m].split(' ')) == 1):
				print("access-list", name.upper(),"extended permit ip host",dom1[k],"host",dom2[m], file=open(outputfile,"a"))
			elif (len(dom1[k].split(' ')) == 1) & (len(dom2[m].split(' ')) != 1):
				print("access-list", name.upper(),"extended permit ip host",dom1[k],dom2[m], file=open(outputfile,"a"))
			elif (len(dom1[k].split(' ')) != 1 & len(dom2[m].split(' ')) == 1):
				print("access-list", name.upper(),"extended permit ip",dom1[k],"host",dom2[m], file=open(outputfile,"a"))
			elif (len(dom1[k].split(' ')) != 1 & len(dom2[m].split(' ')) != 1):
				print("access-list", name.upper(),"extended permit ip",dom1[k],dom2[m], file=open(outputfile,"a"))
			m=m+1
		k=k+1
	#print("exit", file=open("output/ipsec.txt","a"))


def create_crypto_map(id,crypname,ike,peer1,peer2,acl,prop2,pfs,grp):
	print("crypto map",crypname.upper(), id,"annotation CryptoMap_"+name.upper(), file=open(outputfile,"a"))
	print("crypto map",crypname.upper(), id,"match address",acl.upper(), file=open(outputfile,"a"))
	if peer2 !="No":
		print("crypto map",crypname.upper(), id,"set peer",peer1, peer2, file=open(outputfile,"a"))
	else:
		print("crypto map",crypname.upper(), id,"set peer",peer1, file=open(outputfile,"a"))
	if ike == '1':
		print("crypto map",crypname.upper(), id,"set ikev1 transform-set TS_IKEv1_"+prop2.upper(), file=open(outputfile,"a"))
	elif ike == '2':
		print("crypto map",crypname.upper(), id,"set ikev2 ipsec-proposal TS_IKEv2_"+prop2.upper(), file=open(outputfile,"a"))
	if (pfs == "yes" or pfs =="y"):
		print("crypto map",crypname.upper(), id,"set pfs group"+grp, file=open(outputfile,"a"))

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

with open(ikeinputfile,'rt') as ike_pol_Form:
		ikeForm=csv.reader(ike_pol_Form, delimiter = ';', quotechar = '|')
		ikeForm= list(ikeForm)
		i=0
		ikev1_liste = []
		ikev2_liste = []
		id_ikev1=10
		id_ikev2=10
		print("!!!!Create IKE proposal!!!!\n", file=open(outputfile,"a"))
		while i < len(ikeForm):
			ike_pol = ikeForm[i]
			ikev = ike_pol[0]
			cbc = ike_pol[1].split(" ")
			for p in range(len(cbc)):
				if "cbc" in cbc[p]:					#aes-cbc-256 not supported in ASA it changed by aes-256
					cbc[p]=cbc[p].split("-")[0]+"-"+cbc[p].split("-")[2]
				if "aes-128" == cbc[p]:				#aes-128 not supported in ASA it changed by aes
					cbc[p]="aes"
			enc = " ".join(cbc)
			hach = ike_pol[2].split(" ")
			for s in range(len(hach)):
				if "sha1" in hach[s]:				#hash1 not supported in ASA it changed by hash
					hach[hach.index("sha1")]="sha"
			hash = " ".join(hach)
			auth = ike_pol[3]
			grp = ike_pol[4]
			lifetime = ike_pol[5]
			######create ipsec proposal######
			#verifier que le policy n'existe pas sinon la créer
			if ikev == '1' and ike_pol not in ikev1_liste:
				if hash=="sha256" or hash=="sha1":	#sha256 is not supported in ASA for integrity
					print("\n!!!!Attention: integrity proposal",hash,"not supported on ASA and should be reviewed with partner!!!!!", file=open(outputfile,"a"))
					hash="sha"
				if grp != "1" and grp != "2" and grp != "5" :	#only supported DH on ikev1 are 1,2,5
					print("!!!!Attention: DH group",grp,"not supported on ASA and should be reviewed with partner!!!!!", file=open(outputfile,"a"))
					grp="5"
				create_ike_pol(id_ikev1,ikev,enc,hash,grp,lifetime,outputfile)
				ikev1_liste.append(ike_pol)
				id_ikev1=id_ikev1+1
			elif ikev == '2' and ike_pol not in ikev2_liste:
				create_ike_pol(id_ikev2,ikev,enc,hash,grp,lifetime,outputfile)
				ikev2_liste.append(ike_pol)
				id_ikev2=id_ikev2+1
			else:
				print("!!!!",ike_pol, "already exist!!!!!\n", file=open(outputfile,"a"))

			i=i+1

			######create ipsec proposal######
with open(configinputfile,'rt') as ipsecForm:
		vpnForm = csv.reader(ipsecForm, delimiter = ';', quotechar = '|')
		vpnForm = list(vpnForm)
		i=1
		ipsec_liste_v1 = []
		ipsec_liste_v2 = []
		keeplive = "yes"
		policyName = "default"
		id_cmap = 100
		cmap = "Outside_Map"
		while i < len(vpnForm):
			#cmapid = vpnForm[i][16]
			name = vpnForm[i][0]
			ikev = vpnForm[i][1]
			peer1 = vpnForm[i][2]
			peer2 = vpnForm[i][3]
			psk1 = vpnForm[i][4]
			psk2 = vpnForm[i][5]
			P2Prop = vpnForm[i][6]
			list_P2prop = P2Prop.split('_')
			enc2 = list_P2prop[0]
			hash2 = list_P2prop[1]
			pfs = vpnForm[i][8]
			grp2 = vpnForm[i][9]
			local_net = vpnForm[i][11]
			remote_net = vpnForm[i][12]


			print("\n!!!!!*****Create VPN IPSEC for Partner: ",name.upper(),"**************!!!!\n", file=open(outputfile,"a"))

			######create ipsec proposal######
			print("!!!!Create ipsec proposal!!!!\n", file=open(outputfile,"a"))
			if exist(ikev,P2Prop,grp2,ipsec_liste_v1,ipsec_liste_v2) != 0:
				#print(P2Prop)
				create_ipsec_pol(ikev,enc2,hash2)
			else:
				print("!!!!",P2Prop, "already exist!!!!!\n", file=open(outputfile,"a"))

			######create Tunnel-group######
			print("\n!!!!Create Tunnel-group!!!!", file=open(outputfile,"a"))
			if ikev =='1':
				tunnel_groupe_v1(ikev,peer1,psk1,keeplive,policyName)
				if peer2 != "No":
					tunnel_groupe_v1(ikev,peer2,psk2,keeplive,policyName)
			elif ikev =='2':
				tunnel_groupe_v2(ikev,peer1,psk1,psk2,keeplive,policyName)
				if peer2 != "No":
					tunnel_groupe_v2(ikev,peer2,psk1,psk2,keeplive,policyName)
			######create Access-list######
			print("\n!!!!Create ACL for encryption domain!!!!\n", file=open(outputfile,"a"))
			enc_domain(name,local_net,remote_net)

			######create CryptoMap######
			print("\n!!!!Create CryptoMap!!!!\n", file=open(outputfile,"a"))
			create_crypto_map(id_cmap,cmap,ikev,peer1,peer2,name,P2Prop,pfs,grp2)
			id_cmap=id_cmap+1
			i=i+1
