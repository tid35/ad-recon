#!/usr/bin/env python
import os
import subprocess

# variables for cypher-shell queries
host = 'localhost'
user = 'neo4j'
password = 'password'

## This script will query the High Value Targets (HVTs) in Bloodhound and print out who has inbound rights to them that are not admincount=true. This will be a quick way to identify potentially interesting priv esc paths to HVTs.


## Query to build a list of high value targets into list 'hv'
hv = []
comm ="cypher-shell -a "+host+" -u "+user+" -p "+password+" --format plain \"MATCH (m) WHERE m.highvalue=TRUE RETURN m.name, m.objectid\" 2> /dev/null | grep -v 'm\.objectid' | sed -r 's/\"//g'"
result = subprocess.Popen([comm], stdout=subprocess.PIPE,shell=True)
(output,error)=result.communicate()
formatted_out = output.decode("utf-8")
for line in formatted_out.split('\n'):
        if len(line) > 2:
                hv.append(line.strip())

# Query to go through each HV target in 'hv' and populate non-admin accounts that have paths to said HV target storing the results in the lsit 'hv_results'
hv_results=[]
print("[+] Generating list of non-admin accounts with permissions to high value targets (Domain Admins, Domain Controllers, etc.) this query can take a bit:")
for groups in hv:
	if len(groups) > 2:
		group = groups.split(",")[0]
		objectid = groups.split(",")[1].strip()
		comm ="cypher-shell -a "+host+" -u "+user+" -p "+password+" --format plain \"MATCH (n) WHERE NOT (n.objectid='"+objectid+"') WITH n MATCH p = shortestPath((n)-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:Group {objectid: '"+objectid+"'})) RETURN n.name, n.admincount\" 2> /dev/null | grep -v 'n\.name' | sed -r 's/\"//g' | grep 'FALSE' | awk -F ',' '{print $1}'"
		result = subprocess.Popen([comm], stdout=subprocess.PIPE,shell=True)
		(output,error)=result.communicate()
		formatted_out = output.decode("utf-8")
		for line in formatted_out.split('\n'):
			if len(line) > 2:
				str1 = "[+] "+line.strip()
				str2 = "is 'admincount: false' and has a path to "+group+" Group that needs to be investigated"
				print('{:<35s} {:<50s}'.format(str1, str2))
