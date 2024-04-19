#!/usr/bin/env python
import os
import subprocess

# variables for cypher-shell queries
host = 'localhost'
user = 'neo4j'
password = 'password'


## Query to build a list of GPOs into list 'gpos'
gpos = []
comm ="cypher-shell -a "+host+" -u "+user+" -p "+password+" --format plain \"MATCH (m:GPO) RETURN m.name, m.objectid\" 2> /dev/null | grep -v 'm\.objectid' | sed -r 's/\"//g'"
result = subprocess.Popen([comm], stdout=subprocess.PIPE,shell=True)
(output,error)=result.communicate()
formatted_out = output.decode("utf-8")
for line in formatted_out.split('\n'):
        if len(line) > 2:
                gpos.append(line.strip())


if len(gpos) > 100:
        print("[+] Generating list of GPOs and inbound rights: (Total GPOs: "+str(len(gpos))+" this will take a bit ~5-10secs per GPO)")

else:
        print("[+] Generating list of GPOs and inbound rights: (Total GPOs: "+str(len(gpos))+")")


for gpo in gpos:
	if len(gpo) > 1:
		gpo_name = gpo.split(",")[0]
		objectid = gpo.split(",")[1].strip()
		comm ="cypher-shell -a "+host+" -u "+user+" -p "+password+" --format plain \"MATCH (n) WHERE NOT (n.objectid='"+objectid+"') WITH n MATCH p = shortestPath((n)-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:GPO {objectid: '"+objectid+"'})) RETURN count(n.name)\" 2> /dev/null | grep -v 'count' | sed -r 's/\"//g'"
		result = subprocess.Popen([comm], stdout=subprocess.PIPE,shell=True)
		(output,error)=result.communicate()
		formatted_out = output.decode("utf-8")
		for line in formatted_out.split('\n'):
			if len(line) > 1:
				print("[+] GPO: "+gpo_name+" inbound rights: "+str(line.strip()))
