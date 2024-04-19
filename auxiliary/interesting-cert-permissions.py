#!/usr/bin/env python
import os
import itertools
import subprocess


host = 'localhost'
user = 'neo4j'
password = 'password'


ct=[]
comm ="cypher-shell -a "+host+" -u "+user+" -p "+password+" --format plain \"MATCH p = (n)-[r:AddMember|AddSelf|WriteSPN|AddKeyCredentialLink|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(g:GPO) WHERE NOT (n.name CONTAINS 'DOMAIN ADMINS' or n.name CONTAINS 'ENTERPRISE ADMINS' or n.name CONTAINS 'ADMINISTRATORS' or n.name CONTAINS 'DOMAIN CONTROLLERS') AND (g.name IS NOT NULL) RETURN g.name\" 2> /dev/null | grep -v 'g\.name' | sed -r 's/\"//g'"
result = subprocess.Popen([comm], stdout=subprocess.PIPE,shell=True)
(output,error)=result.communicate()
formatted_out = output.decode("utf-8")
for line in formatted_out.split('\n'):
        ct.append(line.strip())

results = [(g[0], len(list(g[1]))) for g in itertools.groupby(ct)]
print("[+] Generating list of certificate templates where interesting principals can modify (Not DA|EA|DC|Administrators) - Investigate these inbound rights!")
for line in results:
        line=list(line)
        certtemp=line[0]
        count=line[1]
        if len(certtemp) > 2:
                print(str(certtemp)+"\t"+str(count)+" inbound rights")
