#!/usr/bin/env python
import os
import itertools
import subprocess


host = 'localhost'
user = 'neo4j'
password = 'password'

# Prints out all principals who can enroll into a certificate template. The idea here is to find a path to being able to do this

# MATCH (n:GPO) WHERE n.type = 'Certificate Template' RETURN n.name
comm ="cypher-shell -a "+host+" -u "+user+" -p "+password+" --format plain \"MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.Enabled RETURN n.name\" 2> /dev/null | grep -v 'n.name' | sed -r 's/\"//g'"
result = subprocess.Popen([comm], stdout=subprocess.PIPE,shell=True)
(output,error)=result.communicate()
formated_out = output.decode('utf-8')
cert_temp=[]

for line in formated_out.split('\n'):
	if len(line) > 2:
		cert_temp.append(line.strip())


print("[+] Generating a list of prinicipals who have Enroll|AutoEnroll rights to a certificate template. If the template is configured poorly + you enroll = you can exploit:")
# MATCH p=(g)-[:Enroll|AutoEnroll]->(n:GPO {name:'SJUWEBSERVER4YEARS@AD.SJU.EDU'}) WHERE n.type = 'Certificate Template' return g.name
for cert in cert_temp:
	principals=[]
	comm ="cypher-shell -a "+host+" -u "+user+" -p "+password+" --format plain \"MATCH p=(g)-[:Enroll|AutoEnroll]->(n:GPO {name:'"+cert+"'}) WHERE n.type = 'Certificate Template' return g.name\" 2> /dev/null | grep -v 'g.name' | sed -r 's/\"//g'"
	result = subprocess.Popen([comm], stdout=subprocess.PIPE,shell=True)
	(output,error)=result.communicate()
	formated_out = output.decode('utf-8')
	for line in formated_out.split('\n'):
		if len(line) > 2:
			principals.append(line.strip())

	print("[+] Certificate Template: "+cert+" \t Enroll Permissions: "+", ".join(principals).strip(","))

