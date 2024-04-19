#!/usr/bin/env python
from neo4j import GraphDatabase, RoutingControl
import time
import sys
import argparse
from termcolor import colored
import itertools


################################
# Define for target environment#
################################
URI = "neo4j://localhost:7687"
AUTH = ("neo4j", "password")
################################


def do_query(driver, query):
    records, _, _ = driver.execute_query(
        query,
        database_="neo4j", 
        routing_=RoutingControl.READ,
    )
    return records

# Query to retrieve Domain Controllers
# MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' return c1.name
def get_DCs():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' return c1.name")
        print("Domain Controllers: ")
        for record in result:
            print(record["c1.name"])
        print("-----")

# Query to parse out Domains
# MATCH (n:Domain) RETURN n.name
def get_domains():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (n:Domain) RETURN n.name")
        print("Domains Found: ")
        for record in result:
            if record['n.name']:
                print(record["n.name"])
            else:
                print("No Domain Detected please check to ensure database setup properly and data imported")
                sys.exit(0)
        print("-----")

# Query to get number of total computers
# MATCH (u:Computer) return count(u)
def get_computers():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:Computer) return count(u)")
        for record in result:
            if record["count(u)"]:
                count=record["count(u)"]
        if len(str(count)) > 1:
            print("Number of Computers: "+str(count))

# Query to print number of sessions
# MATCH (c:Computer)-[:HasSession]->(u:User) return count(c)
def get_sessionCount():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (c:Computer)-[:HasSession]->(u:User) return count(c)")
        for record in result:
            if record["count(c)"]:
                count=record["count(c)"]
            else:
                count="0"

        if int(count) < 100:
            print("Number of Sessions: "+str(count)+" Session data is low consider session looping")
        else:
            print("Number of Sessions: "+str(count))

# Query to print number of Users
# MATCH (u:User) return count(u)
def get_users():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:User) return count(u)")
        for record in result:
            if record["count(u)"]:
                count=record["count(u)"]
            else:
                count="0"

        print("Number of Users: "+str(count))


# Query to print number of Enabled Users
# MATCH (u:User {enabled: true}) return count(u)
def get_Enabledusers():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:User {enabled: true}) return count(u)")
        for record in result:
            if record["count(u)"]:
                count=record["count(u)"]
            else:
                count="0"

        print("Number of Enabled Users: "+str(count))


# Print number of owned users:
# MATCH (m:User) WHERE m.owned=TRUE RETURN count(m)
def get_ownedUsersCount():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (m:User) WHERE m.owned=TRUE RETURN count(m)")
        for record in result:
            if record["count(m)"]:
                count=record["count(m)"]
            else:
                count="0"
    print("Number of Owned Users: "+str(count))


# Getting DAs:
# Q1: MATCH p=(n:Group)<-[:MemberOf*1..]-(m) WHERE n.objectid =~ '(?i)S-1-5-.*-512' RETURN m.name
# Getting Owned Users with 'admincount: true'
# Q2: MATCH (m:User {enabled: true, admincount: true}) WHERE m.owned=TRUE RETURN m
def get_ownedUsers():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        das=[]
        result = do_query(driver, "MATCH p=(n:Group)<-[:MemberOf*1..]-(m) WHERE n.objectid =~ '(?i)S-1-5-.*-512' RETURN m.name")
        for record in result:
            if record["m.name"]:
                das.append(record["m.name"])
            else:
                das.append("None")

        result = do_query(driver, "MATCH (m:User {enabled: true, admincount: true}) WHERE m.owned=TRUE RETURN m.name")
        print("Compromised Enabled Users with admincount true: ")
        for record in result:
            if record["m.name"]:
                if record["m.name"] in das:
                    da_str ="[*] "+record["m.name"].strip()+" is a Domain Admin (DA)!"
                    print(colored(da_str, 'green'))
                else:
                    print("[-] "+record["m.name"].strip())
    print("")


# Generate file with all Domain Admin sessions
# MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = (c:Computer)-[:HasSession]->(u) RETURN c.name, u.name
def get_daSessions():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = (c:Computer)-[:HasSession]->(u) RETURN c.name, u.name")
        das_file=open("da_sessions.txt", "w")
        for record in result:
            if record["u.name"]:
                user_name=record["u.name"]
                computer_name=record["c.name"]
                das_file.write("[*] Computer: "+computer_name+" has Domain Admin Session: "+user_name+"\n")
        das_file.close()

    with open("da_sessions.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating List of Domain Admin Sessions: da_sessions.txt ("+entries+") lines")


# Generate a file with all the owners of the the computer objects within current dataset
# MATCH p = (n)-[r:Owns]->(g:Computer) RETURN n.name, g.name
# You can also check out admincount=false: MATCH p = (n)-[r:Owns]->(g:Computer) WHERE n.admincount=false RETURN p
def get_compOwners():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH p = (n)-[r:Owns]->(g:Computer) RETURN n.name, g.name")
        owner_file=open("comp_owners.txt", "w")
        for record in result:
            if record["n.name"]:
                user_name=record["n.name"]
                computer_name=record["g.name"]
                owner_file.write("User: "+user_name+" owns: "+computer_name+"\n")
        owner_file.close()

    with open("comp_owners.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating List of Owners for the Computers in AD: comp_owners.txt ("+entries+") lines")



# Generate file with all sessions
# MATCH (c:Computer)-[:HasSession]->(u:User) return c.name, u.name
def get_sessions():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (c:Computer)-[:HasSession]->(u:User) return c.name, u.name")
        session_file=open("sessions_all.txt", "w")
        for record in result:
            if record["u.name"]:
                user_name=record["u.name"]
            else:
                user_name = "NULL"
            computer_name=record["c.name"]
            session_file.write("[*] Computer: "+computer_name+" has session from user: "+user_name+"\n")
        session_file.close()

    with open("sessions_all.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating List of all Sessions: sessions_all.txt ("+entries+") lines")


# Generate file with all users that have local admin rights:
# MATCH p=(m:User)-[r:AdminTo]->(n:Computer) RETURN m.name, n.name
def get_localAdmins():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH p=(u:User)-[r:AdminTo]->(c:Computer) RETURN u.name, c.name")
        localadmins_file=open("users_localadmins.txt", "w")
        for record in result:
            if record["u.name"]:
                user_name=record["u.name"]
            else:
                user_name = "NULL"
            if record["c.name"]:
                computer_name=record["c.name"]
            else:
                computer_name= "NULL"
            localadmins_file.write("[*] User: "+user_name+" has local admin rights to: "+computer_name+"\n")
        localadmins_file.close()

    with open("users_localadmins.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating List of users with local admin rights: users_localadmins.txt ("+entries+") lines")



# Generate a file with a list of Certificate Templates that interesting users have inbound rights to (Not: DAs, EAs, DCs, Administrators, etc.) - this should be interesting paths to control the certifiate template to exploit it to take over domain
# MATCH p = (n)-[r:AddMember|AddSelf|WriteSPN|AddKeyCredentialLink|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(g:GPO) WHERE NOT (n.name CONTAINS 'DOMAIN ADMINS' or n.name CONTAINS 'ENTERPRISE ADMINS' or n.name CONTAINS 'ADMINISTRATORS' or n.name CONTAINS 'DOMAIN CONTROLLERS') AND (g.name IS NOT NULL) RETURN g.name
def get_certTempNotAdmin():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        ct=[]
        result = do_query(driver, "MATCH p = (n)-[r:AddMember|AddSelf|WriteSPN|AddKeyCredentialLink|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(g:GPO) WHERE NOT (n.name CONTAINS 'DOMAIN ADMINS' or n.name CONTAINS 'ENTERPRISE ADMINS' or n.name CONTAINS 'ADMINISTRATORS' or n.name CONTAINS 'DOMAIN CONTROLLERS') AND (g.name IS NOT NULL) RETURN g.name")
        for record in result:
            if record["g.name"]:
                ct.append(record["g.name"])
            else:
                ct.append("None")

        cert_file=open("vuln_certs.txt", "w")
        ct_results = [(g[0], len(list(g[1]))) for g in itertools.groupby(ct)]
        for line in ct_results:
            line=list(line)
            certtemp=line[0]
            count=line[1]
            cert_file.write(str(certtemp)+"\t"+str(count)+" inbound rights"+"\n")
        cert_file.close()
        with open("vuln_certs.txt", "r") as fp:
            entries = str(len(fp.readlines()))
        print("[+] Generating list of certificate templates where interesting principals can modify (Not DA|EA|DC|Administrators) - Investigate these inbound rights: vuln_certs.txt ("+entries+") lines")


# Multiple stage query to generate a list of certificate templates and list of principals with enroll rights > cert_enroll_permissions.txt
# Q1 - Generate a list of enabled certificate templates: MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.Enabled RETURN n.name 
# Q2 - Getting Enroll and AutoEnroll permissions for each cert template: MATCH p=(g)-[:Enroll|AutoEnroll]->(n:GPO {name:'cert_temp_name'}) WHERE n.type = 'Certificate Template' return g.name
def get_certEnroll():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        cert_temp=[]
        result = do_query(driver, "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.Enabled RETURN n.name")
        for record in result:
            if record["n.name"]:
                cert_temp.append(record["n.name"])
            else:
                cert_temp.append("NULL")

        cert_enroll = open("cert_enroll_permissions.txt", "w")
        for cert in cert_temp:
            principals=[]
            result = do_query(driver, "MATCH p=(g)-[:Enroll|AutoEnroll]->(n:GPO {name:'"+cert+"'}) WHERE n.type = 'Certificate Template' return g.name")
            for record in result:
                if record['g.name']:
                    principals.append(record['g.name'])
            cert_enroll.write("[+] Certificate Template: "+cert+" \t Enroll Permissions: "+", ".join(principals).strip(",")+"\n")
        cert_enroll.close()

    with open("cert_enroll_permissions.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating list of certificate templates and list of principals with enroll rights: cert_enroll_permissions.txt ("+entries+") lines")


# Generate file with users and descriptions: user_descriptions.txt
# MATCH (u:User) return u.name, u.description
def get_userDesc():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:User) return u.name, u.description")
        userdesc_file=open("user_descriptions.txt", "w")
        for record in result:
            if record["u.name"]:
                user_name=record["u.name"]
            else:
                user_name=""

            if record['u.description']:
                user_desc=record["u.description"]
            else:
                user_desc=""

            if len(user_desc) > 1:
                userdesc_file.write(user_name+", "+user_desc+"\n")
            else:
                userdesc_file.write(user_name+"\n")
        userdesc_file.close()

    with open("user_descriptions.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating Users + Descriptions: user_descriptions.txt ("+entries+") lines")



# Generate file with computers and descriptions: computer_descriptions.txt
# MATCH (u:Computer) return u.name, u.description
def get_compDesc():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:Computer) return u.name, u.description")
        comp_file=open("computer_descriptions.txt", "w")
        for record in result:
            if record["u.name"]:
                comp_name=record["u.name"]
            else:
                comp_name=""

            if record['u.description']:
                comp_desc=record["u.description"]
            else:
                comp_desc=""

            if len(comp_desc) > 1:
                comp_file.write(comp_name+", "+comp_desc+"\n")
            else:
                comp_file.write(comp_name+"\n")
        comp_file.close()

    with open("computer_descriptions.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating Computers + Descriptions: computer_descriptions.txt ("+entries+") lines")


# Generate a file with the top 100 oldest computers that have authenticated to the domain within the last 30 days. This is useful for finding the oldest systems connected to AD as they likely have less controls (maybe missing EDR or logging) good spot for persistence
# MATCH (u:Computer) WHERE u.lastlogon > (datetime().epochseconds - (30 * 86400)) return u.name, datetime({epochSeconds:toInteger(u.lastlogon)}) as lastlogon, datetime({epochSeconds:toInteger(u.whencreated)}) as whencreated, u.operatingsystem ORDER BY datetime({epochSeconds:toInteger(u.whencreated)}) ASC LIMIT 100
def get_oldComps():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:Computer) WHERE u.lastlogon > (datetime().epochseconds - (30 * 86400)) return u.name as name, datetime({epochSeconds:toInteger(u.lastlogon)}) as lastlogon, datetime({epochSeconds:toInteger(u.whencreated)}) as whencreated, u.operatingsystem ORDER BY datetime({epochSeconds:toInteger(u.whencreated)}) ASC LIMIT 100")
        compold_file=open("top100_oldest_computers.txt", "w")
        compold_file.write("name, lastlogin, whencreated, os"+'\n')
        for record in result:

            if record["name"]:
                comp_name=record["name"]
            else:
                comp_name=""

            if record['lastlogon']:
                lastlogon=str(record["lastlogon"])
            else:
                lastlogon=""

            if record['whencreated']:
                whencreated=str(record['whencreated'])
            else:
                whencreated=""

            if record["u.operatingsystem"]:
                os=record["u.operatingsystem"]
            else:
                os=""

            compold_file.write(comp_name+", "+lastlogon+", "+whencreated+", "+os+"\n")

        compold_file.close()

    with open("top100_oldest_computers.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating the top 100 oldest computers that have recently authenticated to the domain (last 30 days) maybe lower security controls - top100_oldest_computers.txt ("+entries+") lines")



# Generate file with groups and descriptions: group_descriptions.txt
# MATCH (u:Group) return u.name, u.description
def get_groupDesc():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:Group) return u.name, u.description")
        group_file=open("group_descriptions.txt", "w")
        for record in result:
            if record["u.name"]:
                group_name=record["u.name"]
            else:
                group_name=""

            if record['u.description']:
                group_desc=record["u.description"]
            else:
                group_desc=""

            if len(group_desc) > 1:
                group_file.write(group_name+", "+group_desc+"\n")
            else:
                group_file.write(group_name+"\n")
        group_file.close()

    with open("group_descriptions.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating Groups + Descriptions: group_descriptions.txt ("+entries+") lines")



# Generate file with computers who have SPN records set who have recently authenticated to the domain (last 60 days)
# MATCH (c:Computer) MATCH WHERE c.lastlogon < (datetime().epochseconds - (60 * 86400)) return c.name, c.serviceprincipalnames
def get_compSPNs():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (c:Computer) WHERE c.lastlogon < (datetime().epochseconds - (60 * 86400)) return c.name, c.serviceprincipalnames")
        spn_file=open("computer_spns.txt", "w")
        for record in result:
            if record["c.name"]:
                comp_name=record["c.name"]
            else:
                comp_name=""

            if record['c.serviceprincipalnames']:
                spn=str(record["c.serviceprincipalnames"])
            else:
                spn=""

            if len(spn) > 1:
                spn_file.write(comp_name+", "+spn+"\n")
            else:
                spn_file.write(comp_name+"\n")
        spn_file.close()

    with open("computer_spns.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating Computer SPNs connected to AD last 60 days - useful for identifying servers + service offered: computer_spns.txt ("+entries+") lines")


# Generate a file with Groups + Descriptions where they have an 'admincount: true}: admin_groups.txt
# MATCH (u:Group {admincount: true}) return u.name
def get_adminGroups():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:Group {admincount: true}) return u.name, u.description")
        group_file=open("admin_groups.txt", "w")
        for record in result:
            if record["u.name"]:
                group_name=record["u.name"]
            else:
                group_name=""

            if record['u.description']:
                group_desc=record["u.description"]
            else:
                group_desc=""

            if len(group_desc) > 1:
                group_file.write(group_name+", "+group_desc+"\n")
            else:
                group_file.write(group_name+"\n")
        group_file.close()

    with open("admin_groups.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating Admin Groups (admincount: true): admin_groups.txt ("+entries+") lines")



# Generate a file with User + Descriptions where they have an 'admincount: true}: admin_users.txt
# MATCH (u:User {admincount: true}) return u.name
def get_adminUsers():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:User {admincount: true}) return u.name, u.description")
        userdesc_file=open("admin_users.txt", "w")
        for record in result:
            if record["u.name"]:
                user_name=record["u.name"]
            else:
                user_name=""

            if record['u.description']:
                user_desc=record["u.description"]
            else:
                user_desc=""

            if len(user_desc) > 1:
                userdesc_file.write(user_name+", "+user_desc+"\n")
            else:
                userdesc_file.write(user_name+"\n")
        userdesc_file.close()

    with open("admin_users.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating Admin Users (admincount: true): admin_users.txt ("+entries+") lines")


# Generate a file with a list of users who have extensive rights (DCSync|AllExtendedRights|GenericAll) within the domain and are admincount=false: dcsync-notadmin_domain.txt
# Q1 - Get Domains: MATCH (n:Domain) RETURN n.name
# Q2 - Get all the said permissions for each domain: MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain {name: '"+domain+"'}) WHERE n.admincount=false RETURN n.name
def get_dcsync():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (n:Domain) RETURN n.name")
        domains = []
        for record in result:
            domains.append(record["n.name"])

        for domain in domains:
            result = do_query(driver, "MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain {name: '"+domain+"'}) WHERE n.admincount=false RETURN n.name")
            dcsync_file=open("dcsync-notadmin_"+domain+".txt", "w")
            for record in result:
                if record["n.name"]:
                    dcsync_file.write(record["n.name"]+"\n")
                else:
                    dcsync_file.write("None"+"\n")
            dcsync_file.close()

            with open("dcsync-notadmin_"+domain+".txt", "r") as fp:
                entries = str(len(fp.readlines()))
            print("[+] Generating Users with Admincount=false and DCSync|AllExtendedRights|GenericAll -> these are very likely problems: dcsync-notadmin_"+domain+".txt ("+entries+") lines")

# Generate a file with Enabled Users who have SPN records set: kerberoastable.txt
# MATCH (u:User {enabled: true}) WHERE u.hasspn=true RETURN u.name
def get_kerbUsers():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:User {enabled: true}) WHERE u.hasspn=true RETURN u.name")
        kerb_file=open("kerberoastable.txt", "w")
        for record in result:
            if record["u.name"]:
                user_name=record["u.name"]
            else:
                user_name=""
            kerb_file.write(user_name+"\n")
        kerb_file.close()

    with open("kerberoastable.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating Enabled Users with SPN Records (Kerberoastable): kerberoastable.txt ("+entries+") lines")


# Generate a file with Enabled Users who have {dontreqpreauth: true} : asprep_roast.txt
# MATCH (u:User {dontreqpreauth: true}) RETURN u.name
def get_asprepRoast():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (u:User {dontreqpreauth: true}) RETURN u.name")
        asp_file=open("asprep_roast.txt", "w")
        for record in result:
            if record["u.name"]:
                user_name=record["u.name"]
            else:
                user_name=""
            asp_file.write(user_name+"\n")
        asp_file.close()

    with open("asprep_roast.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating Users with DontReqPreAuth enabled (ASP-REP Roastable its not likely you'll see this): asprep_roast.txt ("+entries+") lines")



# Return objects with unconstrained delegration enabled which should really only be DCs
# MATCH (c {unconstraineddelegation:true}) return c.name
def get_unconstrainedDel():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (c {unconstraineddelegation:true}) return c.name")
        uncon_file=open("unconstrained_delegation.txt", "w")
        for record in result:
            if record["c.name"]:
                uncon_name=record["c.name"]
            else:
                uncon_name=""
            uncon_file.write(uncon_name+"\n")
        uncon_file.close()

    with open("unconstrained_delegation.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating list of objects with unconstrained delegation (should really only be DCs): unconstrained_delegation.txt ("+entries+") lines")


# Generate a list of enabled users with passwordlastset value greater than 365 days: enabled_users_passwordlastset_1yr.txt
# Query is long so not commented but its the query that is set to the variable "query" below
def get_pwdYear():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        query = '''MATCH (u:User {enabled: true}) WHERE u.pwdlastset > 0 
WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.pwdlastset) }) AS pwdlastset, duration.inDays(datetime({ epochSeconds:toInteger(u.pwdlastset) }), date()).days AS days_since_pwdlastset
WHERE days_since_pwdlastset > 365
RETURN name, days_since_pwdlastset, pwdlastset 
ORDER BY days_since_pwdlastset DESC'''
        pwd_file=open("enabled_users_passwordlastset_1yr.txt", "w")
        result = do_query(driver, query)
        for record in result:
            name = record["name"]
            pwdlastset=record["pwdlastset"]
            days_since_pwlastset=record["days_since_pwdlastset"]
            pwd_file.write(name+", "+str(days_since_pwlastset)+", "+str(pwdlastset)+"\n")
        pwd_file.close()

    with open("enabled_users_passwordlastset_1yr.txt", "r") as fp:
        entries = str(len(fp.readlines())) 
    print("[+] Generating list of enabled users with passwordlastset value greater than 365 days: enabled_users_passwordlastset_1yr.txt ("+entries+") lines")


# Generate a list of enabled Users who have never logged on: enabledacct_never_loggedon.txt"
# MATCH (n:User) WHERE n.lastlogontimestamp=-1.0 AND n.enabled=TRUE RETURN n.name
def get_userNoLogon():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (n:User) WHERE n.lastlogontimestamp=-1.0 AND n.enabled=TRUE RETURN n.name")
        user_file=open("enabledacct_never_loggedon.txt", "w")
        for record in result:
            if record["n.name"]:
                user_name=record["n.name"]
            else:
                user_name=""
            user_file.write(user_name+"\n")
        user_file.close()

    with open("enabledacct_never_loggedon.txt", "r") as fp:
        entries = str(len(fp.readlines())) 
    print("[+] Generating Enabled Users who have never logged on: enabledacct_never_loggedon.txt ("+entries+") lines")


# Query to get computers with LAPS disabled: computers_laps_disabled.txt
# MATCH p = (d:Domain)-[r:Contains*1..]->(c:Computer) WHERE c.haslaps = false AND c.enabled = true RETURN c.name, c.description
def get_computersNoLAPS():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH p = (d:Domain)-[r:Contains*1..]->(u:Computer) WHERE u.haslaps = false AND u.enabled = true RETURN u.name, u.description")
        comp_file=open("computers_laps_disabled.txt", "w")
        for record in result:
            if record["u.name"]:
                comp_name=record["u.name"]
            else:
                comp_name=""

            if record['u.description']:
                comp_desc=record["u.description"]
            else:
                comp_desc=""

            if len(comp_desc) > 1:
                comp_file.write(comp_name+", "+comp_desc+"\n")
            else:
                comp_file.write(comp_name+"\n")
        comp_file.close()

    with open("computers_laps_disabled.txt", "r") as fp:
        entries = str(len(fp.readlines()))   
    print("[+] Generating Computers with LAPS Disabled: computers_laps_disabled.txt ("+entries+") lines")


### This function is only invoked if `--pathing` is selected on the CLI due to the time it takes to run
# Build a list of High Value Targets (HVTs) in Q1, and then interate through their inbound rights in Q2 (this is the one that takes a bit)
# Q1 - MATCH (m) WHERE m.highvalue=TRUE RETURN m.name, m.objectid
# Q2 - MATCH (n) WHERE NOT (n.objectid='"+objectid+"') WITH n MATCH p = shortestPath((n)-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:Group {objectid: '"+objectid+"'})) RETURN count(n.name)
def get_hvtRights():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (m) WHERE m.highvalue=TRUE RETURN m.name, m.objectid")
        hvt_file=open("hvt_inbound_rights.txt", "w")
        for record in result:
          if record["m.name"]:
              hvt_name = record["m.name"]
              objectid = record["m.objectid"]
              result1 = do_query(driver, "MATCH (n) WHERE NOT (n.objectid='"+objectid+"') WITH n MATCH p = shortestPath((n)-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:Group {objectid: '"+objectid+"'})) RETURN count(n.name)")
              for record1 in result1:
                  if record1["count(n.name)"]:
                      inbound_rights=str(record1["count(n.name)"])
                      hvt_file.write("[-] HVT: "+hvt_name+" inbound rights: "+inbound_rights+"\n")
        hvt_file.close()

    with open("hvt_inbound_rights.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating list of High Value Targets (HVT) and inbound rights: hvt_inbound_rights.txt ("+entries+") lines")



### This function is only invoked if `--pathing` is selected on the CLI due to the time it takes to run
# Multiple query to build a list of GPOs then find inbound rights
# Q1 - MATCH (m:GPO) RETURN m.name, m.objectid
# Q2 - MATCH (n) WHERE NOT (n.objectid='"+objectid+"') WITH n MATCH p = shortestPath((n)-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:GPO {objectid: '"+objectid+"'})) RETURN count(n.name)
def get_gpoRights():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (m:GPO) RETURN count(m.name)")
        for record in result:
            if record["count(m.name)"]:
                count = str(record["count(m.name)"])
            else:
                count="0"

        result = do_query(driver, "MATCH (m:GPO) RETURN m.name, m.objectid")
        gpo_file=open("gpo_inbound_rights.txt", "w")

        for record in result:
          if record["m.name"]:
              gpo_name = record["m.name"]
              objectid = record["m.objectid"]
              result1 = do_query(driver, "MATCH (n) WHERE NOT (n.objectid='"+objectid+"') WITH n MATCH p = shortestPath((n)-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:GPO {objectid: '"+objectid+"'})) RETURN count(n.name)")
              for record1 in result1:
                  if record1["count(n.name)"]:
                      inbound_rights=str(record1["count(n.name)"])
                      gpo_file.write("[-] GPO: "+gpo_name+" inbound rights: "+inbound_rights+"\n")

        gpo_file.close()

    with open("gpo_inbound_rights.txt", "r") as fp:
        entries = str(len(fp.readlines()))   
    print("[+] Generating list of GPOs and inbound rights (Total GPOs: "+count+" this will take a bit ~5-10secs per GPO): gpo_inbound_rights.txt ("+entries+") lines")


# Multiple query to get the transitive outbound rights for a set of groups defined as "starter_groups" list below
# Q1 - Get Domains: MATCH (n:Domain) RETURN n.name
# Q2 - Get Group Objectids: MATCH (n:Group {name:"+starter_group+"@"+domain+"}) RETURN n.objectid
# Q3 - Get Transitive Outbound rights: MATCH (n) WHERE NOT n.objectid="+objectid+" WITH n MATCH p = shortestPath((g:Group {objectid: "+objectid+"})-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n)) RETURN count(p)
def get_startingPoints():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        # List of common starting points:
        starter_groups=['DOMAIN USERS', 'EVERYONE', 'DOMAIN COMPUTERS']
        starter_file=open("common_groups_outboundrights.txt", "w")
        result = do_query(driver, "MATCH (n:Domain) RETURN n.name")
        for record in result:
            if record['n.name']:
                domain=record['n.name']
            else:
                print("No Domains Found")
                continue
            # Get the group objectid for each starter_group:
            for starter_group in starter_groups:
                result1= do_query(driver, "MATCH (n:Group {name:'"+starter_group+"@"+domain+"'}) RETURN n.objectid")
                for record1 in result1:
                    if record1["n.objectid"]:
                        # Get the transitive outbound rights for each starter_group:
                        objectid=record1["n.objectid"]
                        result2=do_query(driver, "MATCH (n) WHERE NOT n.objectid='"+objectid+"' WITH n MATCH p = shortestPath((g:Group {objectid: '"+objectid+"'})-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n)) RETURN count(p)")
                        for record2 in result2:
                            if record2['count(p)']:
                                outbound_rights = str(record2['count(p)'])
                            else:
                                outbound_rights = "0"
                            starter_file.write("[+] "+starter_group+"@"+domain+" outbound rights: "+outbound_rights+"\n")

        starter_file.close()

    with open("common_groups_outboundrights.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating a file with common groups and their transitive outbound rights - investigate for anomalies: common_groups_outboundrights.txt ("+entries+") lines")


def get_serverRDP():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (m:Computer) WHERE m.operatingsystem CONTAINS 'Server' return m.name, m.objectid")
        server_rdp_file=open("server_RDP.txt", "w")
        for record in result:
          if record["m.name"]:
              server_name = record["m.name"]
              objectid = record["m.objectid"]
              result1 = do_query(driver, "MATCH p=(n)-[r:CanRDP]->(m:Computer {objectid: '"+objectid+"'}) RETURN count(p)")
              for record1 in result1:
                  if record1["count(p)"]:
                      rdp_rights=str(record1["count(p)"])
                      server_rdp_file.write("[-] Server: "+server_name+" First Degree RDP Users: "+rdp_rights+"\n")
        server_rdp_file.close()

    with open("server_RDP.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating a List of Servers with First Degree RDP Rights: server_RDP.txt ("+entries+") lines")


def get_userOutboundRights_firstdegree():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (m:User) return m.name, m.objectid")
        user_outbound_file=open("users_outbound_1st_rights.txt", "w")
        for record in result:
          if record["m.name"]:
              username = record["m.name"]
              objectid = record["m.objectid"]
              result1 = do_query(driver, "MATCH p=(u:User {objectid: '"+objectid+"'})-[r1]->(n) WHERE r1.isacl=true RETURN count(p)")
              for record1 in result1:
                  if record1["count(p)"]:
                      firstdegree_rights=str(record1["count(p)"])
                      user_outbound_file.write("[-] User: "+username+" First Degree Outbound Rights: "+firstdegree_rights+"\n")
        user_outbound_file.close()

    with open("users_outbound_1st_rights.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating a List of Users with First Degree Outbound Rights: users_outbound_1st_rights.txt ("+entries+") lines")


def get_serverAdminGroup():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (m:Group) return m.name, m.objectid")
        server_admin_file=open("server_admin_bygroup.txt", "w")
        for record in result:
          if record["m.name"]:
              group_name = record["m.name"]
              objectid = record["m.objectid"]
              result1 = do_query(driver, "MATCH p = (g1:Group {objectid: '"+objectid+"'})-[r2:AdminTo]->(n:Computer) RETURN count(p)")
              for record1 in result1:
                  if record1["count(p)"]:
                      admin_rights=str(record1["count(p)"])
                      server_admin_file.write("[-] Group: "+group_name+" First Degree Admin Rights: "+admin_rights+"\n")
        server_admin_file.close()

    with open("server_admin_bygroup.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating a List of Groups with First Degree Admin Rights: server_admin_bygroup.txt ("+entries+") lines")


def get_userOutboundRights_trans():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (m:User) return m.name, m.objectid")
        user_outbound_file=open("users_outbound_trans_rights.txt", "w")
        for record in result:
          if record["m.name"]:
              username = record["m.name"]
              objectid = record["m.objectid"]
              result1 = do_query(driver, "MATCH (n) WHERE NOT n.objectid='"+objectid+"' MATCH p=shortestPath((u:User {objectid: '"+objectid+"'})-[r1:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n)) RETURN count(p)")
              for record1 in result1:
                  if record1["count(p)"]:
                      trans_rights=str(record1["count(p)"])
                      user_outbound_file.write("[-] User: "+username+" Transitive Outbound Rights: "+trans_rights+"\n")
        user_outbound_file.close()

    with open("users_outbound_trans_rights.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating a List of Users with Transitive Outbound Rights: users_outbound_trans_rights.txt ("+entries+") lines")


def get_computerOutboundRights_trans():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (m:Computer) return m.name, m.objectid")
        comp_outbound_file=open("comp_outbound_trans_rights.txt", "w")
        for record in result:
          if record["m.name"]:
              comp_name = record["m.name"]
              objectid = record["m.objectid"]
              result1 = do_query(driver, "MATCH (n) WHERE NOT n.objectid='"+objectid+"' MATCH p=shortestPath((u:Computer {objectid: '"+objectid+"'})-[r1:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n)) RETURN count(p)")
              for record1 in result1:
                  if record1["count(p)"]:
                      trans_rights=str(record1["count(p)"])
                      comp_outbound_file.write("[-] Computer: "+comp_name+" Transitive Outbound Rights: "+trans_rights+"\n")
        comp_outbound_file.close()

    with open("comp_outbound_trans_rights.txt", "r") as fp:
        entries = str(len(fp.readlines()))
    print("[+] Generating a List of Computers with Transitive Outbound Rights: comp_outbound_trans_rights.txt ("+entries+") lines")




# Function is invoked with CLI switch "--dump" this is designed to cleanly print out all the queries performed by the tool
# This way a user can use these in Neo4j/BloodHound and and more easily modify them as needed
def dumpQuery():
    queries = '''
Query to retrieve Domain Controllers:
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' return c1.name

Query to parse out Domains:
MATCH (n:Domain) RETURN n.name

Query to get number of total computers:
MATCH (u:Computer) return count(u)

Query to print number of sessions:
MATCH (c:Computer)-[:HasSession]->(u:User) return count(c)

Query to print number of Users:
MATCH (u:User) return count(u)

Query to print number of Enabled Users:
MATCH (u:User {enabled: true}) return count(u)

Query to print number of owned users:
MATCH (m:User) WHERE m.owned=TRUE RETURN count(m)

Query to get Domain Admins (DAs):
MATCH p=(n:Group)<-[:MemberOf*1..]-(m) WHERE n.objectid =~ '(?i)S-1-5-.*-512' RETURN m.name

Query to get Owned Users with 'admincount: true':
MATCH (m:User {enabled: true, admincount: true}) WHERE m.owned=TRUE RETURN m

Query to get all Domain Admin (DA) sessions -> Reach a DA can potentially PrivEsc:
MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = (c:Computer)-[:HasSession]->(u) RETURN c.name, u.name

Query to list all sessions:
MATCH (c:Computer)-[:HasSession]->(u:User) return c.name, u.name

Query to list of Certificate Templates that interesting users have inbound rights to (Not: DAs, EAs, DCs, Administrators, etc.) - this should be interesting paths to control the certifiate template to exploit it to take over domain:
MATCH p = (n)-[r:AddMember|AddSelf|WriteSPN|AddKeyCredentialLink|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(g:GPO) WHERE NOT (n.name CONTAINS 'DOMAIN ADMINS' or n.name CONTAINS 'ENTERPRISE ADMINS' or n.name CONTAINS 'ADMINISTRATORS' or n.name CONTAINS 'DOMAIN CONTROLLERS') AND (g.name IS NOT NULL) RETURN g.name

Query to get list of enabled certificate templates:
MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.Enabled RETURN n.name

Query to get list of Enroll and AutoEnroll permissions for each cert template - Please note you will need to change [cert_temp_name] with the GPO name:
MATCH p=(g)-[:Enroll|AutoEnroll]->(n:GPO {name:'[cert_temp_name]'}) WHERE n.type = 'Certificate Template' return g.name

Query to get users and descriptions:
MATCH (u:User) return u.name, u.description

Query to get computers and descriptions:
MATCH (u:Computer) return u.name, u.description

Query to get groups and descriptions:
MATCH (u:Group) return u.name, u.description

Query to get computers who have SPN records set who have recently authenticated to the domain (last 60 days):
MATCH (c:Computer) MATCH WHERE c.lastlogon < (datetime().epochseconds - (60 * 86400)) return c.name, c.serviceprincipalnames

Query to get Groups + Descriptions where they have an admincount: true:
MATCH (u:Group {admincount: true}) return u.name

Query to get User + Descriptions where they have an admincount: true:
MATCH (u:User {admincount: true}) return u.name

Query to get all users that have local admin rights:
MATCH p=(m:User)-[r:AdminTo]->(n:Computer) RETURN m.name, n.name

Query to get all the said permissions for a given domain - please note remove [domain] and replace with the actual domain: 
MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain {name: '[domain]'}) WHERE n.admincount=false RETURN n.name

Query to list all enabled Users who have SPN records set (kerberoastable users):
MATCH (u:User {enabled: true}) WHERE u.hasspn=true RETURN u.name

Query to list all enabled Users who have {dontreqpreauth: true} (aspreproastable users - very rare):
MATCH (u:User {dontreqpreauth: true}) RETURN u.name

Query to list all objects with unconstrained delegration enabled which should really only be DCs:
MATCH (c {unconstraineddelegation:true}) return c.name

Query to list list of enabled users with passwordlastset value greater than 365 days:
MATCH (u:User {enabled: true}) WHERE u.pwdlastset > 0 
WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.pwdlastset) }) AS pwdlastset, duration.inDays(datetime({ epochSeconds:toInteger(u.pwdlastset) }), date()).days AS days_since_pwdlastset
WHERE days_since_pwdlastset > 365
RETURN name, days_since_pwdlastset, pwdlastset 
ORDER BY days_since_pwdlastset DESC

Query to list of enabled Users who have never logged on -> these may have default or weak passwords:
MATCH (n:User) WHERE n.lastlogontimestamp=-1.0 AND n.enabled=TRUE RETURN n.name

Query to get computers with LAPS disabled -> good targets for local admin spraying:
MATCH p = (d:Domain)-[r:Contains*1..]->(c:Computer) WHERE c.haslaps = false AND c.enabled = true RETURN c.name, c.description

Query to get a list of High Value Targets (HVTs) and their objectid:
MATCH (m) WHERE m.highvalue=TRUE RETURN m.name, m.objectid

Query to get the inbound rights associated with a given group based on the groups "objectid". Please note you will need to replace [objectid] with the actual group's objectid (reference above query):
MATCH (n) WHERE NOT (n.objectid='"+objectid+"') WITH n MATCH p = shortestPath((n)-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:Group {objectid: '[objectid]'})) RETURN count(n.name)

Query to get a list of GPOs and objectid:
MATCH (m:GPO) RETURN m.name, m.objectid

Query to get owners of the computer objects within the current dataset:
MATCH p = (n)-[r:Owns]->(g:Computer) RETURN n.name, g.name

Query to get owners of the computer objects where admincount is false:
MATCH p = (n)-[r:Owns]->(g:Computer) WHERE n.admincount=false RETURN p

Query to get the inbound rights associated with a given GPO based on the groups "objectid". Please note you will need to replace [objectid] with the actual group's objectid (reference above query):
MATCH (n) WHERE NOT (n.objectid='"+objectid+"') WITH n MATCH p = shortestPath((n)-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:GPO {objectid: '"+objectid+"'})) RETURN count(n.name)

Query to get the transitive outbound rights for a given group based on the objectid. You will need to modify the 'objectid' variable below
MATCH (n) WHERE NOT n.objectid="+objectid+" WITH n MATCH p = shortestPath((g:Group {objectid: "+objectid+"})-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n)) RETURN count(p)

Query to get the top 100 oldest computers that have recently authenticated to the network (within the last 30 days) - these may lack EDR or other security controls and could be a good spot for priv esc or persistence:
MATCH (u:Computer) WHERE u.lastlogon > (datetime().epochseconds - (30 * 86400)) return u.name as name, datetime({epochSeconds:toInteger(u.lastlogon)}) as lastlogon, datetime({epochSeconds:toInteger(u.whencreated)}) as whencreated, u.operatingsystem ORDER BY datetime({epochSeconds:toInteger(u.whencreated)}) ASC LIMIT 100
'''

    for line in queries.split("\n"):
        if line.startswith("Query"):
            print(colored(line.strip(), attrs=['bold']))
        else:
            print(line.strip())

def moreHelp():
    queries = '''
[+] Generating List of Domain Admin Sessions
- Explanation: Understanding the elevated sessions can help you discover more priv esc paths. Being able to reach the systems the DAs have sessions means you have a chance at stealing their token in memory (does require admin access)

[+] Generating List of all Sessions
- Explanation: Sessions in general are useful for expanding access.

[+] Generating list of certificate templates where interesting principals can modify (Not DA|EA|DC|Administrators)
- Explanation: Certificate templates provide a potential path to impersonate access as anyone in the domain. If you have permissions to reconfigure the cert template you can configure them to allow for impersonation.

[+] Generating list of certificate templates and list of principals with enroll rights
- Explanation: If a certificate template has theses permissions it can likely be abused to impersonate users within the domain.

[+] Generating Users + Descriptions
[+] Generating Computers + Descriptions
[+] Generating Groups + Descriptions
- Explanation: General understanding of the environment. Descriptions can be useful to understand the context of accounts, computers, and groups  or potentially reveal sensitive information.

[+] Generating Admin Users (admincount: true)
[+] Generating Admin Groups (admincount: true)
- Explanation: Understanding of privileged users and groups. These might be good targets to expand access.

[+] Generating List of users with local admin rights
- Explanation: Understanding of which users have explicit local admin rights. Might help expand access if you could gain access to these targets.

[+] Generating Computer SPNs connected to AD last 60 days
- Explanation: Useful for identifying servers + service being offered

[+] Generating Users with Admincount=false and DCSync|AllExtendedRights|GenericAll
- Explanation: These are very likely problems because they have extensive access over the domain but aren't marked properly for Admincount controls. Usually its easier to reach these accounts and they are certainly a misconfiguration. Most notably are Microsoft Azure Sync service accounts (MSOL_XXXX..) accounts that used to be configured poorly during the install of Azure Sync before 2017. These accounts linger on networks very often as admins are generally unaware the accounts were created.

[+] Generating Enabled Users with SPN Records (Kerberoastable)
- Explanation: These accounts allow any authenticated user to request a kerberos ticket for the SPN. The ticket is encrypted with the hash of the service account password. Attackers can attempt to crack these offline, and are often some of the first attacks conducted on a network to expand access. Detections should be in place to enumerate kerberoasting attempts to improve visibility into this potential attack.

[+] Generating Users with DontReqPreAuth enabled (ASP-REP Roastable its not likely you'll see this)
- Explanation: This is a configuration you'll likely not see but should still evaluate to ensure accounts aren't configured with kerberos preauthentication disabled. With this configuration an attacker can effectively get the users hash via AS-REP message from the DC.

[+] Generating list of objects with unconstrained delegation (should really only be DCs)
- Explanation: Objects with this configuration shoud really be the domain controllers as they allow impersonation of others within the domain (unconstrained delegation). Objects that aren't DC's with this permission should be evaluabled and likely modified to constrained delegation.

[+] Generating List of Owners for the Computers in AD
- Explanation: Understanding who owns computers can provide intersting access / abuse paths based on current access levels. Evaluate if ownership to said computers makes sense. Often you'll see a single account that is otherwise not interesting but owns most of the computers in the environment as it was used to join the computers to the domain. Now that account might be a target for escalation attacks/attempts that might not otherwise jump out as interesting.

[+] Generating a List of Servers with First Degree RDP Rights
- Explanation: This might expose systems that have excessive RDP rights. If you see most servers have 10 inbound rights to RDP and one has 1,000 this might be a significant misconfiguration that should be addressed.

[+] Generating a List of Groups with First Degree Admin Rights
- Explanation: This should be a fairly small list as it will be any group who is assigned directly to admin over a computer. Misconfigurations can bubble out here because "Domain Users" could be set to admin several systems, which is a configuration that would not make sense. Ensure the rights track and make sense, example Domain Admins being admin to admin a server does, but domain users does not.

[+] Generating list of enabled users with passwordlastset value greater than 365 days
- Explanation: This is a list of users who likely do not meet the organizations password policy and may have weaker passwords or be a violation in itself since they might be required to change the passwords more frequently. You will often see service accounts here and the proper configuration should be to leverage Microsoft Managed Service account configuration which would rotate the password automatically.

[+] Generating Enabled Users who have never logged on
- Explanation: This is a list of users who likely aren't required for operations and can potentially be removed. To an attacker they  could be a way to expand access as they are more likely to be configured with a default password for the domain/organization.

[+] Generating Computers with LAPS Disabled
- Explanation: This will print out all computers wihout LAPS enabled which is a way to more securely manage local admin accounts to computers. Please note that there could be Linux and MAC systems here that wouldn't make sense to enable LAPS. Evaluate the systems here to see if Windows systems do not make use of LAPS.

[+] Generating the top 100 oldest computers that have recently authenticated to the domain (last 30 days)
- Explanation: These older computers might be good targets for version specific flaws or misconfigurations.


--pathing Queries/Resuls: These queries can take a bit to run id wager probably ~30mins depending on the size of the network

[+] Generating a List of Users with First Degree Outbound Rights
- Explanation: This query takes a little longer to run but will give you visibility into what a user is directly assigned permissions in the environment. Look for anomalies like Bob is a regular user who has a lot more rights than others.

[+] Generating list of GPOs and inbound rights
- Explanation: Looking for GPOs that have a lot of inbound rights. You might find one is far too open to users to modify and allow for abuse / escalation paths due to permissions being too open.

[+] Generating list of High Value Targets (HVT) and inbound rights
- Explanation: Looking at all the objects marked as HVT within BloodHound (Domain Admins, etc.) and their inbound rights, look for anomalies here as it might show an HVT that as far too open permissions.


--transitive Queries/Resuls: These queries will take very likely over 5hrs for most networks. This is a run it overnight kinda thing.

[+] Generating a file with common groups and their transitive outbound rights
- Explanation: Essentially the outbound rights for the common groups all users are generally in within the domain. This can be a great place to identify misconfigurations that apply to nearly all domain users.

[+] Generating a List of Users with Transitive Outbound Rights
- Explanation: Looking at all the effective permissions for every user. You can then audit these to see what doesn't make sense. Why does someone in HR have nearly the same outbound rights as a DA? 

[+] Generating a List of Computers with Transitive Outbound Rights
- Explanation: Same logic as the above Users transitive outbound rights but applied to computer objects. You will find generally much less variability here.

'''

    for line in queries.split("\n"):
        if line.startswith("- Explanation"):
            print(colored(line.strip(), attrs=['bold']))
        else:
            print(line.strip())



def checkConnection():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        driver.verify_connectivity()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='ad-recon',
                    description='Quickly triage BloodHound data via Neo4j queries',
                    epilog='ad-recon --pathing (optional) --dump (optional) --transitive (optional)')

    parser.add_argument('--pathing', help='Run pathing queries - takes longer', required=False, action='store_true')
    parser.add_argument('--transitive', help='Run transitive queries - takes even longer', required=False, action='store_true')  
    parser.add_argument('--dump', help='Dumps raw Cypher queries to more easily modify and use in BH/Neo4j. If selected no queries are performed', required=False, action='store_true')
    parser.add_argument('--morehelp', help='Provides context into how to analyze the output files', required=False, action='store_true')
    args = vars(parser.parse_args())

    st = time.time()

    if args['morehelp'] == True:
        moreHelp()
        sys.exit(0)

    if args['dump'] == True:
        dumpQuery()
        sys.exit(0)

    checkConnection()
    get_domains()
    get_DCs()
    get_computers()
    get_sessionCount()
    get_users()
    get_Enabledusers()
    get_ownedUsersCount()
    get_ownedUsers()
    get_daSessions()
    get_sessions()
    get_certTempNotAdmin()
    get_certEnroll()
    get_userDesc()
    get_compDesc()
    get_adminUsers()
    get_adminGroups()
    get_localAdmins()
    get_groupDesc()
    get_compSPNs()
    get_dcsync()
    get_kerbUsers()
    get_asprepRoast()
    get_unconstrainedDel()
    get_compOwners()
    get_serverRDP()
    get_serverAdminGroup()
    get_pwdYear()
    get_userNoLogon()
    get_computersNoLAPS()
    get_oldComps()

    if args['pathing'] == True:
        print("----")
        print("Pathing Queries these will take longer")
        print("----")
        get_userOutboundRights_firstdegree()
        get_hvtRights()
        get_gpoRights()

    if args['transitive'] == True:
        print("----")
        print("Transitive Query will take a long time...probably like 5hrs")
        print("----")
        get_startingPoints()
        get_computerOutboundRights_trans()
        get_userOutboundRights_trans()

    et = time.time()
    elapsed = et-st
    print("")
    print(f"took {elapsed} seconds to complete")

'''
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (n:User)WHERE n.hasspn=true RETURN n")
        for record in result:
            n = record['n']
            print(f"User: {n.get('samaccountname')}, adminCount: {n.get('admincount')}")
'''
