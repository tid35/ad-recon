from neo4j import RoutingControl
from termcolor import colored
import itertools, sys, toml

# Import config variables
config = toml.load('config.toml')

def do_query(driver, query):
    local_config = config
    #config = toml.load('config.toml')
    records, _, _ = driver.execute_query(
        query,
        database = local_config['bloodhound']['DATABASE'] ,
        #routing_=RoutingControl.READ,
        routing_='r',
    )
    return records


# Query to retrieve Domain Controllers
# MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' return c1.name
def get_DCs(driver):
    result = do_query(driver, "MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' return c1.name")
    print("Domain Controllers: ")
    dcs = []
    for record in result:
        print(record["c1.name"])
        dcs.append(record["c1.name"])
    print("-----")
    return dcs


# Query to parse out Domains
# MATCH (n:Domain) RETURN n.name
def get_domains(driver):
    result = do_query(driver, "MATCH (n:Domain) RETURN n.name")

    domains = []
    print("Domains Found: ")
    for record in result:
        if record['n.name']:
            print(record["n.name"])
            domains.append(record["n.name"])
        else:
            print("No Domain Detected please check to ensure database setup properly and data imported")
            sys.exit(0)
    print("-----")
    return domains

# Query to get number of total computers
# MATCH (u:Computer) return count(u)
def get_computers(driver):
    result = do_query(driver, "MATCH (u:Computer) return count(u)")
    for record in result:
        if record["count(u)"]:
            count=record["count(u)"]
        else:
            count = 0
    if len(str(count)) > 1:
        print("Number of Computers: "+str(count))
    return count

# Query to print number of sessions
# MATCH (c:Computer)-[:HasSession]->(u:User) return count(c)
def get_sessionCount(driver):
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
    return int(count)

# Query to print number of Users
# MATCH (u:User) return count(u)
def get_users(driver):
    result = do_query(driver, "MATCH (u:User) return count(u)")
    for record in result:
        if record["count(u)"]:
            count=record["count(u)"]
        else:
            count="0"

    print("Number of Users: "+str(count))
    return int(count)


# Query to print number of Enabled Users
# MATCH (u:User {enabled: true}) return count(u)
def get_Enabledusers(driver):
    result = do_query(driver, "MATCH (u:User {enabled: true}) return count(u)")
    for record in result:
        if record["count(u)"]:
            count=record["count(u)"]
        else:
            count="0"

    print("Number of Enabled Users: "+str(count))
    return int(count)


# Print number of owned users:
# MATCH (m:User) WHERE m.owned=TRUE RETURN count(m)
def get_ownedUsersCount(driver):
    result = do_query(driver, "MATCH (m:User) WHERE m.owned=TRUE RETURN count(m)")
    for record in result:
        if record["count(m)"]:
            count=record["count(m)"]
        else:
            count="0"
    print("Number of Owned Users: "+str(count))
    return int(count)


# Getting DAs:
# Q1: MATCH p=(n:Group)<-[:MemberOf*1..]-(m) WHERE n.objectid =~ '(?i)S-1-5-.*-512' RETURN m.name
# Getting Owned Users with 'admincount: true'
# Q2: MATCH (m:User {enabled: true, admincount: true}) WHERE m.owned=TRUE RETURN m
def get_ownedUsers(driver):
    das=[]
    result = do_query(driver, "MATCH p=(n:Group)<-[:MemberOf*1..]-(m) WHERE n.objectid =~ '(?i)S-1-5-.*-512' RETURN m.name")
    for record in result:
        if record["m.name"]:
            das.append(record["m.name"])
        else:
            das.append("None")

    result = do_query(driver, "MATCH (m:User {enabled: true, admincount: true}) WHERE m.owned=TRUE RETURN m.name")
    if result:
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
def get_daSessions(driver):
    result = do_query(driver, "MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = (c:Computer)-[:HasSession]->(u) RETURN c.name, u.name")
    das_file=open(config['bloodhound']['OUTPUT_DIR'] + "/da_sessions.txt", "w")
    for record in result:
        if record["u.name"]:
            user_name=record["u.name"]
            if record["c.name"]:
                computer_name=record["c.name"]
            else:
                computer_name="NULL"

            das_file.write("[*] Computer: "+str(computer_name)+" has Domain Admin Session: "+user_name+"\n")

    das_file.close()

    print("[+] Generating Domain Admin Sessions: da_sessions.txt ("+str(len(result))+") lines")


# Generate a file with all the owners of the the computer objects within current dataset
# MATCH p = (n)-[r:Owns]->(g:Computer) RETURN n.name, g.name
# You can also check out admincount=false: MATCH p = (n)-[r:Owns]->(g:Computer) WHERE n.admincount=false RETURN p
def get_compOwners(driver):
    result = do_query(driver, "MATCH p = (n)-[r:Owns]->(g:Computer) RETURN n.name, g.name")
    owner_file=open(config['bloodhound']['OUTPUT_DIR'] + "/comp_owners.txt", "w")
    for record in result:
        if record["n.name"]:
            user_name=record["n.name"]
            computer_name=record["g.name"]
            owner_file.write("User: "+user_name+" owns: "+computer_name+"\n")
    owner_file.close()

    print("[+] Generating Owners for the Computers in AD: comp_owners.txt ("+str(len(result))+") lines")



# Generate file with all sessions
# MATCH (c:Computer)-[:HasSession]->(u:User) return c.name, u.name
def get_sessions(driver):
    result = do_query(driver, "MATCH (c:Computer)-[:HasSession]->(u:User) return c.name, u.name")
    session_file=open(config['bloodhound']['OUTPUT_DIR'] + "/sessions_all.txt", "w+")
    for record in result:
        if record["u.name"]:
            user_name=record["u.name"]
        else:
            user_name = "NULL"
        if record["c.name"]:
            computer_name=record["c.name"]
        else:
            computer_name="NULL"
        session_file.write("[*] Computer: "+computer_name+" has session from user: "+user_name+"\n")
    session_file.close()

    print("[+] Generating all Sessions: sessions_all.txt ("+str(len(result))+") lines")


# Generate file with all users that have local admin rights:
# MATCH p=(m:User)-[r:AdminTo]->(n:Computer) RETURN m.name, n.name
def get_localAdmins(driver):
    result = do_query(driver, "MATCH p=(u:User)-[r:AdminTo]->(c:Computer) RETURN u.name, c.name")
    localadmins_file=open(config['bloodhound']['OUTPUT_DIR'] + "/users_localadmins.txt", "w")
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

    print("[+] Generating users with local admin rights: users_localadmins.txt ("+str(len(result))+") lines")



# Generate a file with a list of Certificate Templates that interesting users have inbound rights to (Not: DAs, EAs, DCs, Administrators, etc.) - this should be interesting paths to control the certifiate template to exploit it to take over domain
# MATCH p = (n)-[r:AddMember|AddSelf|WriteSPN|AddKeyCredentialLink|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(g:GPO) WHERE NOT (n.name CONTAINS 'DOMAIN ADMINS' or n.name CONTAINS 'ENTERPRISE ADMINS' or n.name CONTAINS 'ADMINISTRATORS' or n.name CONTAINS 'DOMAIN CONTROLLERS') AND (g.name IS NOT NULL) RETURN g.name
def get_certTempNotAdmin(driver):
    ct=[]
    result = do_query(driver, "MATCH p = (n)-[r:AddMember|AddSelf|WriteSPN|AddKeyCredentialLink|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(g:GPO) WHERE NOT (n.name CONTAINS 'DOMAIN ADMINS' or n.name CONTAINS 'ENTERPRISE ADMINS' or n.name CONTAINS 'ADMINISTRATORS' or n.name CONTAINS 'DOMAIN CONTROLLERS') AND (g.name IS NOT NULL) RETURN g.name")
    for record in result:
        if record["g.name"]:
            ct.append(record["g.name"])
        else:
            ct.append("None")

    cert_file=open(config['bloodhound']['OUTPUT_DIR'] + "/vuln_certs.txt", "w")
    ct_results = [(g[0], len(list(g[1]))) for g in itertools.groupby(ct)]
    for line in ct_results:
        line=list(line)
        certtemp=line[0]
        count=line[1]
        cert_file.write(str(certtemp)+"\t"+str(count)+" inbound rights"+"\n")
    cert_file.close()
    print("[+] Generating Certificate Templates Where Interesting Principals Can Modify (Not DA|EA|DC|Administrators) - Investigate these inbound rights: vuln_certs.txt ("+str(len(result))+") lines")


# Multiple stage query to generate a list of certificate templates and list of principals with enroll rights > cert_enroll_permissions.txt
# Q1 - Generate a list of enabled certificate templates: MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.Enabled RETURN n.name 
# Q2 - Getting Enroll and AutoEnroll permissions for each cert template: MATCH p=(g)-[:Enroll|AutoEnroll]->(n:GPO {name:'cert_temp_name'}) WHERE n.type = 'Certificate Template' return g.name
def get_certEnroll(driver):
    cert_temp=[]
    result = do_query(driver, "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.Enabled RETURN n.name")
    for record in result:
        if record["n.name"]:
            cert_temp.append(record["n.name"])
        else:
            cert_temp.append("NULL")

    cert_enroll = open(config['bloodhound']['OUTPUT_DIR'] + "/cert_enroll_permissions.txt", "w")
    for cert in cert_temp:
        principals=[]
        result = do_query(driver, "MATCH p=(g)-[:Enroll|AutoEnroll]->(n:GPO {name:'"+cert+"'}) WHERE n.type = 'Certificate Template' return g.name")
        for record in result:
            if record['g.name']:
                principals.append(record['g.name'])
        cert_enroll.write("[+] Certificate Template: "+cert+" \t Enroll Permissions: "+", ".join(principals).strip(",")+"\n")
    cert_enroll.close()

    print("[+] Generating Certificate Templates and Principals with Enroll Rights: cert_enroll_permissions.txt ("+str(len(result))+") lines")


# Generate file with users and descriptions: user_descriptions.txt
# MATCH (u:User) return u.name, u.description
def get_userDesc(driver):
    result = do_query(driver, "MATCH (u:User) return u.name, u.description")
    userdesc_file=open(config['bloodhound']['OUTPUT_DIR'] + "/user_descriptions.txt", "w")
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

    print("[+] Generating Users + Descriptions: user_descriptions.txt ("+str(len(result))+") lines")



# Generate file with computers and descriptions: computer_descriptions.txt
# MATCH (u:Computer) return u.name, u.description
def get_compDesc(driver):
    result = do_query(driver, "MATCH (u:Computer) return u.name, u.description")
    comp_file=open(config['bloodhound']['OUTPUT_DIR'] + "/computer_descriptions.txt", "w")
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

    print("[+] Generating Computers + Descriptions: computer_descriptions.txt ("+str(len(result))+") lines")


# Generate a file with the top 100 oldest computers that have authenticated to the domain within the last 30 days. This is useful for finding the oldest systems connected to AD as they likely have less controls (maybe missing EDR or logging) good spot for persistence
# MATCH (u:Computer) WHERE u.lastlogon > (datetime().epochseconds - (30 * 86400)) return u.name, datetime({epochSeconds:toInteger(u.lastlogon)}) as lastlogon, datetime({epochSeconds:toInteger(u.whencreated)}) as whencreated, u.operatingsystem ORDER BY datetime({epochSeconds:toInteger(u.whencreated)}) ASC LIMIT 100
def get_oldComps(driver):
    result = do_query(driver, "MATCH (u:Computer) WHERE u.lastlogon > (datetime().epochseconds - (30 * 86400)) return u.name as name, datetime({epochSeconds:toInteger(u.lastlogon)}) as lastlogon, datetime({epochSeconds:toInteger(u.whencreated)}) as whencreated, u.operatingsystem ORDER BY datetime({epochSeconds:toInteger(u.whencreated)}) ASC LIMIT 100")
    compold_file=open(config['bloodhound']['OUTPUT_DIR'] + "/top100_oldest_computers.txt", "w")
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

    print("[+] Generating the top 100 oldest computers that have recently authenticated to the domain (last 30 days) maybe lower security controls - top100_oldest_computers.txt ("+str(len(result))+") lines")


# Generate file with groups and descriptions: group_descriptions.txt
# MATCH (u:Group) return u.name, u.description
def get_groupDesc(driver):
    result = do_query(driver, "MATCH (u:Group) return u.name, u.description")
    group_file=open(config['bloodhound']['OUTPUT_DIR'] + "/group_descriptions.txt", "w")
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

    print("[+] Generating Groups + Descriptions: group_descriptions.txt ("+str(len(result))+") lines")


# Generate file with computers who have SPN records set who have recently authenticated to the domain (last 60 days)
# MATCH (c:Computer) MATCH WHERE c.lastlogon < (datetime().epochseconds - (60 * 86400)) return c.name, c.serviceprincipalnames
def get_compSPNs(driver):
    result = do_query(driver, "MATCH (c:Computer) WHERE c.lastlogon < (datetime().epochseconds - (60 * 86400)) return c.name, c.serviceprincipalnames")
    spn_file=open(config['bloodhound']['OUTPUT_DIR'] + "/computer_spns.txt", "w")
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

    print("[+] Generating Computer SPNs connected to AD last 60 days - useful for identifying servers + service offered: computer_spns.txt ("+str(len(result))+") lines")


# Generate a file with Groups + Descriptions where they have an 'admincount: true}: admin_groups.txt
# MATCH (u:Group {admincount: true}) return u.name
def get_adminGroups(driver):
    result = do_query(driver, "MATCH (u:Group {admincount: true}) return u.name, u.description")
    group_file=open(config['bloodhound']['OUTPUT_DIR'] + "/admin_groups.txt", "w+")
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

    print("[+] Generating Admin Groups (admincount: true): admin_groups.txt ("+str(len(result))+") lines")



# Generate a file with User + Descriptions where they have an 'admincount: true}: admin_users.txt
# MATCH (u:User {admincount: true}) return u.name
def get_adminUsers(driver):
    result = do_query(driver, "MATCH (u:User {admincount: true}) return u.name, u.description")
    userdesc_file=open(config['bloodhound']['OUTPUT_DIR'] + "/admin_users.txt", "w")
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

    print("[+] Generating Admin Users (admincount: true): admin_users.txt ("+str(len(result))+") lines")


# Generate a file with a list of users who have extensive rights (DCSync|AllExtendedRights|GenericAll) within the domain and are admincount=false: dcsync-notadmin_domain.txt
# Q1 - Get Domains: MATCH (n:Domain) RETURN n.name
# Q2 - Get all the said permissions for each domain: MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain {name: '"+domain+"'}) WHERE n.admincount=false RETURN n.name
def get_dcsync(driver):
    result = do_query(driver, "MATCH (n:Domain) RETURN n.name")
    domains = []
    for record in result:
        domains.append(record["n.name"])

    for domain in domains:
        result = do_query(driver, "MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain {name: '"+domain+"'}) WHERE n.admincount=false RETURN n.name")
        dcsync_file=open(config['bloodhound']['OUTPUT_DIR'] + "/dcsync-notadmin_"+domain+".txt", "w")
        for record in result:
            if record["n.name"]:
                dcsync_file.write(record["n.name"]+"\n")
            else:
                dcsync_file.write("None"+"\n")
        dcsync_file.close()

        print("[+] Generating Users with Admincount=false and DCSync|AllExtendedRights|GenericAll -> these are very likely problems: dcsync-notadmin_"+domain+".txt ("+str(len(result))+") lines")

# Generate a file with Enabled Users who have SPN records set: kerberoastable.txt
# MATCH (u:User {enabled: true}) WHERE u.hasspn=true RETURN u.name
def get_kerbUsers(driver):
    result = do_query(driver, "MATCH (u:User {enabled: true}) WHERE u.hasspn=true RETURN u.name")
    kerb_file=open(config['bloodhound']['OUTPUT_DIR'] + "/kerberoastable.txt", "w")
    for record in result:
        if record["u.name"]:
            user_name=record["u.name"]
        else:
            user_name=""
        kerb_file.write(user_name+"\n")
    kerb_file.close()

    print("[+] Generating Enabled Users with SPN Records (Kerberoastable): kerberoastable.txt ("+str(len(result))+") lines")


# Generate a file with Enabled Users who have {dontreqpreauth: true} : asprep_roast.txt
# MATCH (u:User {dontreqpreauth: true}) RETURN u.name
def get_asprepRoast(driver):
    result = do_query(driver, "MATCH (u:User {dontreqpreauth: true}) RETURN u.name")
    asp_file=open(config['bloodhound']['OUTPUT_DIR'] + "/asprep_roast.txt", "w")
    for record in result:
        if record["u.name"]:
            user_name=record["u.name"]
        else:
            user_name=""
        asp_file.write(user_name+"\n")
    asp_file.close()

    print("[+] Generating Users with DontReqPreAuth enabled (ASP-REP Roastable its not likely you'll see this): asprep_roast.txt ("+str(len(result))+") lines")



# Return objects with unconstrained delegration enabled which should really only be DCs
# MATCH (c {unconstraineddelegation:true}) return c.name
def get_unconstrainedDel(driver):
    result = do_query(driver, "MATCH (c {unconstraineddelegation:true}) return c.name")
    uncon_file=open(config['bloodhound']['OUTPUT_DIR'] + "/unconstrained_delegation.txt", "w")
    for record in result:
        if record["c.name"]:
            uncon_name=record["c.name"]
        else:
            uncon_name=""
        uncon_file.write(uncon_name+"\n")
    uncon_file.close()

    print("[+] Generating objects with unconstrained delegation (should really only be DCs): unconstrained_delegation.txt ("+str(len(result))+") lines")


# Generate a list of enabled users with passwordlastset value greater than 365 days: enabled_users_passwordlastset_1yr.txt
# Query is long so not commented but its the query that is set to the variable "query" below
def get_pwdYear(driver):
    query = '''MATCH (u:User {enabled: true}) WHERE u.pwdlastset > 0 
WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.pwdlastset) }) AS pwdlastset, duration.inDays(datetime({ epochSeconds:toInteger(u.pwdlastset) }), date()).days AS days_since_pwdlastset
WHERE days_since_pwdlastset > 365
RETURN name, days_since_pwdlastset, pwdlastset 
ORDER BY days_since_pwdlastset DESC'''
    pwd_file=open(config['bloodhound']['OUTPUT_DIR'] + "/enabled_users_passwordlastset_1yr.txt", "w")
    result = do_query(driver, query)
    for record in result:
        name = record["name"]
        pwdlastset=record["pwdlastset"]
        days_since_pwlastset=record["days_since_pwdlastset"]
        pwd_file.write(name+", "+str(days_since_pwlastset)+", "+str(pwdlastset)+"\n")
    pwd_file.close()

    print("[+] Generating enabled users with passwordlastset value greater than 365 days: enabled_users_passwordlastset_1yr.txt ("+str(len(result))+") lines")


# Generate a list of enabled Users who have never logged on: enabledacct_never_loggedon.txt"
# MATCH (n:User) WHERE n.lastlogontimestamp=-1.0 AND n.enabled=TRUE RETURN n.name
def get_userNoLogon(driver):
    result = do_query(driver, "MATCH (n:User) WHERE n.lastlogontimestamp=-1.0 AND n.enabled=TRUE RETURN n.name")
    user_file=open(config['bloodhound']['OUTPUT_DIR'] + "/enabledacct_never_loggedon.txt", "w")
    for record in result:
        if record["n.name"]:
            user_name=record["n.name"]
        else:
            user_name=""
        user_file.write(user_name+"\n")
    user_file.close()

    print("[+] Generating Enabled Users who have never logged on: enabledacct_never_loggedon.txt ("+str(len(result))+") lines")

# MATCH p = (d:Domain)-[r:Contains*1..]->(c:Computer) WHERE c.haslaps = false AND c.enabled = true AND c.operatingsystem CONTAINS "Win" RETURN c.name, c.description, c.operatingsystem
# Query to get computers with LAPS disabled: computers_laps_disabled.txt
# MATCH p = (d:Domain)-[r:Contains*1..]->(c:Computer) WHERE c.haslaps = false AND c.enabled = true RETURN c.name, c.description
def get_computersNoLAPS(driver):
    #result = do_query(driver, "MATCH p = (d:Domain)-[r:Contains*1..]->(u:Computer) WHERE u.haslaps = false AND u.enabled = true AND u.operatingsystem CONTAINS 'Win' RETURN u.name, u.operatingsystem, u.description")
    result = do_query(driver, "MATCH p = (d:Domain)-[r:Contains*1..]->(u:Computer) WHERE u.haslaps = false AND u.enabled = true RETURN u.name, u.description")
    comp_file=open(config['bloodhound']['OUTPUT_DIR'] + "/computers_laps_disabled.txt", "w")
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

    print("[+] Generating Computers with LAPS Disabled: computers_laps_disabled.txt ("+str(len(result))+") lines")


# Get 1st degree DCOM Privs
# MATCH p=(m:User {objectid: "OBJECT_ID"})-[r:ExecuteDCOM]->(n:Computer) RETURN p
def get_firstDegreeUserDCOM_old(driver):
    result = do_query(driver, "MATCH (m:User) where m.name is not null return m.name, m.objectid")
    dcom_file=open(config['bloodhound']['OUTPUT_DIR'] + "/firstdegree_user_dcom_rights.txt", "w")
    for record in result:
        if record["m.name"]:
            user_name = record["m.name"]
            objectid = record["m.objectid"]
            result1 = do_query(driver, "MATCH p=(m:User {objectid: '"+objectid+"'})-[r:ExecuteDCOM]->(n:Computer) RETURN count(p)")
            for record1 in result1:
                if record1["count(p)"]:
                    dcom_rights=str(record1["count(p)"])
                    dcom_file.write("[-] User: "+user_name+" DCOM rights: "+dcom_rights+"\n")
    dcom_file.close()
    print("[+] Generating Users first degree DCOM rights: firstdegree_user_dcom_rights.txt ("+str(len(result))+") lines")

def get_firstDegreeUserDCOM(driver):
    result = do_query(driver, "MATCH (m:User) where m.name is not null return m.name, m.objectid")
    dcom_file=open(config['bloodhound']['OUTPUT_DIR'] + "/firstdegree_user_dcom_rights.txt", "w")
    def query(tx):
        for record in result:
            if record["m.name"]:
                user_name = record["m.name"]
                objectid = record["m.objectid"]
                result1 = tx.run("MATCH p=(m:User {objectid: '"+objectid+"'})-[r:ExecuteDCOM]->(n:Computer) RETURN count(p)")
                for record1 in result1:
                    if record1["count(p)"]:
                        dcom_rights=str(record1["count(p)"])
                        dcom_file.write("[-] User: "+user_name+" DCOM rights: "+dcom_rights+"\n")
    with driver.session(database='neo4j') as session:
        result1 = session.execute_read(query)
    dcom_file.close()
    print("[+] Generating Users first degree DCOM rights: firstdegree_user_dcom_rights.txt ("+str(len(result))+") lines")

# Get group delegated DCOM Privs
# MATCH p=(m:User {objectid: "S-1-5-21-3031697400-3124200660-2978427-16364"})-[r1:MemberOf*1..]->(g:Group)-[r2:ExecuteDCOM]->(n:Computer) RETURN p
def get_groupDelUserDCOM(driver):
    result = do_query(driver, "MATCH (m:User) where m.name is not null return m.name, m.objectid")
    dcom_file=open(config['bloodhound']['OUTPUT_DIR'] + "/groupdel_user_dcom_rights.txt", "w")
    for record in result:
        if record["m.name"]:
            user_name = record["m.name"]
            objectid = record["m.objectid"]
            result1 = do_query(driver, "MATCH p=(m:User {objectid: '"+objectid+"'})-[r1:MemberOf*1..]->(g:Group)-[r2:ExecuteDCOM]->(n:Computer) RETURN count(p)")
            for record1 in result1:
                if record1["count(p)"]:
                    dcom_rights=str(record1["count(p)"])
                    dcom_file.write("[-] User: "+user_name+" group del DCOM rights: "+dcom_rights+"\n")
    dcom_file.close()

    print("[+] Generating Users group delegated DCOM rights: groupdel_user_dcom_rights.txt ("+str(len(result))+") lines")


# Get 1st degree Group DCOM Privs
# MATCH p=(m:Group {objectid: "OBJECT_ID"})-[r:ExecuteDCOM]->(n:Computer) RETURN p
def get_firstDegreeGroupDCOM(driver):
    result = do_query(driver, "MATCH (m:Group) where m.name is not null return m.name, m.objectid")
    dcom_file=open(config['bloodhound']['OUTPUT_DIR'] + "/firstdegree_group_dcom_rights.txt", "w")
    for record in result:
        if record["m.name"]:
            user_name = record["m.name"]
            objectid = record["m.objectid"]
            result1 = do_query(driver, "MATCH p=(m:Group {objectid: '"+objectid+"'})-[r:ExecuteDCOM]->(n:Computer) RETURN count(p)")
            for record1 in result1:
                if record1["count(p)"]:
                    dcom_rights=str(record1["count(p)"])
                    dcom_file.write("[-] Group: "+user_name+" DCOM rights: "+dcom_rights+"\n")
    dcom_file.close()

    print("[+] Generating Groups first degree DCOM rights: firstdegree_group_dcom_rights.txt ("+str(len(result))+") lines")


### This function is only invoked if `--pathing` is selected on the CLI due to the time it takes to run
# Build a list of High Value Targets (HVTs) in Q1, and then interate through their inbound rights in Q2 (this is the one that takes a bit)
# Q1 - MATCH (m) WHERE m.highvalue=TRUE RETURN m.name, m.objectid
# Q2 - MATCH (n) WHERE NOT (n.objectid='"+objectid+"') WITH n MATCH p = shortestPath((n)-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:Group {objectid: '"+objectid+"'})) RETURN count(n.name)
def get_hvtRights(driver):
    result = do_query(driver, "MATCH (m) WHERE m.highvalue=TRUE RETURN m.name, m.objectid")
    hvt_file=open(config['bloodhound']['OUTPUT_DIR'] + "/hvt_inbound_rights.txt", "w")
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

    print("[+] Generating High Value Targets (HVT) and inbound rights: hvt_inbound_rights.txt ("+str(len(result))+") lines")



### This function is only invoked if `--pathing` is selected on the CLI due to the time it takes to run
# Multiple query to build a list of GPOs then find inbound rights
# Q1 - MATCH (m:GPO) RETURN m.name, m.objectid
# Q2 - MATCH (n) WHERE NOT (n.objectid='"+objectid+"') WITH n MATCH p = shortestPath((n)-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:GPO {objectid: '"+objectid+"'})) RETURN count(n.name)
def get_gpoRights(driver):
    result = do_query(driver, "MATCH (m:GPO) RETURN count(m.name)")
    for record in result:
        if record["count(m.name)"]:
            count = str(record["count(m.name)"])
        else:
            count="0"

    result = do_query(driver, "MATCH (m:GPO) RETURN m.name, m.objectid")
    gpo_file=open(config['bloodhound']['OUTPUT_DIR'] + "/gpo_inbound_rights.txt", "w")

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

    print("[+] Generating GPOs and inbound rights (Total GPOs: "+count+" this will take a bit ~5-10secs per GPO): gpo_inbound_rights.txt ("+str(len(result))+") lines")


# Multiple query to get the transitive outbound rights for a set of groups defined as "starter_groups" list below
# Q1 - Get Domains: MATCH (n:Domain) RETURN n.name
# Q2 - Get Group Objectids: MATCH (n:Group {name:"+starter_group+"@"+domain+"}) RETURN n.objectid
# Q3 - Get Transitive Outbound rights: MATCH (n) WHERE NOT n.objectid="+objectid+" WITH n MATCH p = shortestPath((g:Group {objectid: "+objectid+"})-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n)) RETURN count(p)
def get_startingPoints(driver):
    # List of common starting points:
    starter_groups=['DOMAIN USERS', 'EVERYONE', 'DOMAIN COMPUTERS']
    starter_file=open(config['bloodhound']['OUTPUT_DIR'] + "/common_groups_outboundrights.txt", "w")
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

    print("[+] Generating common groups and their transitive outbound rights - investigate for anomalies: common_groups_outboundrights.txt ("+str(len(result))+") lines")



def get_serverRDP(driver):
    result = do_query(driver, "MATCH (m:Computer) WHERE m.operatingsystem CONTAINS 'Server' return m.name, m.objectid")
    server_rdp_file=open(config['bloodhound']['OUTPUT_DIR'] + "/server_RDP.txt", "w")
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

    print("[+] Generating Servers with First Degree RDP Rights: server_RDP.txt ("+str(len(result))+") lines")

def get_userOutboundRights_firstdegree(driver):
    result = do_query(driver, "MATCH (m:User) return m.name, m.objectid")
    user_outbound_file=open(config['bloodhound']['OUTPUT_DIR'] + "/users_outbound_1st_rights.txt", "w")
    def query(tx):
        for record in result:
            if record["m.name"]:
                username = record["m.name"]
                objectid = record["m.objectid"]
                result1 = tx.run("MATCH p=(u:User {objectid: '"+objectid+"'})-[r1]->(n) WHERE r1.isacl=true RETURN count(p)")
    #        result1 = do_query(driver, "MATCH p=(u:User {objectid: '"+objectid+"'})-[r1]->(n) WHERE r1.isacl=true RETURN count(p)")
                for record1 in result1:
                    if record1["count(p)"]:
                        firstdegree_rights=str(record1["count(p)"])
                        user_outbound_file.write("[-] User: "+username+" First Degree Outbound Rights: "+firstdegree_rights+"\n")
    with driver.session(database='neo4j') as session:
        result1 = session.execute_read(query)
    user_outbound_file.close()

    print("[+] Generating Users with First Degree Outbound Rights: users_outbound_1st_rights.txt ("+str(len(result))+") lines")


def get_userOutboundRights_firstdegree_old(driver):
    result = do_query(driver, "MATCH (m:User) return m.name, m.objectid")
    user_outbound_file=open(config['bloodhound']['OUTPUT_DIR'] + "/users_outbound_1st_rights.txt", "w")
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

    print("[+] Generating Users with First Degree Outbound Rights: users_outbound_1st_rights.txt ("+str(len(result))+") lines")


def get_serverAdminGroup(driver):
    result = do_query(driver, "MATCH (m:Group) return m.name, m.objectid")
    server_admin_file=open(config['bloodhound']['OUTPUT_DIR'] + "/server_admin_bygroup.txt", "w")
    def query(tx):
        for record in result:
            if record["m.name"]:
                group_name = record["m.name"]
                objectid = record["m.objectid"]
                result1 = tx.run("MATCH p = (g1:Group {objectid: '"+objectid+"'})-[r2:AdminTo]->(n:Computer) RETURN count(p)")
            #result1 = do_query(driver, "MATCH p = (g1:Group {objectid: '"+objectid+"'})-[r2:AdminTo]->(n:Computer) RETURN count(p)")
                for record1 in result1:
                    if record1["count(p)"]:
                        admin_rights=str(record1["count(p)"])
                        server_admin_file.write("[-] Group: "+group_name+" First Degree Admin Rights: "+admin_rights+"\n")
    
    with driver.session(database='neo4j') as session:
        result1 = session.execute_read(query)
    server_admin_file.close()
    print("[+] Generating Groups with First Degree Admin Rights: server_admin_bygroup.txt ("+str(len(result))+") lines")

def get_userOutboundRights_trans(driver):
    result = do_query(driver, "MATCH (m:User) return m.name, m.objectid")
    user_outbound_file=open(config['bloodhound']['OUTPUT_DIR'] + "/users_outbound_trans_rights.txt", "w")
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

    print("[+] Generating Users with Transitive Outbound Rights: users_outbound_trans_rights.txt ("+str(len(result))+") lines")



def get_userinboundRights_trans(driver):
    result = do_query(driver, "MATCH (m:User) return m.name, m.objectid")
    user_inbound_file=open(config['bloodhound']['OUTPUT_DIR'] + "/users_inbound_trans_rights.txt", "w")
    for record in result:
        if record["m.name"]:
            username = record["m.name"]
            objectid = record["m.objectid"]
            result1 = do_query(driver, "MATCH (n) WHERE NOT n.objectid='"+objectid+"' MATCH p = shortestPath((n)-[r1:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner*1..]->(u1:User {objectid: '"+objectid+"'})) RETURN count(p)")
            for record1 in result1:
                if record1["count(p)"]:
                    trans_rights=str(record1["count(p)"])
                    user_inbound_file.write("[-] User: "+username+" Transitive Inbound Rights: "+trans_rights+"\n")
    user_inbound_file.close()

    print("[+] Generating Users with Transitive Inbound Rights: users_inbound_trans_rights.txt ("+str(len(result))+") lines")



def get_computerOutboundRights_trans_old(driver):
    result = do_query(driver, "MATCH (m:Computer) return m.name, m.objectid")
    comp_outbound_file=open(config['bloodhound']['OUTPUT_DIR'] + "/comp_outbound_trans_rights.txt", "w")
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

    print("[+] Generating Computers with Transitive Outbound Rights: comp_outbound_trans_rights.txt ("+str(len(result))+") lines")


def get_computerOutboundRights_trans(driver):
    result = do_query(driver, "MATCH (m:Computer) return m.name, m.objectid")
    comp_outbound_file=open(config['bloodhound']['OUTPUT_DIR'] + "/comp_outbound_trans_rights.txt", "w")
    def query(tx):
        for record in result:
            if record["m.name"]:
                comp_name = record["m.name"]
                objectid = record["m.objectid"]
                result1 = tx.run("MATCH (n) WHERE NOT n.objectid='"+objectid+"' MATCH p=shortestPath((u:Computer {objectid: '"+objectid+"'})-[r1:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n)) RETURN count(p)")
                #result1 = do_query(driver, "MATCH (n) WHERE NOT n.objectid='"+objectid+"' MATCH p=shortestPath((u:Computer {objectid: '"+objectid+"'})-[r1:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n)) RETURN count(p)")
                for record1 in result1:
                    if record1["count(p)"]:
                        trans_rights=str(record1["count(p)"])
                        comp_outbound_file.write("[-] Computer: "+comp_name+" Transitive Outbound Rights: "+trans_rights+"\n")
    
    with driver.session(database='neo4j') as session:
        result1 = session.execute_read(query)
    comp_outbound_file.close()

    print("[+] Generating Computers with Transitive Outbound Rights: comp_outbound_trans_rights.txt ("+str(len(result))+") lines")

def get_passNeverExpire(driver):
    result = do_query(driver, "MATCH (u:User {enabled: true}) WHERE u.pwdneverexpires=True return u.name, u.pwdneverexpires, datetime({ epochSeconds:toInteger(u.pwdlastset)}) as pwdlast ORDER BY pwdlast")
    userdesc_file=open(config['bloodhound']['OUTPUT_DIR'] + "/user_enabled_passNeverExpires.txt", "w")
    for record in result:
        if record["u.name"]:
            user_name=record["u.name"]
        else:
            user_name=""
        if record["pwdlast"]:
            pwdlast=record["pwdlast"]
        else:
            pwdlast=""
        if record["u.pwdneverexpires"]:
            user_exp=record["u.pwdneverexpires"]
        else:
            user_exp=""
        if user_exp == True:
            userdesc_file.write(user_name+", "+str(user_exp)+","+str(pwdlast)+"\n")
        else:
            userdesc_file.write(user_name+"\n")
    userdesc_file.close()

    print("[+] Generating Enabled Users With Paswords That Never Expire: user_enabled_passNeverExpires.txt ("+str(len(result))+") lines")


def get_disabledOutboundRights_firstDegree_old(driver):
    result = do_query(driver, "MATCH (m:User {enabled: false}) return m.name, m.objectid, m.admincount")
    user_outbound_file=open(config['bloodhound']['OUTPUT_DIR'] + "/disabled_users_outbound_firstRights.txt", "w")
    for record in result:
        if record["m.name"]:
            username=record["m.name"]
            objectid=record["m.objectid"]
            admincount=record["m.admincount"]
            result_outbound = do_query(driver, "MATCH p=(u:User {objectid: '"+objectid+"'})-[r1]->(n) WHERE r1.isacl=true RETURN count(p)")
            for record_outbound in result_outbound:
                if record_outbound["count(p)"]:
                    firstdegree_rights=str(record_outbound["count(p)"])
                    user_outbound_file.write("[-] User: "+username+" First Degree Outbound Rights: "+firstdegree_rights+" Admincount: "+str(admincount)+"\n")
    user_outbound_file.close()

    print("[+] Generating Disabled Users with First Degree Outbound Rights: disabled_users_outbound_firstRights ("+str(len(result))+") lines")

def get_disabledOutboundRights_firstDegree(driver):
    result = do_query(driver, "MATCH (m:User {enabled: false}) return m.name, m.objectid, m.admincount")
    user_outbound_file=open(config['bloodhound']['OUTPUT_DIR'] + "/disabled_users_outbound_firstRights.txt", "w")
    def query(tx):
        for record in result:
            if record["m.name"]:
                username=record["m.name"]
                objectid=record["m.objectid"]
                admincount=record["m.admincount"]
                result_outbound = tx.run("MATCH p=(u:User {objectid: '"+objectid+"'})-[r1]->(n) WHERE r1.isacl=true RETURN count(p)")
                #result_outbound = do_query(driver, "MATCH p=(u:User {objectid: '"+objectid+"'})-[r1]->(n) WHERE r1.isacl=true RETURN count(p)")
                for record_outbound in result_outbound:
                    if record_outbound["count(p)"]:
                        firstdegree_rights = str(record_outbound["count(p)"])
                        user_outbound_file.write("[-] User: "+username+" First Degree Outbound Rights: "+firstdegree_rights+" Admincount: "+str(admincount)+"\n")
    with driver.session(database='neo4j') as session:
        result1 = session.execute_read(query)

    user_outbound_file.close()
    print("[+] Generating Disabled Users with First Degree Outbound Rights: disabled_users_outbound_firstRights ("+str(len(result))+") lines")

def get_passNotRequired(driver):
    result = do_query(driver, "MATCH (u:User {passwordnotreqd: true, enabled: true}) return u.name")
    pass_file=open(config['bloodhound']['OUTPUT_DIR'] + "/users-enabled-PassNotReqd.txt", "w")
    for record in result:
        if record["u.name"]:
            user_name=record["u.name"]
        else:
            user_name=""
        pass_file.write(user_name+"\n")
    pass_file.close()

    print("[+] Generating Enabled Users with PasswordNotReqd True: users-enabled-PassNotReqd.txt("+str(len(result))+") lines")


def get_allowedToAct(driver):
    result = do_query(driver, "MATCH p = (n)-[r:AllowedToAct]->(g:Computer) RETURN n.name, g.name")
    das_file=open(config['bloodhound']['OUTPUT_DIR'] + "/AllowedToAct.txt", "w")
    for record in result:
        if record["n.name"]:
            user_name=record["n.name"]
            computer_name=record["g.name"]
            das_file.write("[*] "+user_name+" has AllowedToAct over "+computer_name+"\n")
    das_file.close()

    print("[+] Generating AD Objects AllowedToAct on another AD object ("+str(len(result))+") lines")


def get_writeAccountRestrictions(driver):
    result = do_query(driver, "MATCH p = (n)-[r:WriteAccountRestrictions]->(g:Computer) RETURN n.name, g.name")
    das_file=open(config['bloodhound']['OUTPUT_DIR'] + "/WriteAccountRestrictions.txt", "w")
    for record in result:
        if record["n.name"]:
            user_name=record["n.name"]
            computer_name=record["g.name"]
            das_file.write("[*] "+user_name+" has WriteAccountRestirctions over "+computer_name+"\n")
    das_file.close()

    print("[+] Generating AD objects with WriteAccountRestrictions on another AD object ("+str(len(result))+") lines")


def get_userPathToDA(driver):
    da = do_query(driver, "MATCH (m:Group) where m.name contains 'DOMAIN ADMINS' return m.objectid")
    for record in da:
        if record["m.objectid"]:
            da_sid=record["m.objectid"]

    result = do_query(driver, "MATCH (m:User) return m.name, m.objectid, m.admincount")
    user_da_file=open(config['bloodhound']['OUTPUT_DIR'] + "/users_with_path_to_DA.txt", "w+")
    entries = 0
    for record in result:
        if record["m.name"]:
            username = record["m.name"]
            objectid = record["m.objectid"]
            admincount = record["m.admincount"]
            result1 = do_query(driver, "MATCH (n:User {objectid: '"+objectid+"'}) MATCH (m:Group {objectid: '"+da_sid+"'}) MATCH p=allShortestPaths((n)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GPLink|AddAllowedToAct|AllowedToAct|WriteAccountRestrictions|SQLAdmin|ReadGMSAPassword|HasSIDHistory|CanPSRemote|SyncLAPSPassword|DumpSMSAPassword|AZMGGrantRole|AZMGAddSecret|AZMGAddOwner|AZMGAddMember|AZMGGrantAppRoles|AZNodeResourceGroup|AZWebsiteContributor|AZLogicAppContributo|AZAutomationContributor|AZAKSContributor|AZAddMembers|AZAddOwner|AZAddSecret|AZAvereContributor|AZContains|AZContributor|AZExecuteCommand|AZGetCertificates|AZGetKeys|AZGetSecrets|AZGlobalAdmin|AZHasRole|AZManagedIdentity|AZMemberOf|AZOwns|AZPrivilegedAuthAdmin|AZPrivilegedRoleAdmin|AZResetPassword|AZUserAccessAdministrator|AZAppAdmin|AZCloudAppAdmin|AZRunsAs|AZKeyVaultContributor|AZVMAdminLogin|AZVMContributor|AZLogicAppContributor|AddSelf|WriteSPN|AddKeyCredentialLink|DCSync*1..]->(m)) RETURN count(p)")
            for record1 in result1:
                if record1["count(p)"]:
                    da_path=str(record1["count(p)"])
                    entries += 1
                    user_da_file.write("[-] User: "+username+" DA Hop Count: "+da_path+" Admincount: "+str(admincount)+"\n")
    
    print("[+] Generating Users with paths to DA: users_with_path_to_DA.txt ("+str(entries)+") lines")
    user_da_file.close()

def get_computerPathToDA(driver):
    da = do_query(driver, "MATCH (m:Group) where m.name contains 'DOMAIN ADMINS' return m.objectid")
    for record in da:
        if record["m.objectid"]:
            da_sid=record["m.objectid"]

    result = do_query(driver, "MATCH (m:Computer) return m.name, m.objectid")
    comp_da_file=open(config['bloodhound']['OUTPUT_DIR'] + "/computers_with_path_to_DA.txt", "w")
    entries = 0
    for record in result:
        if record["m.name"]:
            username = record["m.name"]
            objectid = record["m.objectid"]
            result1 = do_query(driver, "MATCH (n:Computer {objectid: '"+objectid+"'}) MATCH (m:Group {objectid: '"+da_sid+"'}) MATCH p=allShortestPaths((n)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GPLink|AddAllowedToAct|AllowedToAct|WriteAccountRestrictions|SQLAdmin|ReadGMSAPassword|HasSIDHistory|CanPSRemote|SyncLAPSPassword|DumpSMSAPassword|AZMGGrantRole|AZMGAddSecret|AZMGAddOwner|AZMGAddMember|AZMGGrantAppRoles|AZNodeResourceGroup|AZWebsiteContributor|AZLogicAppContributo|AZAutomationContributor|AZAKSContributor|AZAddMembers|AZAddOwner|AZAddSecret|AZAvereContributor|AZContains|AZContributor|AZExecuteCommand|AZGetCertificates|AZGetKeys|AZGetSecrets|AZGlobalAdmin|AZHasRole|AZManagedIdentity|AZMemberOf|AZOwns|AZPrivilegedAuthAdmin|AZPrivilegedRoleAdmin|AZResetPassword|AZUserAccessAdministrator|AZAppAdmin|AZCloudAppAdmin|AZRunsAs|AZKeyVaultContributor|AZVMAdminLogin|AZVMContributor|AZLogicAppContributor|AddSelf|WriteSPN|AddKeyCredentialLink|DCSync*1..]->(m)) RETURN count(p)")
            for record1 in result1:
                if record1["count(p)"]:
                    da_path = str(record1["count(p)"])
                    entries += 1
                    comp_da_file.write("[-] Computer: "+username+" DA Hop Count: "+da_path+"\n")
    comp_da_file.close()
    print("[Generating Computers with paths to DA: computers_with_path_to_DA.txt ("+str(entries)+") lines")

def get_groupPathToDA(driver):
    da = do_query(driver, "MATCH (m:Group) where m.name contains 'DOMAIN ADMINS' return m.objectid")
    for record in da:
        if record["m.objectid"]:
            da_sid=record["m.objectid"]

    result = do_query(driver, "MATCH (m:Group) return m.name, m.objectid, m.admincount")
    group_da_file=open(config['bloodhound']['OUTPUT_DIR'] + "/groups_with_path_to_DA.txt", "w")
    entries = 0
    for record in result:
        if record["m.name"]:
            username = record["m.name"]
            objectid = record["m.objectid"]
            admincount = record["m.admincount"]
            if objectid != da_sid:
                result1 = do_query(driver, "MATCH (n:Group {objectid: '"+objectid+"'}) MATCH (m:Group {objectid: '"+da_sid+"'}) MATCH p=allShortestPaths((n)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GPLink|AddAllowedToAct|AllowedToAct|WriteAccountRestrictions|SQLAdmin|ReadGMSAPassword|HasSIDHistory|CanPSRemote|SyncLAPSPassword|DumpSMSAPassword|AZMGGrantRole|AZMGAddSecret|AZMGAddOwner|AZMGAddMember|AZMGGrantAppRoles|AZNodeResourceGroup|AZWebsiteContributor|AZLogicAppContributo|AZAutomationContributor|AZAKSContributor|AZAddMembers|AZAddOwner|AZAddSecret|AZAvereContributor|AZContains|AZContributor|AZExecuteCommand|AZGetCertificates|AZGetKeys|AZGetSecrets|AZGlobalAdmin|AZHasRole|AZManagedIdentity|AZMemberOf|AZOwns|AZPrivilegedAuthAdmin|AZPrivilegedRoleAdmin|AZResetPassword|AZUserAccessAdministrator|AZAppAdmin|AZCloudAppAdmin|AZRunsAs|AZKeyVaultContributor|AZVMAdminLogin|AZVMContributor|AZLogicAppContributor|AddSelf|WriteSPN|AddKeyCredentialLink|DCSync*1..]->(m)) RETURN count(p)")
                for record1 in result1:
                    if record1["count(p)"]:
                        da_path=str(record1["count(p)"])
                        entries += 1
                        group_da_file.write("[-] Group: "+username+" DA Hop Count: "+da_path+" Admincount: "+str(admincount)+"\n")
    group_da_file.close()
    print("[+] Generating Groups with paths to DA: groups_with_path_to_DA.txt ("+str(entries)+") lines")


def get_hvtAdminFalse(driver):
    result = do_query(driver, "MATCH (m) WHERE m.highvalue=TRUE RETURN m.name, m.objectid")
    hvt_file = open(config['bloodhound']['OUTPUT_DIR'] + "/hvt_AdminFalse.txt", "w")
    entries = 0
    for record in result:
        if record["m.name"]:
            hvt_name = record["m.name"]
            objectid = record["m.objectid"]
            result1 = do_query(driver, "MATCH (n) WHERE NOT n.objectid='"+objectid+"' and n.admincount=false WITH n MATCH p = shortestPath((n)-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:Group {objectid: '"+objectid+"'})) RETURN n.samaccountname")
            for record1 in result1: 
                if record1["n.samaccountname"]:
                    name = record1["n.samaccountname"]
                    entries += 1
                    hvt_file.write("[-] "+name+" AdminCount False and can reach: "+hvt_name+"\n")
    hvt_file.close()
    print("[+] Generating High Value Targets (HVT) and objects that are AdminCount False that can reach them: hvt_AdminFalse.txt ("+str(entries)+") lines")
        
def get_ownedUserOutboundRights_firstDegree(driver):
    result = do_query(driver, "MATCH (m:User {owned: true, enabled: true}) return m.name, m.objectid")
    user_outbound_file=open(config['bloodhound']['OUTPUT_DIR'] + "/owned_users_outbound_1st_rights.txt", "w")
    entries = 0
    for record in result:
        if record["m.name"]:
            username = record["m.name"]
            objectid = record["m.objectid"]
            result1 = do_query(driver, "MATCH p=(u.User {objectid: '"+objectid+"'})-[r1]->(n) WHER r1.isacl=true RETURN count(p)")
            for record1 in result1:
                if record1["count(p)"]:
                    firstdegree_rights=str(record1["count(p)"])
                    entries += 1
                    user_outbound_file.write("[-] User: "+username+" First Degree Outbound Rights: "+firstdegree_rights+"\n")
    user_outbound_file.close()
    print("[*] Generating Owned Users with First Degree Outbound Rights: owned_users_outbound_1st_rights.txt ("+str(entries)+") lines")


def get_adminCountFalseUsers_trans(driver):
    result = do_query(driver, "MATCH (m:User {admincount: false}) return m.name, m.objectid, m.admincount")
    disabled_outbound_file=open(config['bloodhound']['OUTPUT_DIR'] + "/admincount_false_outbound_trans_rights.txt", "w")
    entries = 0
    for record in result:
        if record["m.name"]:
            username = record["m.name"]
            objectid = record["m.objectid"]
            admincount= record["m.admincount"]
            result1 = do_query(driver, "MATCH (n) WHERE NOT n.objectid='"+objectid+"' MATCH p=shortestPath((u:User {objectid: '"+objectid+"'})-[r1:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n)) RETURN count(p)")
            for record1 in result1:
                if record1["count(p)"]:
                    trans_rights=str(record1["count(p)"])
                    entries += 1
                    disabled_outbound_file.write("[-] User: "+username+" Transitive Outbound Rights: "+trans_rights+" Admincount: "+str(admincount)+"\n")
    disabled_outbound_file.close()

    print("[+] Generating a List of Users with AdminCount=False Transitive Outbound Rights: admincount_false_user_outbound_trans_rights.txt ("+str(entries)+") lines")
