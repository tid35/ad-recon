from termcolor import colored

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
