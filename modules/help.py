from termcolor import colored

def getQueries():
    from modules import query
    import inspect
    
    queries = []

    for f in inspect.getmembers(query, inspect.isfunction):
        if f[0].startswith('get_'):
            #print(f[0])
            queries.append(f[0])
    return queries

def listQueries():
    queries = getQueries()
    for i in queries:
        print(i)

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
