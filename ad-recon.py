#!/usr/bin/env python
# External dependcies 
from neo4j import GraphDatabase
import time, sys, argparse, os

# Internal Modules
from modules import query, dump, help


################################
# Define for target environment#
################################
URI = "neo4j://localhost:7687"
USERNAME = "neo4j"
PASSWORD = "password"
#AUTH = (USERNAME, PASSWORD)
################################

def db_connect(URI, AUTH):
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        driver.verify_connectivity()
        return driver

def default_queries(driver):
    query.get_domains(driver)
    query.get_DCs(driver)
    query.get_computers(driver)
    query.get_sessionCount(driver)
    query.get_users(driver)
    query.get_Enabledusers(driver)
    query.get_ownedUsersCount(driver)
    query.get_ownedUsers(driver)
    query.get_daSessions(driver)
    query.get_sessions(driver)
    query.get_certTempNotAdmin(driver)
    query.get_certEnroll(driver)
    query.get_userDesc(driver)
    query.get_compDesc(driver)
    query.get_adminUsers(driver)
    query.get_adminGroups(driver)
    query.get_localAdmins(driver)
    query.get_groupDesc(driver)
    query.get_compSPNs(driver)
    query.get_dcsync(driver)
    query.get_kerbUsers(driver)
    query.get_asprepRoast(driver)
    query.get_unconstrainedDel(driver)
    query.get_compOwners(driver)
    query.get_serverRDP(driver)
    query.get_serverAdminGroup(driver)
    query.get_pwdYear(driver)
    query.get_userNoLogon(driver)
    query.get_computersNoLAPS(driver)
    query.get_oldComps(driver)


def pathing_queries(driver):
    print("----")
    print("Pathing Queries these will take longer")
    print("----")
    query.get_userOutboundRights_firstdegree(driver)
    query.get_hvtRights(driver)
    query.get_gpoRights(driver)

def transitive_queries(driver):
    print("----")
    print("Transitive Query will take a long time...probably like 5hrs")
    print("----")
    query.get_startingPoints(driver)
    query.get_computerOutboundRights_trans(driver)
    query.get_userOutboundRights_trans(driver)


if __name__ == "__main__":
    # Setup arguments
    parser = argparse.ArgumentParser(
                    prog='ad-recon',
                    description='Quickly triage BloodHound data via Neo4j queries',
                    epilog='ad-recon --pathing (optional) --dump (optional) --transitive (optional)')

    parser.add_argument('-P', '--pathing', help='Run pathing queries - takes longer', required=False, action='store_true')
    parser.add_argument('-T', '--transitive', help='Run transitive queries - takes even longer', required=False, action='store_true')  
    parser.add_argument('-D', '--dump', help='Dumps raw Cypher queries to more easily modify and use in BH/Neo4j. If selected no queries are performed', required=False, action='store_true')
    parser.add_argument('-H', '--moreHelp', help='Provides context into how to analyze the output files', required=False, action='store_true')
    parser.add_argument('-L', '--listQueries', help='List available queries', required=False, action='store_true')
    parser.add_argument('-Q', '--query', type=str, help="Executes an individual query as listed by -L (--listQueries)", required=False)
    parser.add_argument('-U', '--uri', type=str, help="Neo4j URI. Format neo4j://<ip>:<port>. Defaults to neo4j://localhost:7487", required=False)
    parser.add_argument('-u', '--username', type=str, help="Username for neo4j authentication", required=False)
    parser.add_argument('-p', '--password', type=str, help="Password for neo4j authentication", required=False)
    args = vars(parser.parse_args())

    # Track initial start time
    st = time.time()

    # Execute moreHelp query for verbose help info
    if args['moreHelp'] == True:
        help.moreHelp()
        sys.exit(0)
    # List available queries
    elif args['listQueries'] == True:
        help.listQueries()
        sys.exit(0)
    # Dumps list of queries
    elif args['dump'] == True:
        dump.dumpQuery()
        sys.exit(0)

    # Check if the output dir exists, and if not create it    
    if not os.path.exists("output"):
        os.mkdir("output")

    # Connect to the database prior to executing queries
    if args['uri']:
        URI = args['uri']
        print(f"Using {URI}")
    if args['username']:
        USERNAME = args['username']
    if args['password']:
        PASSWORD = args['password']

    # Setup driver connection
    AUTH = (USERNAME, PASSWORD)
    driver = db_connect(URI, AUTH)

    # If a single query is defined, execute, otherwise run the default queries
    if args['query']:
        queries = help.getQueries()
        singleQuery = args['query']
        
        if singleQuery in queries:
            q = getattr(query, singleQuery)
            q(driver)
        else:
            print("Invalid query!")
            help.listQueries()
        sys.exit(0)
    else:
        # Runs the default list of queries
        default_queries(driver)

    # Executes pathing queries if the arg is passed
    if args['pathing'] == True:
        pathing_queries(driver)

    # Executes transitive queries if the arg is passed
    if args['transitive'] == True:
        transitive_queries(driver)

    driver.close()

    # Tracks end time to display query duration
    et = time.time()
    elapsed = et-st
    print("")
    print(f"took {elapsed} seconds to complete")