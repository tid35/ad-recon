#!/usr/bin/env python
# External dependcies 
from neo4j import GraphDatabase
import time, sys, argparse

# Internal Modules
from modules import query, dump, help


################################
# Define for target environment#
################################
URI = "neo4j://localhost:7687"
AUTH = ("neo4j", "password")
################################

def db_connect():
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

    parser.add_argument('--pathing', help='Run pathing queries - takes longer', required=False, action='store_true')
    parser.add_argument('--transitive', help='Run transitive queries - takes even longer', required=False, action='store_true')  
    parser.add_argument('--dump', help='Dumps raw Cypher queries to more easily modify and use in BH/Neo4j. If selected no queries are performed', required=False, action='store_true')
    parser.add_argument('--morehelp', help='Provides context into how to analyze the output files', required=False, action='store_true')
    args = vars(parser.parse_args())

    # Track initial start time
    st = time.time()

    # Execute moreHelp query for verbose help info
    if args['morehelp'] == True:
        help.moreHelp()
        sys.exit(0)

    # Dumps list of queries
    if args['dump'] == True:
        dump.dumpQuery()
        sys.exit(0)

    # Connect to the database prior to executing queries
    driver = db_connect()

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