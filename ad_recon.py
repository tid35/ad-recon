#!/usr/bin/env python
# External dependcies 
import time, sys, argparse, os
from neo4j import GraphDatabase

# Internal Modules
from modules import settings, db, default, dump, help, pathing, query, transitive, hvt, owned, adminCount, report

if __name__ == "__main__":
    # Setup arguments
    parser = argparse.ArgumentParser(
                    prog='ad_recon',
                    description='Quickly triage BloodHound data via Neo4j queries',
                    epilog='ad_recon --pathing (optional) --dump (optional) --transitive (optional)')

    parser.add_argument('-P', '--pathing', help='Run pathing queries - takes longer', required=False, action='store_true')
    parser.add_argument('-T', '--transitive', help='Run transitive queries - takes even longer', required=False, action='store_true')  
    parser.add_argument("--hvt", help="Run High Value Target (HVT) Queries", required=False, action='store_true')
    parser.add_argument("--owned", help="Get owned users outbound transitive rights", required=False, action='store_true')
    parser.add_argument("--adminCount", help="Get AdminCount False Users Outbound Transitive Rights", required=False, action='store_true')
    parser.add_argument('-D', '--dump', help='Dumps raw Cypher queries to more easily modify and use in BH/Neo4j. If selected no queries are performed', required=False, action='store_true')
    parser.add_argument('-H', '--moreHelp', help='Provides context into how to analyze the output files', required=False, action='store_true')
    parser.add_argument('-L', '--listQueries', help='List available queries', required=False, action='store_true')
    parser.add_argument('-Q', '--query', type=str, help="Executes an individual query as listed by -L (--listQueries)", required=False)
    parser.add_argument('-U', '--uri', type=str, help="Neo4j URI. Format neo4j://<ip>:<port>. Defaults to neo4j://localhost:7487", required=False)
    parser.add_argument('-u', '--username', type=str, help="Username for neo4j authentication", required=False)
    parser.add_argument('-p', '--password', type=str, help="Password for neo4j authentication", required=False)
    parser.add_argument('-d', "--database", type=str, help="Neo4j database name for queries", required=False)
    parser.add_argument('-R', '--report', help='Generate an HTML report after queries complete', required=False, action='store_true')
    parser.add_argument('-O', "--output", type=str, help="Specify an output directory for generated files", required=False)
    args = vars(parser.parse_args())

    # Track initial start time
    startTime = time.time()
    
    config = settings.get_config()

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
    if args['output']:
        config['bloodhound']['OUTPUT_DIR'] = args['output']
    
    # Connect to the database prior to executing queries
    # Defines target environment variables
    if args['uri']:
        config['bloodhound']['URI'] = args['uri']
    if args['username']:
        config['bloodhound']['USERNAME'] = args['username']
    if args['password']:
        config['bloodhound']['PASSWORD'] = args['password']
    if args['database']:
        config['bloodhound']['DATABASE'] = args['database']

    settings.update_config(config)

    if not os.path.exists(config['bloodhound']['OUTPUT_DIR']):
        os.mkdir(config['bloodhound']['OUTPUT_DIR'])

    # Setup driver connection
    AUTH = (config['bloodhound']['USERNAME'], config['bloodhound']['PASSWORD'])
    URI = (config['bloodhound']['URI'])
    #driver = db.db_connect(config['bloodhound']['URI'], AUTH) 
    driver = GraphDatabase.driver(URI, auth=AUTH)
    try:
        driver.verify_connectivity()
        print(f"Connected to {URI} successfully!")
    except Exception as e:
        #print(f"error: {e}")
        print(f"Connection to {URI} failed...")
        sys.exit(1)

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
        report_data = default.default_queries(driver)

    # Executes pathing queries if the arg is passed
    if args['pathing'] == True:
        pathing.pathing_queries(driver)

    # Executes transitive queries if the arg is passed
    if args['transitive'] == True:
        transitive.transitive_queries(driver)

    # Executes HVT queries if arg is passed
    if args['hvt'] == True:
        hvt.hvt_queries(driver)
    
    # Executes HVT queries if arg is passed
    if args['owned'] == True:
        owned.owned_queries(driver)
    
    # Executes AdminCountnt queries if arg is passed
    if args['adminCount'] == True:
        adminCount.adminCount_queries(driver)
    
    # Generate HTML report if --report flag is set
    if args['report'] == True:
        report.generate_report(config['bloodhound']['OUTPUT_DIR'], report_data)

    # Close driver connection
    driver.close()

    # Tracks end time to display query duration
    print(f"\ntook {time.time()-startTime} seconds to complete")
