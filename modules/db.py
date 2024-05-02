from neo4j import GraphDatabase

def db_connect(URI, AUTH):
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        driver.verify_connectivity()
        return driver