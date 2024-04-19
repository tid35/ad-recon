from neo4j import GraphDatabase, RoutingControl
import multiprocessing
import time

URI = "neo4j://localhost:7687"
AUTH = ("neo4j", "password")

def do_query(driver, query):
    records, _, _ = driver.execute_query(
        query,
        database_="neo4j", 
        routing_=RoutingControl.READ,
    )
    return records

def get_DCs():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' return c1.name")
        print("[+] Parsing DCs: ")
        for record in result:
            print(record["c1.name"])
        print("-----")
        
# MATCH (n:Domain) RETURN n.name
def get_domains():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (n:Domain) RETURN n.name")
        print("[+] Parsing Domains: ")
        for record in result:
            print(record["n.name"])
        print("-----")



if __name__ == "__main__":
    st = time.time()
    get_domains() 
    get_DCs()
    et = time.time()
    elapsed = et-st
    print(f"took {elapsed} seconds to complete")
'''
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (n:User)WHERE n.hasspn=true RETURN n")
        for record in result:
            n = record['n']
            print(f"User: {n.get('samaccountname')}, adminCount: {n.get('admincount')}")
'''