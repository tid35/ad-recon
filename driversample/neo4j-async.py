from neo4j import AsyncGraphDatabase, RoutingControl
import asyncio
import time

URI = "neo4j://localhost:7687"
AUTH = ("neo4j", "password")

async def do_query(driver, query):
    records, _, _ = await driver.execute_query(
        query,
        database_="neo4j", 
        routing_=RoutingControl.READ,
    )
    return records

async def get_DCs():
    async with AsyncGraphDatabase.driver(URI, auth=AUTH) as driver:
        result = await do_query(driver, "MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' return c1.name")
        print("[+] Parsing DCs: ")
        for record in result:
            print(record["c1.name"])
        print("-----")
        await asyncio.sleep(0)
        
# MATCH (n:Domain) RETURN n.name
async def get_domains():
    async with AsyncGraphDatabase.driver(URI, auth=AUTH) as driver:
        result = await do_query(driver, "MATCH (n:Domain) RETURN n.name")
        print("[+] Parsing Domains: ")
        for record in result:
            print(record["n.name"])
        print("-----")


if __name__ == "__main__":
    st = time.time()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(
        get_DCs(),
        get_domains()
    ))
    loop.close()
    et = time.time()
    elapsed = et-st
    print(f"took {elapsed} seconds to complete")

'''
if __name__ == "__main__":
    st = time.time()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(
        get_DCs(),
        get_domains()
    ))
    loop.close()
    et = time.time()
    elapsed = et-st
    print(f"took {elapsed} seconds to complete")
'''