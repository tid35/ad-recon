# Neo4j Driver

Install the appropriate required version
```
pip3 install -r requirements.txt
```

NOTE: If you have neo4j 5.2.0dev from crackmapexec, just run
```
pip3 install --ignore-installed neo4j
```

## performing queries

Create a function to handle your query
```
def get_domains():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        result = do_query(driver, "MATCH (n:Domain) RETURN n.name")
        print("Domains Found: ")
        for record in result:
            print(record["n.name"])
        print("-----")

```
Your query will go in the `do_query` section and the `RETURN` result will be the appropriate dict key to parse.
You can alternatively return the value rather than printing. 
```
return result
```

NOTE: This sample is single threaded and will not perform async queries

