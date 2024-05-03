from modules import query

def transitive_queries(driver):
    print("----")
    print("Transitive Query will take a long time...probably like 5hrs")
    print("----")
    query.get_startingPoints(driver)
    query.get_computerOutboundRights_trans(driver)
    query.get_userOutboundRights_trans(driver)
    query.get_userinboundRights_trans(driver)
