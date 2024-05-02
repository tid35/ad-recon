from modules import query

def pathing_queries(driver):
    print("----")
    print("Pathing Queries these will take longer")
    print("----")
    query.get_userOutboundRights_firstdegree(driver)
    query.get_hvtRights(driver)
    query.get_gpoRights(driver)