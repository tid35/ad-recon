from modules import query

def azure_queries(driver):
    print("----")
    print("Running Azure Queries")
    print("----")
    query.get_azureUsers(driver)
    query.get_azureDevices(driver)
    query.get_azureUsersGlobalAdmin(driver)
