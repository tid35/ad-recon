from modules import query

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
    query.get_firstDegreeUserDCOM(driver)
    query.get_groupDelUserDCOM(driver)
    query.get_firstDegreeGroupDCOM(driver)
