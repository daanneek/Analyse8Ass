import sqlite3
from os import path
import os
import re
import pprint
import datetime
import time
import sys
from shutil import copyfile

def logOut():
    logAction("User logged out", Session["userName"], False)
    Session.update({"userName":None, "userRole":None, "loggedIn":False})

def encrypt(text):
    if isinstance(text, (str)):
        return viCipher(text, "Encrypt")
    return text

def decrypt(text):
    if isinstance(text, str):
        return viCipher(text)
    return text

# Change this so it will becomes a txt files
def logAction(description:str, info:str, suspicious:bool):
    '''Logs suspicious activity in the database. If the action is suspicious, the user is logged out. booleans are stored as one's and zero's'''
    logFile = open("logFile.txt", 'a')
    logFile.write(
        "username: " + Session["userName"] + " | date: " + getDateTime()["Date"] + " | time: " + getDateTime()["Time"] 
        + " | description: " + description + " | info: " + info + " | suspicious: " + suspicious + "\n"
    )
    if suspicious:
        logOut()
        countdown(10)

def viCipher(text="", typ="d"):
    key = "Tommy8==Daan"
    key_len = len(key)
    key_ints = [ord(i) for i in key]
    txt_ints = [ord(i) for i in text]
    message = ""
    for i in range(len(txt_ints)):
        adder = key_ints[i % key_len]
        if typ == "d":
            adder *= -1
        v = (txt_ints[i] - 32 + adder) % 95
        message += chr(v + 32)
    return message

def getDateTime():
    dt = datetime.datetime.today().now()
    return {"Time":dt.strftime("%H:%M:%S"),"Date": dt.strftime("%d-%m-%Y")}

Session = {
    "userName": None,
    "userRole": None,
    "loggedIn": False
}
# Session["userName"] = "daanneek"
# Session["loggedIn"] = not Session["loggedIn"]
#Encrypt all values

def queryDatabase(query:str, param:dict={}):
    '''Deletes and Updates return an empty list'''
    con = sqlite3.connect('database.db')
    cur = con.cursor().execute(query, encryptParams(param))
    con.commit()
    result = cur.fetchall()
    cur.close()
    return decryptQueryResult(result)  

def encryptParams(param:dict):
    for key in param:
        if not isinstance(param[key], int):
            param[key] = encrypt(param[key])
    return param

# check of database bestaat, if false maak nieuw, if true skip
if not (path.exists("database.db")):
    con = sqlite3.connect('database.db')
    cur = con.cursor()
    cur.execute('''CREATE TABLE clients (id INTEGER PRIMARY KEY, name, street ,houseNumber ,zipCode , city, emailAdress, mobilePhone)''')
    cur.execute('''CREATE TABLE logFile (id INTEGER PRIMARY KEY, username, date, time, description, info, suspicious )''')
    cur.execute('''CREATE TABLE accounts (id INTEGER PRIMARY KEY, username, password, type)''')
    cur.execute('''INSERT INTO accounts(username, password, type) VALUES ('h&~s-:BKNp','6t{w)Yop', 'h&~s-:BKNp')''')
    con.commit()
    if not (path.exists("./backups")):
        os.makedirs("./backups")
    

# inlog gegevens

def getUserLevel(userRole: str) -> int:
    cases = {
        "superadmin": 0,
        "admin": 1,
        "advisor":2
    }
    try:
        return cases[userRole]
    except:
        return -1

def retrieveAccount(userName:str, password: str):
    user = queryDatabase('''SELECT * FROM accounts WHERE username=:name AND password=:pass''' , {"name":userName, "pass":password})
    return None if user == [] else user
 
def returnAccountByUsername(username:str):
    return queryDatabase('''SELECT * FROM accounts WHERE username=:user''', {"user":username})

def countdown(t:int):
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1

def accountActionAttempt(attempt: int, action: str, onValidationFail, onSucces, lastAttempt:tuple=("","")):
    if attempt <= 0:
        print("Too many " + action + " attempts, timeout left:")
        logAction("Too many failed " + action + " attempt", "Username: " + lastAttempt[0] + " Password: " + lastAttempt[1], True)
    else:
        # validate inputs
        if action == "Login":
            userName = input("Enter " + ("" if action == "Login" else "old ") + "Username: ")
        else:
            userName = provideProperUsername("Enter " + ("" if action == "Login" else "old ") + "Username: ")
        if validateUserInput(userName):
            if action == "Login":
                password = input("Enter " + ("" if action == "Login" else "old ") + "Password: ")
            else:
                password = provideProperPassword("Enter " + ("" if action == "Login" else "old ") + "Password: ")
            if validatePassword(password):
                try:
                    logAction("User " + action , userName, False)
                    RetrievedAccount = retrieveAccount(userName, password)[0]
                    onSucces(RetrievedAccount)
                except:
                    print(action + " was unsuccesful")
                    logAction("Unsuccesful" + action + "attempt", "Username: " + userName + " Password: " + password, False)
                    print("Attempt #" + str(4 - attempt))
                    accountActionAttempt(attempt-1, action, onValidationFail, onSucces, (userName,password))
            else:
                logAction("Invalid password input", "Password: " + password, True)
                onValidationFail()
        else:
            logAction("Invalid username input", "Username: " + userName, True)
            onValidationFail()

def logIn():
    accountActionAttempt(3, "Login", logIn, lambda x : Session.update({"userName":x[1], "userRole":x[3], "loggedIn":True}), ("",""))

def changeOwnPassword():
    def refresh():
        logOut()
        logIn()

    def changePassword(userAcc):
        id, usrName, oldPsw, accType = userAcc
        updatePassword(id)

    if checkRole(3):
        if checkSession():
            accountActionAttempt(3, "Confirm old password", refresh, changePassword)

def otherAccountActionAttempt(action: str, onValidationFail, onSucces, role: str):
    # validate inputs
    userName = input("Enter a Username to be changed: ")
    if validateUserInput(userName):
        accounts = returnAccountByUsername(userName)
        if len(accounts):
            RetrievedAccount = accounts[0]
            if RetrievedAccount[3] == role:
                logAction(action + " " + role , userName, False)
                onSucces(RetrievedAccount[0])
            else: 
                logAction("Invalid search", action + " " + role, False)
                print("User is not a " + role)
                return
        else: 
            logAction("No result", action + " " + role, False)
            print("No accounts found")
            return
    else:
        logAction("Invalid input", "Username: " + userName, True)
        onValidationFail()

def changeAccount(permissionLevel, targetRole):
    
    def refresh():
        logOut()
        logIn()

    if checkRole(permissionLevel):
        if checkSession():
            options = {"1": updatePassword, "2": updateUsername, "3": updateRole}
            for o in options: print(o + ': ' + niceFunctionName(options[o].__name__))
            selection = input("Please select an option")
            if checkServerGeneratedInput(options, selection):
                otherAccountActionAttempt(niceFunctionName(options[selection].__name__), refresh, options[selection], targetRole)
            return

def changeAdvisor():
    changeAccount(1, "advisor")

def changeAdmin():
    changeAccount(0, "admin")

def updateRole(userId):
    # remove assignable roles based on user level
    options = ["superadmin","admin", "advisor"]
    for x in range(getUserLevel(Session["userRole"])): options.pop(0)

    # turn array to dictionary with numbers
    dictOptions = {}
    for i in range(len(options)): dictOptions[str(i)] = options[i]

    # print options
    for o in dictOptions: print(o + ": " + dictOptions[o])
    selection = input("Select a role number to assign: ")

    if checkServerGeneratedInput(dictOptions, selection):
        queryDatabase('''UPDATE accounts SET type=:newRole WHERE id=:id''' , {"id": userId, "newRole": dictOptions[selection]})
        logAction("User role changed",  "with userId: " + str(userId) + " by " + Session["userName"] , False)
        print("User role change succesful")
        return
    return

def updateUsername(userId):
    usrName = provideProperUsername("Please provide a new username: ")
    if validateUserInput(usrName):
        queryDatabase('''UPDATE accounts SET username=:newUsername WHERE id=:id''' , {"id": userId, "newUsername": usrName})
        logAction("Username changed", "with userId: " + str(userId) + " by " + Session["userName"], False)
        print("Username change succesful")
        return
    else:
        logAction("Attack on new username field", usrName, True)
        return

def updatePassword(userId):
    psw = provideProperPassword("Please provide a new password: ")
    if validatePassword(psw):
        repeatPsw = input("Please repeat the new password: ")
        if validatePassword(repeatPsw):
            if psw == repeatPsw:
                queryDatabase('''UPDATE accounts SET password=:newPassword WHERE id=:id''' , {"id": userId, "newPassword": psw})
                logAction("Password changed", "with userId: " + str(userId), False)
                print("Password change succesful")
                return
            else:
                print("Passwords do not match, please try again")
                updatePassword()
        else:
            logAction("Attack on new password field", psw, True)
            return
    else:
        logAction("Attack on new password field", psw, True)
        return

def createUser(role: str):
    userName = repeatUntilCorrect("Enter Username for the new " + role + ": ", "Inproper username", checkProperUserName)
    if usernameAvailable(userName):
        password= provideProperPassword("Enter Password for the new " + role + ": ")
        if validateUserInput(userName) and validatePassword(password):
            print("Adding " + role)
            queryDatabase('''INSERT INTO accounts(username, password, type) VALUES (:username, :password, :role)''', 
                {
                    "username":userName, 
                    "password":password, 
                    "role": role
                }
            )
            logAction("A new user was added", "Details: " + userName + ", " + role, False) 
    else:
        print("Username already exists!")

def provideProperPassword(msg: str) -> str:
    return repeatUntilCorrect(msg, "Inproper password", checkProperPassword)
    
def provideProperUsername(msg: str) -> str:
    return repeatUntilCorrect(msg, "Inproper username", checkProperUserName)

def repeatUntilCorrect(msg: str, errorMsg: str, rule) -> str:
    inp = input(msg)
    if rule(inp):
        return inp
    else:
        print(errorMsg)
        return repeatUntilCorrect(msg, errorMsg, rule)

def checkProperPassword(psw):
    return bool(re.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[~!@#$%^&*_\-+=`|\(){\}[\]:;'<>,.?\/\.])(?=.{8,30})").match(psw))

def checkProperUserName(usrName):
    return bool(re.match("^[a-z][\w'\.]{4,20}", usrName, re.IGNORECASE))

def getAvailableOptions(userRole: str) -> None:
    if Session["loggedIn"]:
        actions = [[deleteLogs, createAdmin, changeAdmin],[deleteAccount, readLogs, createAdvisor, checkAccountsInDatabase, changeAdvisor, deleteClient, backUpDatabase, backUpLogFile],[searchClientByProperty, changeOwnPassword, checkClientsInDatabase, createClient, updateClientInformation],[logOut, shutdown]]
        userLevel = getUserLevel(userRole)
        if userLevel < 0:
            print("User not found")
        for x in range(userLevel):
            actions.pop(0)
        options = [item for sublist in actions for item in sublist]
        return options
    return [logIn]

def niceFunctionName(fName: str) -> str:
    '''Changes name of function to a readable string'''
    return re.sub(r"(\w)([A-Z])", r"\1 \2", fName).lower()

def shutdown():
    sys.exit()

def printOptions():
    if Session["loggedIn"]:
        options = getAvailableOptions(Session["userRole"])
        print("\n##############################################################################\n")
        for o in options:
            print(str(options.index(o) + 1) + ". " + niceFunctionName(o.__name__))
        rawInput = input("Select an option by typing in the number: ")
        try:
            if int(rawInput) in range(1,len(options) + 1):
                selection = int(rawInput) - 1
                selectionFunction = options[selection]
                print("Selected option: " + niceFunctionName(selectionFunction.__name__))
                selectionFunction()
                printOptions()
            else:
                print("Pick a valid option.")
                printOptions()
        except SystemExit: 
            sys.exit()
        except:
            print("Invalid option")
            printOptions()
    else:
        input("Press anything to logIn: ")
        logIn()
        printOptions()

# Change this so it deleted the txt file
def deleteLogs():
    '''Delete everything from the logfile'''
    if checkRole(0):
        if checkSession():
            logFile = open("logFile.txt", "w")
            print("Deleted all the logs")
            logAction("Deleted all the logs", "user " + Session["userName"] + " deleted all logs with permission level " + Session["userRole"], False)

def deleteAccount():
    if checkRole(1):
        if checkSession():
            username = input("Enter the username of the user you want to delete: ")
            result = queryDatabase('''SELECT * from accounts where username=:user''', {"user":username})
            if getUserLevel(Session["userRole"]) < getUserLevel(result[0][3]):
                if not (usernameAvailable(username)):
                    queryDatabase('''DELETE FROM accounts WHERE username=:user''', {"user":username})
                    print("User " + username + " has been deleted.")
                else:
                    print("That username does not exist.")
                    return
            else:
                print("You don't have permission to delete this account.")
                
def checkSession() -> bool:
    if not Session["loggedIn"]:
        logAction("Suspicious session", Session["userName"], True)
        print("HEY GA WEG JIJ")
        return False
    return True

def checkRole(requiredLevel: int) -> bool:
    userlevel = getUserLevel(Session["userRole"])
    if userlevel > requiredLevel: 
        logAction("Authentication level too low", str(userlevel) + " is lower then " + str(requiredLevel) , True)
        print("How did you get here?")
        return False
    return True

def decryptQueryResult(queryResult):
    return list(map(lambda x : tuple(map(lambda y : decrypt(y), x)), queryResult))

# Change this so it reads from a txt file
def readLogs():
    if(checkRole(1) and checkSession()):
        result = open("logFile.txt", 'r')
        for l in result:
            print(l)

def validatePassword(input):
    '''returns True if input is valid '''
    return validateBlacklist(input) and bool(re.match("^[a-zA-Z\d~!@#$%^&*_\-+=|\():,.?/]+$", input))

def validateUserInput(input):
    '''returns True when the input is valid, returns False if the input is invalid, logs invalid activity, user is logged out.'''
    if not (validateBlacklist(input) and validateWhiteList(input)):
        logAction("Invalid input", input, True)
        return False
    return True
    
def validateBlacklist(input):
    '''returns True if input is valid '''
    return not bool(re.search("(\$|\^|rm|\\\.\.|\.\.\/|\.\.\\|\\\\|\\|\`|\\\"|-rf|\||\/\/|\/|--|\\x00]|<script>|<\/script>)", input, re.IGNORECASE))

def validateWhiteList(input):
    '''returns True if input is valid '''
    return bool(re.match("^$|^[a-zA-Z0-9@.' ]+$", input))

def checkServerGeneratedInput(options: dict, input):
    '''Check if the input is in the given dictionary'''
    if input not in list(options.keys()):
        logAction("Tampering of server generated input", input, True)
        print("Invalid server generated input.")
        return False
    else:
        return True

def getCity():
    #ASK TEACHER ABOUT SERVER GENERATED INPUT (tommy : DROPDOWN)
    cities = {"1": "Rotterdam", "2": "Amsterdam", "3":"Bahrein", "4":"Barendrecht","5": "New York", "6": "Tarkov", "7":"Vancouver", "8": "London", "9":"Saigon", "10":"Aleppo"}
    for x in cities: print(str(x) + ": " + cities[x])
    choice = input("Enter the number of the city you would like to pick: ")
    if checkServerGeneratedInput(cities, choice):
        return cities[choice]

def getUserInput(regex: str, inputType: str, rule:str = "", pattern:str = ""):
    '''Takes a regular expression, a type of input, and an optional rule. Asks the user for input, validates it for irregularities, and returns '''
    def userInputClosure():
        inp = input("Enter " + inputType + " for the new client " + pattern + ": ")
        if validateUserInput(inp):
            if bool(re.match(regex, inp)):
                return inp
            else:
                print(rule)
                return getUserInput(regex, inputType, rule, pattern)()
        else:
            return None
    return userInputClosure

def createClient():
    '''Function to create a new user. takes input from getuserinput, and checks if values where returned. If so, a new client is added to the database'''
    if checkSession() and checkRole(2):
        clientInfo = {
                    "name":getUserInput("^([a-zA-Z ]+)$", "name", "A name consists only of letters.", "[Only letters]"), 
                    "street":getUserInput("^[a-zA-Z ]+$", "street", "A street name consists only of letters."), 
                    "houseNumber": getUserInput("^\d+[a-zA-Z]*$", "house number", "A house number can only be a number."),
                    "zipCode": getUserInput("(?i)^[1-9][0-9]{3}?(?!sa|sd|ss)[a-z]{2}$", "zipCode", "Follow this pattern: 1234AB"), 
                    "city": getCity,
                    "emailAdress": getUserInput("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$", "emailAdress", "Follow this pattern: word@word.word"),
                    "mobilePhone": getUserInput("^\d{8}$", "phone", "A phone number consists only of 8 digits." )
                }
        for key in clientInfo:
            clientInfo[key] = clientInfo[key]()
            if clientInfo[key] != None:
                continue
            else:
                return
        clientInfo["mobilePhone"] = "31-6-" + clientInfo["mobilePhone"]
        queryDatabase('''INSERT INTO clients(name, street ,houseNumber ,zipCode , city, emailAdress, mobilePhone) VALUES (:name, :street ,:houseNumber ,:zipCode , :city, :emailAdress, :mobilePhone)''', 
            clientInfo
        )
        return
    return

def getColumn(listOfOptions) -> str:
    for x in listOfOptions: print(str(x) + ": " + listOfOptions[x])
    selection = int(input("Enter the number of the column: "))
    if checkServerGeneratedInput(listOfOptions, selection):
        return listOfOptions[selection]
    return None  
  
def searchClientByProperty():
    if checkSession() and checkRole(2):
        column = getColumn({1: "id", 2:"name", 3:"street" ,4:"houseNumber" ,5:"zipCode" ,6:"city", 7:"emailAdress",8:"mobilePhone"})
        if column == None: return
        if column == "city":
            keyword = getCity()
        else:
            keyword = input("Enter the keyword you would like to search with: ")   
        if validateUserInput(keyword):
            if(column == "id"): keyword = int(keyword) 
            result: list = queryDatabase(bindColumns('''SELECT * FROM clients WHERE col=:keyword''', column), {"keyword":keyword})
            if result != []:
                print(result)
                return result
            else:
                print("Client with this property was not found.")
        return

def getClientPropertyChangeFunction(property):
    return {  
        "name":getUserInput("^([a-zA-Z ]+)$", "name", "A name consists only of letters.", "[Only letters]"), 
        "street":getUserInput("^[a-zA-Z ]+$", "street", "A street name consists only of letters."), 
        "houseNumber": getUserInput("^\d+[a-zA-Z]*$", "house number", "A house number can only be a number."),
        "zipCode": getUserInput("(?i)^[1-9][0-9]{3}?(?!sa|sd|ss)[a-z]{2}$", "zipCode", "Follow this pattern: 1234AB"), 
        "city": getCity,
        "emailAdress": getUserInput("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$", "emailAdress", "Follow this pattern: word@word.word"),
        "mobilePhone": getUserInput("^\d{8}$", "phone", "A phone number consists only of 8 digits." )
    }[property]

def updateClientInformation():
    if checkSession() and checkRole(2):
        clientInfo = {}
        clientInfo["userId"] = int(input("Enter the ID of the client you would like to edit: "))
        column = getColumn({1:"name", 2:"street", 3:"houseNumber", 4:"zipCode", 5:"city", 6:"emailAdress", 7:"mobilePhone"})
        if column == None : return
        if column == "mobilePhone":
            clientInfo["newValue"] = "31-6-" + getClientPropertyChangeFunction(column)()
        else:
            clientInfo["newValue"] = getClientPropertyChangeFunction(column)()
        logAction("Client data was changed", "ID: "+ str(clientInfo["userId"]), False)
        print("Client data has been updated!")
        queryDatabase(bindColumns('''UPDATE clients SET col=:newValue WHERE id=:userId''', column), clientInfo)
    return

def bindColumns(sql:str, item):
    sql = sql.replace("col", item, 1)
    return sql

def createAdvisor():
    if checkRole(1) and checkSession():
        createUser("advisor")

def createAdmin():
    if checkSession() and checkRole(0):
        createUser("admin")

def checkAccountsInDatabase():
    if checkSession() and checkRole(1):
        result: list = queryDatabase('''SELECT username, type FROM accounts''')
        pprint.pprint(result)

def checkClientsInDatabase():
    if checkSession() and checkRole(2):
        result: list = queryDatabase('''SELECT id, name, street, houseNumber, zipCode, city, emailAdress, mobilePhone FROM clients''')
        for x in result:
                print(x)

def deleteClient():
    if checkSession() and checkRole(1):
        clientId = input("Please provide a client ID to delete")
        if validateUserInput(clientId):
            queryDatabase('''DELETE FROM clients WHERE id=:id''', {"id":int(clientId)})
            print("Client succesfully deleted")
            logAction("Deleted client", "clientId: " + clientId, False)

def backUpDatabase():
    if checkSession() and checkRole(1):
        datetime = getDateTime()
        append =  "[" + datetime["Date"]+"][" + datetime["Time"].replace(":", "")+ "]"
        copyfile(r"./database.db", "./backups/database"+ append +".db")

def backUpLogFile():
    if checkSession() and checkRole(1):
        datetime = getDateTime()
        append =  "[" + datetime["Date"]+"][" + datetime["Time"].replace(":", "")+ "]"
        copyfile(r"./logFile.txt", "./backups/logFile"+ append +".txt")

def usernameAvailable(username:str):
    '''Returns True if a username is not taken, returns false if a username already exists'''
    if len(returnAccountByUsername(username)):
        logAction("Username" + username + " already exists", "no extra information", False)   
        return False
    
    logAction("Username" + username + " does not exist", "no extra information", False)   
    return True


    

    
#"UPDATE account SET password=:newPassword WHERE id=:id" , {"id": id, "newPassword": newPsw})
#('''SELECT * FROM accounts WHERE username=:name AND password=:pass''' , {"name":userName, "pass":password})

# must have a length of at least 5 characters
# must be no longer than 20 characters
# must be started with a letter
# can contain letters (a-z), numbers (0-9), dashes (-), underscores (_), apostrophes ('), and periods (.)
# no distinguish between lowercase or uppercase letters

# must have a length of at least 8 characters
# must be no longer than 30 characters
# can contain letters (a-z), (A-Z), numbers (0-9), Special characters such as ~!@#$%^&*_-+=`|\(){}[]:;'<>,.?/
# must have a combination of at least one lowercase letter, one uppercase letter, one digit, and one special character

if __name__ == "__main__":
    #createClient()
    # queryDatabase('''UPDATE accounts SET password=:newPassword WHERE id=:id''' , {"id": 5, "newPassword": "Daanneek!3"})
    printOptions()

    #readLogs()
    #backUpDatabase()
