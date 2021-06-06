import sqlite3
from os import path
import re
import pprint
import datetime
import time
#print(sqlite3.connect('database.db').cursor().execute('''SELECT * FROM accounts''', {}).fetchall())

def logOut():
    Session.update({"userName":None, "userRole":None, "loggedIn":False})


def logAction(description:str, info:str, suspicious:bool):
    '''Logs suspicious activity in the database. If the action is suspicious, the user is logged out. booleans are stored as one's and zero's'''
    queryDatabase('''INSERT INTO logFile(username, date, time, description, info, suspicious) VALUES (:username, :date, :time, :description, :info, :suspicious)''',
         {
            "username": encrypt(Session["userName"]), 
            "date": encrypt(getDateTime()["Date"]), 
            "time": encrypt(getDateTime()["Time"]), 
            "description": encrypt(description), 
            "info": encrypt(info), 
            "suspicious": suspicious
        }
    )
    if suspicious:
        logOut()

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

def encrypt(text):
    if isinstance(text, (str)):
        return viCipher(text, "Encrypt")
    return text

def decrypt(text):
    if isinstance(text, str):
        return viCipher(text)
    return text

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

def queryDatabase(query:str, param:dict={}):
    '''Deletes and Updates return an empty list'''
    con = sqlite3.connect('database.db')
    cur = con.cursor().execute(query, param)
    con.commit()
    result = cur.fetchall()
    #print(result)
    cur.close()
    return result  

# check of database bestaat, if false maak nieuw, if true skip
if not (path.exists("database.db")):
    con = sqlite3.connect('database.db')
    cur = con.cursor()
    cur.execute('''CREATE TABLE clients (id INTEGER PRIMARY KEY, name, street ,houseNumber ,zipCode , city, emailAdress, mobilePhone)''')
    cur.execute('''CREATE TABLE logFile (id INTEGER PRIMARY KEY, username, date, time, description, info, suspicious )''')
    cur.execute('''CREATE TABLE accounts (id INTEGER PRIMARY KEY, username, password, type)''')
    cur.execute('''INSERT INTO accounts(username, password, type) VALUES ('superadmin','6t{w)Yop', 'superadmin')''')
    con.commit()
# client
# Full name
# Street name (only numbers)
# house number(X tot XXXXX)
# zip code (1234AB)
# City (List of 10) (if not in list then stop, log incident, give warning and logout)
# email adress (anyname@anydomain.any)
# mobile phone (31-6-XXXXXXXX)

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
    if user == []:
        return None
    else:
        return user    
# print(retrieveAccount("superadmin", "XD").fetchall())
# print(current.execute('''SELECT * FROM accounts''').fetchall())

def checkSession():
    print(Session)

def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1
    

def logIn():

    def logInAttempt(attempt: int, lastAttempt: tuple):
        # add input helper

        if attempt <= 0:
            logAction("Too many failed login attempt", "Username: " + lastAttempt[0] + " Password: " + lastAttempt[1], True)
            print("🖕😂🖕 too many login attempts, timeout left:")
            countdown(10)
        else:
            # validate inputs
            userName = input("Enter Username: ")
            password = input("Enter Password: ")

            if validateUserInput(userName) and validatePassword(password):
                try:
                    RetrievedAccount = retrieveAccount(userName, encrypt(password))[0]
                    print("Login was succesful")
                    Session.update({"userName":RetrievedAccount[1], "userRole":RetrievedAccount[3], "loggedIn":True})
                    logAction("User logged in",userName , False)
                except:
                    print("Login was unsuccesful")
                    logAction("Unsuccesful login attempt", "Username: " + userName + " Password: " + password, False)
                    print("Attempt #" + str(4 - attempt))
                    logInAttempt(attempt-1, (userName,password))
            else:
                logAction("Invalid input", "Username: " + userName + " Password: " + password, True)
                print("🖕😂🖕 timeout left:")
                countdown(30)
                logIn()

    logInAttempt(3, ("",""))


def createAdmin():
    #todo
    pass

def createAdvisor():
    #todo
    pass

def updatePassword():
    #todo
    pass

def addClient():
    #todo
    pass

def updateClient():
    #todo
    pass

def getClient():
    #todo
    pass


#["Assign administrator"],["Backup","Assign advisor"],["Delete Client","Add Client"],["LogOut", "Update password"]
def getAvailableOptions(userRole: str) -> None:
    if Session["loggedIn"]:
        actions = [[createAdmin, deleteLogs],[createAdvisor, readLogs ],[],[logOut]]
        userLevel = getUserLevel(userRole)
        if userLevel < 0:
            # log him out
            print("User not found")
            # PLACEHOLDER
        for x in range(userLevel):
            actions.pop(0)
        options = [item for sublist in actions for item in sublist]
        return options
    return [logIn]

def niceFunctionName(fName: str) -> str:
    return re.sub(r"(\w)([A-Z])", r"\1 \2", fName).lower()

def printOptions():
    if Session["loggedIn"]:
        options = getAvailableOptions(Session["userRole"])
        for o in options:
            print(str(options.index(o) + 1) + ". " + niceFunctionName(o.__name__))
        rawInput = input("Select an option by typing in the number: ")
        try:
            if int(rawInput) in range(1,len(options) + 1):
                selection = int(rawInput) - 1
                selectionFunction = options[selection]
                print("SeLeCtEd: " + niceFunctionName(selectionFunction.__name__))
                selectionFunction()
                printOptions()
        except:
            print("Invalid option")
            printOptions()
    else:
        input("Press anything to logIn: ")
        logIn()
        printOptions()

def deleteLogs():
    '''Delete everything from the logfile'''
    queryDatabase('''DELETE FROM logFile''')
    print("Deleted all the logs")
    # cur.execute("DELETE FROM human WHERE sex = 'Male'")

#('''SELECT * FROM accounts WHERE username=:name''', {"name":userName})

def checkSession() -> bool:
    if not Session["loggedIn"]:
        logAction("Suspicious session", Session["userName"], True)
        print("HEY GA WEG JIJ")
        return False
    return True

def checkRole(requiredLevel: int) -> bool:
    userlevel = getUserLevel(Session["userRole"])
    if userlevel > requiredLevel: 
        logAction("Authentication level too low", userlevel + " is lower then " + requiredLevel , True)
        print("How did you get here? msg tommy@hotmail.nl for info")
        return False
    return True

def readLogs():
    if(checkRole(1) and checkSession()):
        result: list = queryDatabase('''SELECT * FROM logFile''')
        pprint.pprint(list(map(lambda x : tuple(map(lambda y : decrypt(y), x)), result)))

def validatePassword(input):
    '''returns True if input is valid '''
    print(input)
    return validateBlacklist(input) and bool(re.match("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%^&*_\-+=`|\(){}\[\]:;'<>,.?/]).{8,30}$", input))
    #VALIDATEBLACKLIST IS SHIT XD
def validateUserInput(input):
    '''returns True when the input is valid, returns False if the input is invalid, logs invalid activity, user is logged out.'''
    if validateBlacklist(input) and validateWhiteList(input):
        logAction("Invalid input", input, True)
        return False
    return True
    
def validateBlacklist(input):
    '''returns True if input is valid '''
    return not bool((re.match(
    "(|rm|\\\.\.|\.\.\/|\.\.\\|\\\\|\\|\`|\\\"|-rf|\||\/\/|\/|--|\\x00]|<script>|<\/script>|AND|OR|ALTER|CREATE|DELETE|DROP|EXEC|INSERT|MERGE|SELECT|UPDATE|UNION)", 
    input)))
    
def validateWhiteList(input):
    '''returns True if input is valid '''
    return bool(re.match("^[a-zA-Z0-9@.]+$", input))

reg_user_patt   = re.compile("^[a-zA-Z][\w'.-]{4,19}$")
reg_pass_patt   = re.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[~!@#$%^&*_\-+=`|\(){\}[\]:;'<>,.?\/\.])(?=.{8,})")

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
    print(validatePassword("DDASFA4e!DEE"))
    #printOptions()