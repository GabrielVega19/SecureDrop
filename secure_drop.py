# The secure_drop command is the entry point of the application. If a user
# does not exist, the registration module will activate. The email address
# is used as the user identifier.
from sys import exit
from hmac import compare_digest
from Crypto.Cipher import AES
from backports.pbkdf2 import pbkdf2_hmac
import getpass
import pickle
import crypt  
import json
from os import urandom



#global variable for the name of the file where userdata is stored
filename = "userdata"

#this is the class to hold the information for the user 
class user:
  def __init__(self, name, email, password):
    #name email and password for user
    self.name = name
    self.email = email
    self.password = crypt.crypt(password)
    #stuff for encryption and decryption of the contacts 
    self.salt = urandom(16)
    self.nonce = b""
    self.tag = b""
    #a binary string that will get decoded and hold the dictionary of contacts 
    self.contacts = b""
    
    #sets up the first encryption for contact and dumps to userData
    self.encryptContacts(password, {})
    self.dump(filename)
    
  #member function that checks if the username and password were correct takes in username and password and returns true or false
  def valPass(self, username, password):
    if username == self.email:
      return compare_digest(crypt.crypt(password, self.password), self.password) 
  
  #member function that dumps the contents of userclass into a file
  def dump(self, filename):
    pickle.dump(self, open(filename, 'wb'))

  #member function that is used for adding a contact takes in the name and email of user and password used to encrypt contact info
  def addContact(self, name, email, password):
    dict = self.decryptContacts(password)
    dict[name] = email
    self.encryptContacts(password, dict)

    self.dump(filename)
    print("Contact Added.")

  #member function that encrypts the contact dictionary takes in the dictionary to encrypt and the password used to encrypt it
  def encryptContacts(self, password, dict):
    key = pbkdf2_hmac("sha256", bytes(password, 'ascii'), self.salt, 50000, 32)
    aesObject = AES.new(key, AES.MODE_GCM)
    self.contacts, self.tag = aesObject.encrypt_and_digest(json.dumps(dict).encode('ascii'))
    self.nonce = aesObject.nonce
  
  #function that decrypts the function dictionary returns the dictionary decrypted with the password
  def decryptContacts(self, password):
    key = pbkdf2_hmac("sha256", bytes(password, 'ascii'), self.salt, 50000, 32)
    aesObject = AES.new(key, AES.MODE_GCM, nonce = self.nonce)
    self.contacts = aesObject.decrypt_and_verify(self.contacts, self.tag)
    return json.loads(self.contacts.decode("ascii"))


#the login proscess prompts for email and password and checks it against the stored data
def login(dataFile):
  #loads data
  userData = pickle.load(dataFile)

  #login loop
  while(True):
    username = input("Enter Email Address: ")
    password = getpass.getpass("Enter Password: ")
    
    if(not userData.valPass(username, password)):
      print("Email and Password Combination Invalid.")
    else:
      #returns userData class and successful password to the main shell loop
      return userData, password


#creates a user and then outputs it into a file
def createUser(): 
  #gets user data
  fullName = input("Enter Full Name: ")
  email = input("Enter Email Address: ")
  #checks passwords match 
  while True:      
    pswd= getpass.getpass("Enter Password: ")
    repswd = getpass.getpass("Re-enter Password: ")
    if pswd == repswd and pswd:
      print("Passwords match.")
      break
    else:
      print("Passwords do not match.")
  
  #puts data into a user class and dumps it to the file
  userData = user(fullName.lower(), email.lower(), pswd)

  exit(0)



def main():
  #main code that tries to login and if no userdata then it creates one and exits 
  try:
    with open(filename, 'rb') as dataFile:
      print("User Data was found")
      userData, password = login(dataFile)
  except IOError:
    print("No users are registered with this client.")
    while True:
      value = input("Do you want to register a new user (y/n)? ")
      if value == 'y' or value == 'Y':
        createUser()
        break
      elif value == 'n' or value == 'N':
        exit()
      else:
        print("Invalid Input")

  #will get here on successful login
  print("Welcome to SecureDrop.")
  print("Type \"help\" For Commands.")
  
  #main loop for the shell 
  while(True):
    #gets input from the user
    command = input("secure_drop> ")
    
    #proscesses the command from the user
    if command == "help":
      print("     \"add\" -> Add a new contact")
      print("     \"list\" -> List all online contacts")
      print("     \"send\" -> Transfer file to contact")
      print("     \"exit\" -> Exit SecureDrop")
    elif command == "add":
      name = input("     Enter Full Name: ")
      email = input("     Enter Email Address: ")
      userData.addContact(name, email, password)
    elif command == "exit":
      break
    else:
      print("Invlid Command.")

  #exit condition for the program 
  exit(0)

  
  

if __name__ == '__main__':
    main()
