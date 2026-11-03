#Function without parameters
# def greet_user():
#     print("Welcome to DAE")
#     print("Hello")
#     print("Goodbye")
#     print("*********")

#greet_user()

# Function with a parameter
# def greet_user(username):
#     print("Welcome to DAE")
#     print("Hello",username)
#     print("Goodbye")
#     print("*********")

# username = input("What's your name?: ")
# greet_user(username)

# Function with multiple parameters
# def greet_user(username,hometown):
#     print("Hello",username)
#     print("Are you from this place?", hometown)

# name = input("What is your name: ")
# hometown = input("What is your hometown?: ")

# greet_user(name,hometown)

#Function with 3 parameters
def greet_user(username,hometown,currentcity):
    print("Welcome to DAE")
    print("Hello",username)
    print("Are you from this place?", hometown)
    print("Are you working in this city?",currentcity)

username = input("What is your name?: ")
hometown = input("What is your hometown?: ")
currentcity = input("Which city are you working now? : ")

greet_user(username,hometown,currentcity)






