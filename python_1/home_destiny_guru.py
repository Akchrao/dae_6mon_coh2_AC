
print("Welcome to learning Python")
print("Enjoy Coding")
print("Welcome to Home Destiny Guru")

# Hardcoding the values to represent the user's credentials
correct_username = "Akhi"
correct_password = "Daetraining"
computer_weather = 76
user_wants_to_try_again = "True"
 
# Ask the user for their username
user_name = input("Please enter the username: ")
password = input("Thank you. Also please type in your password: ")

# Use while loop to run the code if the username and password are incorrect.

while user_name != correct_username or password != correct_password:
    print("Incorrect username or password. Please try again.")
    user_name = input("Please enter the username: ")
    password = input("Thank you. Also please type in your password: ")

# The while loop is done and below is the code out of while loop

print("Login successful! Welcome,", user_name)
print("Welcome")

# Ask the user for location

#user_location = input("where are you?", Home or Work: ")
#raining = int(input("Is it raining? Press 1 for Yes or 0 for No"))
# Ask if it is raining and the User's location
while user_wants_to_try_again:
    at_home = int(input("Where are you? Press 1 for Home. 0 for Work: "))
    raining = int(input("Is it raining?Press 1 for Yes and 0 for No: "))
    if raining and at_home:
        print("Stay Home")
    elif raining and not at_home:
        print("Stay at Work")
    elif not raining and at_home:
        print("Go to Work")
    elif not raining and not at_home:
        print("Go Home")

    # # Ask the user if interested to go again or leave the site
    print("Thank you for using the Home Destiny Guru")

    repeat_Guru = input("Do you want to use again?Press y/n ")
    while repeat_Guru != "y" and repeat_Guru != "n":
        repeat_Guru = input("Hey,please enter a y or n,Nothing else")

    if repeat_Guru =="y":
        user_wants_to_try_again = 1

    elif repeat_Guru =="n":
        user_wants_to_try_again = 0

print("Thank you,Bye!")
    






        