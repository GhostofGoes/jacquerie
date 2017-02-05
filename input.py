# will ask the user for the message then grab the current time-stamp

""" input will be created as a dict.
        Name: msgpkt
    
    will create 2 fields.
        Message:
        Timestamp:
    
    Message will be an input from the user using getpass to maintain security.
    
    Timestamp will be the GMT at the time the message is received. """
    
from time import time, gmtime, asctime
from getpass import getpass

def tacos():
    msgpkt = {}

    # get user input
    msgpkt["Message"] = getpass("Enter Message:")

    # get time-stamp for message
    msgpkt["Timestamp"] = asctime(gmtime(time()))

    # pass data to next module !! Currently print function for testing.
    return(msgpkt)
