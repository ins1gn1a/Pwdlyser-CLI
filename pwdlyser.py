#! /usr/bin/env python3

# Password analyser
#
# 1) Multiple input types: username:password, password, email:password
# 2) outputs to CSV for review with excel, but also to stdout in graph
# 3) functionalities include: 
#	identify 'organisation' names within pwds
#	weak < 9 character/10 character passwords
# 	identify domain admins/admins/etc from an imported list (take admin list, highlight any of those)

import sys, os
import argparse
import re

parser = argparse.ArgumentParser(description='Password Analyser')
parser.add_argument('-p','--pass-list',dest='pass_list',help='Enter the path to the list of passwords, either in the format of passwords, or username:password.',required=True)
parser.add_argument('-a','--admin-list',dest='admin_list',help='Enter the path to the list of admin accounts that will be highlighted if they are seen within the password list',required=False)
parser.add_argument('-n','--org-name',dest='org_name',help='Enter the organisation name to identify any users that will be using a variation of the word for their password. Note: False Positives are possible',required=False)
parser.add_argument('--length',dest='min_length',help='Display passwords that do not meet the minimum length',type=int)
parser.add_argument('-i',dest='input_type',help='Type of input for the password list. "-i 1" for username:password, "-i 2" for password.',type=int,required=True)
parser.add_argument('-A',dest='print_all',help='Print only usernames',action='store_true')
#parser.add_argument('-s',dest='basic_search',help='Run a basic search using a keyword. Non-alpha characters will be stripped, i.e. syst3m will become systm (although this will be compared against the same stripped passwords')
args = parser.parse_args()

pass_list = args.pass_list
admin_list = args.admin_list
organisation = args.org_name
input_type = args.input_type

# Input function
def import_file_to_list(path):
    with open(path) as file:
        out_var = file.read().splitlines()
    return out_var

# Do stuff -- NOT YET1
def output_pass(username,password,issue):
    # Username:Pass
    print (username.ljust(30),end=":".ljust(5),flush=True)
    print (password.ljust(30),end=":".ljust(5),flush=True)
    print (issue)

# Check for inputted min length
def check_min_length(password,min):
    if len(password) < min:
        output_pass(user,pwd,"Length < " + str(args.min_length))

# Check for inputted min length
def check_org_name(user,password,org):
    re_alpha = re.compile('[^a-zA-Z]')
    org_stripped = re_alpha.sub('', org)
    pass_stripped = re_alpha.sub('', password)
    if org_stripped.lower() == pass_stripped.lower():
        output_pass(user,pwd,"Contains variation of " + org)

# output and delimit input list
def delimit_list(list):
    list = import_file_to_list(list)
    out_list = []
    for list_entry in list:
        out_list.append(list_entry.split(":"))
    return out_list

# Run main stuff
if __name__ == "__main__":

     # Retrieve list
     x = (delimit_list(pass_list))

     # Headers
     output_pass("Username","Password","Description")
     
     # Cycle through output list
     for item in x:
         if input_type == 1:
             user = item[0]
         else:
             user = "NONE"
         if (input_type == 2):
             pwd = item[0]
         else:
             pwd = item[1]

         # Print everything regardless
         if args.print_all:
             output_pass(user,pwd,"Not Analysed")
             continue # Skip analysis functions below

         # Check Min Length
         if (args.min_length is not None):
             check_min_length(pwd,args.min_length)

         # Check if Org name (or slight variation) is in list
         if organisation is not None:
             check_org_name(user,pwd,organisation)

        
