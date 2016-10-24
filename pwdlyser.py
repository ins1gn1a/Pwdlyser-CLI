#! /usr/bin/env python3

'''
To Do:
* Identify multiple shared passwords.
* Keyboard patterns: e.g. zxcdsa, asdfjkl;
'''

import sys, os
import argparse
from string import digits
import re
from collections import Counter
from collections import defaultdict

parser = argparse.ArgumentParser(description='Password Analyser')
parser.add_argument('-p','--pass-list',dest='pass_list',help='Enter the path to the list of passwords, either in the format of passwords, or username:password.',required=True)
parser.add_argument('-o','--org-name',dest='org_name',help='Enter the organisation name to identify any users that will be using a variation of the word for their password. Note: False Positives are possible',required=False)
parser.add_argument('-l','--length',dest='min_length',help='Display passwords that do not meet the minimum length',type=int,required=False)
parser.add_argument('-A','--all',dest='print_all',help='Print only usernames',action='store_true',required=False)
parser.add_argument('-s','--search',dest='basic_search',help='Run a basic search using a keyword. Non-alpha characters will be stripped, i.e. syst3m will become systm (although this will be compared against the same stripped passwords',required=False)
parser.add_argument('-oR',dest='output_report',help='Output format set for reporting with "- " prefix',action='store_true',default=False,required=False)
parser.add_argument('-c','--common',dest='common_pass',help='Check against list of common passwords',action='store_true',default=False,required=False)
parser.add_argument('-f','--freq',dest='freq_anal',help='Perform frequency analysis',required=False,type=int)
parser.add_argument('--exact',dest='exact_search',help='Perform a search using the exact string.',required=False)
parser.add_argument('-u','--user',dest='user_search',help='Return usernames that match string (case insensitive)',required=False)
parser.add_argument('--admin',dest='admin_path',help='Import line separated list of Admin usernames to check password list',required=False)
parser.add_argument('-up','--user-as-pass',dest='user_as_pass',help='Check for passwords that use part of the username',required=False,action='store_true',default=False)
#parser.add_argument('--shared',dest='shared_pass',help='Display any reused/shared passwords.',required=False,action='store_true',default=False)
parser.add_argument('-fl','--freq-length',dest='freq_len',help='Perform frequency analysis',required=False,type=int)
parser.add_argument('--char-analysis',dest='char_anal',help='Perform character-level analysis',required=False,action='store_true',default=False)
parser.add_argument('--date',dest='date_day',help='Check for common date/day passwords',required=False,action='store_true',default=False)
args = parser.parse_args()

pass_list = args.pass_list
admin_list = args.admin_path
organisation = args.org_name
issue_old = None

rows, columns = os.popen('stty size', 'r').read().split()

v_1 = "1"
v_2 = "2"
v_3 = "2"

version = v_1 + "." + v_2 + "." + v_3

banner =        "\n  #####  #     # #####  #      #   #  ####  ###### ##### \n"
banner = banner + "  #    # #     # #    # #       # #  #      #      #    # \n"
banner = banner + "  #    # #  #  # #    # #        #    ####  #####  #    # \n"
banner = banner + "  #####  # # # # #    # #        #        # #      #####  \n"
banner = banner + "  #      ##   ## #    # #        #   #    # #      #   #  \n"
banner = banner + "  #      #     # #####  ######   #    ####  ###### #    # \n\n"
banner = banner + "  ---- Password analysis & reporting tool --- v" + version + " ----\n"


# Input function
def import_file_to_list(path):
    with open(path) as file:
        out_var = file.read().splitlines()
    return out_var

def check_admin(user,pwd):

    admin_list = import_file_to_list(args.admin_path)
    for admin in admin_list:
        #print (admin.lower().rstrip() ==  user.lower().rstrip())
        if admin.lower().rstrip() == user.lower().rstrip():
            if args.output_report:
                print_report(user) #  + " [Variation of '" +  + "']")
            else:
                output_pass(user,pwd,"Admin: " + admin)

# Output to STDOUT
def output_pass(username,password,issue):


    if password.rstrip() == "":
        end = ""
    else:
        end = ":"

    if issue.rstrip() == "":
        end_delim = ""
    else:
        end_delim = ":"

    print (str(username.ljust(30)),end=end.ljust(5),flush=True)
    print (str(password.ljust(35)),end=end_delim.ljust(5),flush=True)
    print (issue)

def print_report(u):
    print ("- " + u)

# Check for inputted min length
def check_min_length(password,min):
    if (len(password) < min) or (password.rstrip() == "*******BLANK-PASS*******"):
        if args.output_report:
            print_report(user)
        else:
            output_pass(user,pwd,"Length < " + str(args.min_length))

def check_user_search(user,password,term):
    if term.lower() in user.lower():
        if args.output_report:
            print_report(user)
        else:
            output_pass(user,password,"Username Search: " + term)

def check_exact_search(user,password,term):
    if term in password:
        if args.output_report:
            print_report(user)
        else:
            output_pass(user,password,"Term " + term + " in password")

# Check for org name (reused code from below, laziness)
def check_org_name(user,password,org):
    x = 0
    pwd_unleet = password
    leet_list = reverse_leet_speak()
    for line in leet_list:
        if "," in line:
            char_change = line.split(",")
        else:
            continue
        try:
            pwd_unleet = (pwd_unleet.replace(char_change[0],char_change[1])).lower()
            search = org.lower()
        except:
            continue
    if (search in pwd_unleet):
        if args.output_report:
            print_report(user)
        else:
            output_pass(user,password,"Variation of org name " + org)

# Imports leet config file and processes each mutation
def reverse_leet_speak():
    with open("pwd_leet.conf") as leetconf:
        leet_list = leetconf.read().splitlines()
    return leet_list

def check_user_as_pass(user,pwd):
    if user.rstrip() == "NONE" or user.rstrip() == "":
        return
    check_basic_search(user,pwd,user)

# Checks for variation of input based upon removal of leetspeak
def check_basic_search(user,password,search):
    x = 0
    pwd_unleet = password
    leet_list = reverse_leet_speak()
    for line in leet_list:
        if "," in line:
            char_change = line.split(",")
        else:
            continue
        try:
            pwd_unleet = (pwd_unleet.replace(char_change[0],char_change[1])).lower()
            search = search.lower()
        except:
            continue
    if (search in pwd_unleet):
        if args.output_report:
            print_report(user)
        else:
            output_pass(user,password,"Variation of " + search)

# Common password check from import list - List can be appended to
def check_common_pass(user,password):
    x = 0
    out_issue = ""
    leet_list = reverse_leet_speak()
    pwd_unleet = password

    # Import common passwords
    with open ("pwd_common.conf") as passcommon:
        pass_list = passcommon.read().splitlines()

    # Loop through common passwords list
    for common in pass_list:
        common = common.lower()

        # Loop through each leet_speak change in imported list
        for line in leet_list:
            char_change = line.split(",")

            # Amend each
            try:
                if char_change[0] in password:
                     pwd_unleet = (pwd_unleet.replace(char_change[0],char_change[1])).lower()
            except:
                continue

        if (common in pwd_unleet) and (x == 0):
            if args.output_report:
                print_report(user)
            else:
                out_issue = "Variation of " + common
                output_pass(user,password,out_issue)
                x += 1

def check_date_day(user,password):
    x = 0
    out_issue = ""

    date_day_list = ['january','february','march','april','may','june','july','august','september','october','november','december','monday','tuesday','wednesday','thursday','friday','saturday','sunday']

    # Loop through each leet_speak change in imported list
    for line in date_day_list:
        if (line in password.lower()) and (x == 0):
            if args.output_report:
                print_report(user)
            else:
                out_issue = "Variation of '" + line.rstrip() + "'"
                output_pass(user,password,out_issue)
                x += 1


# output and delimit input list
def delimit_list(list):
    list = import_file_to_list(list)
    out_list = []
    for list_entry in list:
        list_stuff = list_entry.split(":",1)
        if (len(list_stuff)) == 1:
            list_stuff.append("")
        out_list.append(list_stuff)
    return (out_list)

# Perform frequency analysis for [num]
def check_frequency_analysis(full_list,length):
    z = 0
    pwd_list = []
    words = Counter()
    total_pass_length = 0

    for pwd in full_list:
        x = pwd[1]
        if x == "":
            x = "*******BLANK-PASS*******"
        pwd_list.append(x)
        total_pass_length += 1

    words.update(pwd_list)
    wordfreq = (words.most_common())

    for pair in wordfreq:
        if z < length and args.output_report:
            print_report(str(pair[0]) + " : " + str(int(pair[1] / int(len(wordfreq)) * 100)) + "%" + " | " + str(pair[1]) + "/" + str(total_pass_length))
            z += 1
        elif z < length and args.output_report is False:
            output_pass(pair[0],str(pair[1]),"")
            z += 1

# Perform frequency analysis for [num]
def check_frequency_length(full_list,length):
    z = 0
    pwd_list = []
    words = Counter()

    for pwd in full_list:
        x = pwd[1]
        pwd_list.append(len(x))

    words.update(pwd_list)
    wordfreq = (words.most_common())

    for pair in wordfreq:
        if z < length and args.output_report:
            print_report("Length : " + str(pair[0]) + " : " + str(int((pair[1] / len(pwd_list)) * 100)) + "%")
            z += 1
        elif z < length and args.output_report is False:
            output_pass(str(pair[0]),str(pair[1]),"")
            z += 1

'''
#def check_shared_pass(full_list):
#    z = 0
#    pwd_list = []
#    words = Counter()

    for pwd in full_list:
        x = pwd[1]
        if x ==.rstrip() "":
            x = "*******BLANK-PASS*******"
        pwd_list.append(x)

    words.update(pwd_list)
    wordfreq = (words.most_common())

    comp_list = []
    for pair in wordfreq:
        if z < 10:
            comp_list.append(pair)
            z += 1
    for dup in sorted(list_duplicates(full_list)):
        print (dup)

def list_duplicates(seq):
    tally = defaultdict(list)
    for i,item in enumerate(seq):
        tally[item].append(i)
    return ((key,locs) for key,locs in tally.items()
                            if len(locs)>1)

#    print (comp_list)

#    seen = set(full_list)
#    uniq = []
#    for q in comp_list:
#        if q[1] not in seen:
#            uniq.append(q)
#            seen.add(q)


#    for l in uniq:
#        output_pass(l[0],str(l[1]),"")

'''

# Run character analysis

# Perform analysis analysis
def check_character_analysis(full_list):
    z = 0
    pwd_list = []
    words = Counter()
    upperList = []
    lowerList = []
    numList = []
    specList = []
    allList = []

    for pwd in full_list:
        z += 1
        x = pwd[1]
        pwd_list.append(x)

    alphaCharList = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
    numCharList = ['0','1','2','3','4','5','6','7','8','9']
    specCharList = ['!','@','£','#','$','%','^','&','*','(',')','-','+','=','_','|','?','`','±','§',';',':']


    # At present I only report on top characters, but the *List dicts provide support for single charset type.
    for e in pwd_list:
        charLen = len(e)

        for char in alphaCharList:
            count = 0
            for i in range(charLen):
                if char.upper() == e[count]:
                    upperList.append(e[count])
                    allList.append(e[count])
                elif char.lower() == e[count]:
                    lowerList.append(e[count])
                    allList.append(e[count])
                count += 1

        for char in numCharList:
            count = 0
            for i in range(charLen):
                if char == e[count]:
                    allList.append(e[count])
                    numList.append(e[count])
                count += 1

        for char in specCharList:
            count = 0
            for i in range(charLen):
                if char == e[count]:
                    specList.append(e[count])
                    allList.append(e[count])
                count += 1

    words.update(allList)
    wordfreq = (words.most_common())

    w = 0
    ast = "*"
    mostUsed = (wordfreq[0])[1]

    if args.output_report:
        print ("The top 20 characters used out of " + str(z) + " passwords:")

    for pair in wordfreq:
        if w != 20:
            percent = str((pair[1] / mostUsed) * 50).split('.')[0]
            if args.output_report:
                print_report(str((pair[0]) + "  :  " + str(ast * int(percent)) + str((10 - int(percent)) * " ") + "| " + str(pair[1])))
            else:
                output_pass(str(pair[0]),str(pair[1]),"")
            w += 1
    print ("")

# Run main stuff
if __name__ == "__main__":

    print (banner)

    if int(columns) < 110:
        sys.exit("Warning: Resize your terminal to be at least 110 columns wide. Currently it is " + columns + " columns wide.")

    # Retrieve list
    full_list = (delimit_list(pass_list))
    y = 0

    min_count = 0
    common_count = 0
    search_count = 0
    org_count = 0
    exact_count = 0
    admin_count = 0
    pass_count = 0
    date_day_count = 0

    if args.output_report is False:
        if ((args.freq_anal is None) and (args.freq_len is None)):
            if args.char_anal:
                output_pass("-" * 30,"-" * 30,"")
                output_pass("Character","Count","")
                output_pass("-" * 30,"-" * 30,"")

            elif (args.print_all is False):
                # Headers
                output_pass("-" * 30,"-" * 30,"-" * 30)
                output_pass("Username","Password","Description")
                output_pass("-" * 30,"-" * 30,"-" * 30)

    if args.freq_anal is not None:
        if args.output_report:
            print ("The following passwords were the " + str(args.freq_anal) + " most commonly used passwords that were able to be obtained:")
            check_frequency_analysis(full_list,args.freq_anal)
        else:
            output_pass("-" * 30,"-" * 30,"")
            output_pass("Password","Frequency","")
            output_pass("-" * 30,"-" * 30,"")

            check_frequency_analysis(full_list,args.freq_anal)

    elif args.freq_len is not None:
        if args.output_report:
            print ("The following is a descending list of the most popular password lengths: ")
            check_frequency_length(full_list,args.freq_len)
        else:
            output_pass("-" * 30,"-" * 30,"")
            output_pass("Password Length","Frequency","")
            output_pass("-" * 30,"-" * 30,"")
            check_frequency_length(full_list,args.freq_len)

    elif args.char_anal:
        check_character_analysis(full_list)
        
    else:
        # Print everything and exit
        if args.print_all:
            args.output_report = True

            check_character_analysis(full_list)

            print ("The following is a descending list of the most popular password lengths: ")
            check_frequency_length(full_list,10)
            print ("")

            print ("The following passwords were the 15 most commonly used passwords that were able to be obtained:")
            check_frequency_analysis(full_list,15)

            print ("\nThe length of the following user account passwords does not meet the recommended minimum of 9 characters:")
            min_count = 9
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                check_min_length(pwd,min_count)

            print ("\nThe following user accounts used a variation of the username as the password.")
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                check_user_as_pass(user,pwd)
                
            if args.admin_path is not None:
                if args.output_report and admin_count == 0:
                    print ("\nThe following user accounts were identified as Domain Administrators (Domain Admins, Enterprise Admins, Administrators, etc) and were found to have weak passwords set: ")
                    admin_count += 1
                for item in full_list:
                    user = item[0]
                    pwd = item[1]
                    if pwd == "":
                        pwd = "*******BLANK-PASS*******"
                    check_admin(user,pwd)

            print ("\nThe following user accounts were found to have a password that was a variation of a day or date (e.g. Monday01 or September2016):")
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                    check_date_day(user,pwd)

            sys.exit() # Skip analysis functions below

        # Check for passwords that don't meet Min Length
        if (args.min_length is not None):
            if args.output_report and min_count == 0:
                print ("\nThe length of the following user account passwords does not meet the required minimum of " + str(args.min_length) + " characters:")
                min_count += 1
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                check_min_length(pwd,args.min_length)

        # Check if Org name (or slight variation) is in list
        if organisation is not None:
            if args.output_report and org_count == 0:
                print ("\nThe organisation name " + organisation + " appears within several passwords for the following accounts (within some variation):")
                org_count += 1
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                check_org_name(user,pwd,organisation)

        # Check for passwords via unleeted search
        if args.basic_search is not None:
            if args.output_report and search_count == 0:
                print ("\nThe following user accounts were found to have a password that was some variation of the word/phrase: " + args.basic_search)
                search_count += 1
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                check_basic_search(user,pwd,args.basic_search)

        # Check for Common Passwords
        if args.common_pass is True:
            if args.output_report and common_count == 0:
                print ("\nThe following user accounts were found to have a password that was a variation of the most common user passwords, which can include 'password', 'letmein', '123456', 'admin', 'iloveyou', 'friday', or 'qwerty':")
                common_count += 1
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                check_common_pass(user,pwd)

        # Check for Date/Day Passwords
        if args.date_day is True:
            if args.output_report and date_day_count == 0:
                print ("\nThe following user accounts were found to have a password that was a variation of a day or date (e.g. Monday01 or September2016):")
                date_day_count += 1
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                check_date_day(user,pwd)

        # Search exact phrase or character
        if args.exact_search is not None:
            if args.output_report and exact_count == 0:
                print ("\nThe following user accounts were found to have a password that contains the word/phrase " + args.exact_search + ":")
                exact_count += 1
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                check_exact_search(user,pwd,args.exact_search)

        # Check for username (basic search)
        if args.user_search is not None:
            for item in full_list:
                user = item[0]
                pwd = item[1]
                check_user_search(user,pwd,args.user_search)

        # Check if admins have had their passwords cracked
        if args.admin_path is not None:
            if args.output_report and admin_count == 0:
                print ("\nThe following user accounts were identified as Domain Administrators (Domain Admins, Enterprise Admins, Administrators, etc) and were found to have weak passwords set: ")
                admin_count += 1
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                check_admin(user,pwd)

        # Check if password contains username
        if args.user_as_pass:
            if args.output_report and pass_count == 0:
                print ("\nThe following user accounts were found to have a variation of their username set as their account password: ")
                pass_count += 1
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                check_user_as_pass(user,pwd)


# Not working at the moment :(
#    if args.shared_pass:
#        check_shared_pass(full_list)
