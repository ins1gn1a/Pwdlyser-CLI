#! /usr/bin/env python3


__author__ = "Adam Govier"
__license__ = "MIT"
__version__ = "2.5.0"
__maintainer__ = "ins1gn1a"
__status__ = "Production"


import sys, os
import argparse
from string import digits
import re
from collections import Counter
from collections import defaultdict
import collections
import math

parser = argparse.ArgumentParser(description='Password Analyser and Reporting Tool')

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-p','--pass-list',dest='pass_list',help='Enter the path to the list of passwords in the format of username:password (see README usage for additional information).')

summary_group = parser.add_mutually_exclusive_group(required=False)
summary_group.add_argument('--all','-A',dest='print_all',help='Run all standard tests and display the output in format aimed at a more technical audience. Can be combined with -o [org-name], --summary, --admin [path]',action='store_true',required=False)
summary_group.add_argument('--report','-oR',dest='output_report',help='Display a descriptive output that is suitable for a more technical audience. This output provides usernames and partially-masked passwords, and can be used with any of the individual tests (such as -e, -m, -c, etc.)',action='store_true',default=False,required=False)
summary_group.add_argument('--summary',dest='summary',help='Use --summary to provide a descriptive management-summary output.',required=False,action='store_true',default=False)

parser.add_argument('--admin',dest='admin_path',help='Import a line separated list of administrator usernames (Domain Admins, Enterprise Admins, etc.) to check against the cracked password list',required=False)
parser.add_argument('-c','--common',dest='common_pass',help='Analyse passwords against a list of common passwords and their variations',action='store_true',default=False,required=False)
parser.add_argument('--char-analysis',dest='char_anal',help='Perform character-level analysis, useful for penetration and security testers',required=False,action='store_true',default=False)
parser.add_argument('--date',dest='date_day',help='Review passwords that use a variation of dates, days, months, or years',required=False,action='store_true',default=False)
parser.add_argument('-e','--entropy',dest='entropy',help='Output the estimated entropy for the top 10 passwords (by frequency of bits)',action='store_true',default=False)
parser.add_argument('--exact',dest='exact_search',help='Perform a search using an exact input string',required=False)
parser.add_argument('-f','--frequency',dest='freq_anal',help='Perform analysis of the frequency of the top N passwords. Usage example: "-f 10"',required=False,type=int)
parser.add_argument('-fl','--length-frequency',dest='freq_len',help='Perform analysis on the most frequently used password lengths. Usage example: "-fl 15"',required=False,type=int)
parser.add_argument('-k','--keyboard-pattern',dest='keyboard_pattern',help='Identify common keyboard pattern usage within password lists, such as passwords using "zxc123"',required=False,action='store_true',default=False)
parser.add_argument('-l','--length',dest='min_length',help='Display passwords that do not meet the minimum length specified. Usage example: "-l 8"',type=int,required=False)
parser.add_argument('-m','--mask',dest='masks',help='Display the most commonly used Hashcat masks. This is extremely useful for further cracking attacks',action='store_true',required=False,default=False)
parser.add_argument('-mc','--mask-count',dest='masks_results_count',help='(Optional) Specify the number of mask to output for the -m / --masks option',default=25,required=False,type=int)
parser.add_argument('-o','--org-name',dest='org_name',help='Enter the organisation name or abbreviation to identify any users that have a variation in their password. Usage exmaple: "-o google"',required=False)
parser.add_argument('-r','--reuse',dest='reuse_pass',help='List user accounts and masked passwords that re-use passwords between low-privileged and high-privileged accounts.',required=False,action='store_true',default=False)
parser.add_argument('-S','--search',dest='basic_search',help='Run a basic search using a keyword. Non-alpha characters will be stripped, i.e. syst3m will become systm (although this will be compared against the same stripped passwords',required=False)
parser.add_argument('-s','--shared',dest='shared_pass',help='Display any passwords that appear more than once in the list. This is useful for identifying accounts that reuse passwords, such as service accounts or administrators',required=False,action='store_true',default=False)
parser.add_argument('-u','--user',dest='user_search',help='Search for usernames that contain all or part of the input string (case insensitive). Usage example: "-u ins1g"',required=False)
parser.add_argument('-up','--user-as-pass',dest='user_as_pass',help='Check for passwords that use part or all of the username',required=False,action='store_true',default=False)
parser.add_argument('-w','--clean-wordlist',dest='clean_pass_wordlists',help='Enable this flag to append cleaned (no trailing numerics) to a wordlist at wordlist-cleaned.txt. Re-using this wordlist in Hashcat or John can be useful when paired with a strong rule-list',required=False,action='store_true',default=False)
parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
args = parser.parse_args()

pass_list = args.pass_list
admin_list = args.admin_path
organisation = args.org_name
issue_old = None

rows, columns = os.popen('stty size', 'r').read().split()

banner =        "\n  #####  #     # #####  #      #   #  ####  ###### ##### \n"
banner = banner + "  #    # #     # #    # #       # #  #      #      #    # \n"
banner = banner + "  #    # #  #  # #    # #        #    ####  #####  #    # \n"
banner = banner + "  #####  # # # # #    # #        #        # #      #####  \n"
banner = banner + "  #      ##   ## #    # #        #   #    # #      #   #  \n"
banner = banner + "  #      #     # #####  ######   #    ####  ###### #    # \n\n"
banner = banner + "  ---- Password analysis & reporting tool --- v" + __version__ + " ----\n"


# Input function
def import_file_to_list(path):
    with open(path) as file:
        out_var = file.read().splitlines()
    return out_var

# Check for admin accounts (from list) that were compromised
def check_admin(user,pwd):
    admin_list = import_file_to_list(args.admin_path)
    for admin in admin_list:
        if admin.lower().rstrip() == user.lower().rstrip():
            if args.summary:
                return (("- " + user + " : " + password_masking(pwd)))
            elif args.output_report:
                print_report(user + " : " + password_masking(pwd)) #  + " [Variation of '" +  + "']")
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
            print_report(user + " : " + password_masking(pwd))
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
            print_report(user + " : " + password_masking(password))
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
            print_report(user + " : " + password_masking(password))
        elif args.summary:
            return (password)
        else:
            output_pass(user,password,"Variation of org name " + org)

# Imports leet config file and processes each mutation
def reverse_leet_speak():
    if (os.path.exists("/etc/pwdlyser/pwd_leet.conf")):
        conf_pwdleet = "/etc/pwdlyser/pwd_leet.conf"
    else:
        try:
            conf_pwdleet = "pwd_leet.conf"
        except:
            sys.exit("[!] Cannot locate pwd_leet.conf. Try running 'setup.sh' again.")
    with open(conf_pwdleet) as leetconf:
        leet_list = leetconf.read().splitlines()
    return leet_list

# Check for user stating as password
def check_user_as_pass(user,pwd):
    if user.rstrip() == "NONE" or user.rstrip() == "":
        return

    if args.summary:
        tmp = check_basic_search(user,pwd,user)

        if tmp:
            return (1)
    else:
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
            print_report(user + " : " + password_masking(password))
        elif args.summary:
            return True
        else:
            output_pass(user,password,"Variation of " + search)

# Common password check from import list - List can be appended to
def check_common_pass(user,password):
    x = 0
    out_issue = ""
    leet_list = reverse_leet_speak()
    pwd_unleet = password
    tmp_summary_count = 0

    # Import common passwords
    if (os.path.exists("/etc/pwdlyser/pwd_common.conf")):
        conf_pwdcommon = "/etc/pwdlyser/pwd_common.conf"
    else:
        try:
            conf_pwdcommon = "pwd_common.conf"
        except:
            sys.exit("[!] Cannot locate pwd_common.conf. Try running 'setup.sh' again.")
    with open (conf_pwdcommon) as passcommon:
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
                print_report(user + " : " + password_masking(password))
            elif args.summary:
                tmp_summary_count += 1
            else:
                out_issue = "Variation of " + common
                output_pass(user,password,out_issue)
                x += 1

    if args.summary:
        return tmp_summary_count

def check_date_day(user,password):
    x = 0
    out_issue = ""

    date_day_list = ['january','february','march','april','may','june','july','august','september','october','november','december','monday','tuesday','wednesday','thursday','friday','saturday','sunday']

    # Loop through each leet_speak change in imported list
    for line in date_day_list:
        if (line in password.lower()) and (x == 0):
            if args.output_report:
                print_report(user + " : " + password_masking(password))
            else:
                out_issue = "Variation of '" + line.rstrip() + "'"
                output_pass(user,password,out_issue)
                x += 1


# output and delimit input list
def delimit_list(list):
    list = import_file_to_list(list)
    out_list = []
    n = 0
    file_line_count = 0
    check_hash_delimit = True
    try:
        for list_entry in list:
            file_line_count += 1
            if check_hash_delimit:
                try:
                    # Check if user:hash:pass - return n += 1 if True
                    if (len(list_entry.split(":",2)[1]) >= 24) and (len(list_entry.split(":",2)[2]) > 0):
                        n += 1
                        print ("[!] Running analysis with 'user:hash:password' delimitation\n")
                        check_hash_delimit = False
                    else:
                        print ("[!] Running analysis with 'user:password' delimitation\n")
                        check_hash_delimit = False
                except:
                    n = 0
                    check_hash_delimit = False

            # Delimits with hash username:hash:password or username:password
            if n != 0:
                try: # Try to delimit user:hash:password
                    list_stuff = [list_entry.split(":",2)[0],list_entry.split(":",2)[2]]
                except: # Except try user:password
                    try:
                        list_stuff = [list_entry.split(":",2)[0],list_entry.split(":",2)[1]]
                    except: # Everything has gone wrong
                        print ("[!] Can't split input line: " + str(file_line_count))
            else:
                list_stuff = list_entry.split(":",1)
            if (len(list_stuff)) == 1: # Can't remember what this does
                list_stuff.append("")
            out_list.append(list_stuff)
    except:
        sys.exit("[!] Cannot delimit the input list. Check that input is format of either 'username:password' or 'username:hash:password'.")
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
        if (z < length) and (args.output_report or args.summary):
            if int(pair[1] / int(len(full_list)) * 100) == 0:
                percent_out = ("< 1")
            else:
                percent_out = int(pair[1] / int(len(full_list)) * 100)
            print_report(str(pair[0]) + " : " + str(percent_out) + "%" + " | " + str(pair[1]) + "/" + str(total_pass_length))
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
        if (z < length) and (args.output_report or args.summary):

            if (int((pair[1] / len(pwd_list)) * 100)) == 0:
                percent_out = ("< 1")
            else:
                percent_out = str(int((pair[1] / len(pwd_list)) * 100))

            print_report("Length : " + str(pair[0]) + " : " + percent_out + "%")
            z += 1
        elif z < length and args.output_report is False:
            output_pass(str(pair[0]),str(pair[1]),"")
            z += 1


def password_masking(x):

    if x == "*******BLANK-PASS*******":
        mask_pwd = x
    else:
        # Output Masking
        if len(x) >= 9:
            mask_pwd = x[0:3] + ((len(x) - 6) * "*") + x[-3:]

        elif len(x) >= 5 and len(x) <= 8:
            mask_pwd = x[0:2] + ((len(x) - 4) * "*") + x[-2:]
        elif len(x) == 4:
            mask_pwd = x[0:1] + ((len(x) - 2) * "*") + x[-1:]
        elif len(x) == 3:
            mask_pwd = x[0:1] + ((len(x) - 2) * "*") + x[-1:]
        elif len(x) == 2:
            mask_pwd = x[0:1] + ((len(x) - 1) * "*")
        else:
            mask_pwd = x

    return mask_pwd

def check_shared_pass(full_list):
    a = ([])
    for item in full_list:
        a.append(item[1])

    # Sort as collection
    y=collections.Counter(a)
    pwd_list = [i for i in y if y[i]>1]

    # Identifying duplicates and outputting
    for x in full_list:
        for z in pwd_list:
            if x[1] == z:
                #if ((len(x[1]) % 2) > 0):

                if args.output_report:
                    print_report(str(x[0]) + " : " + password_masking(x[1]))
                else:
                    output_pass(x[0],str(x[1]),"Password Re-Use")

def check_reuse_pass(full_list,z):
    a = ([])
    for item in full_list:
        a.append(item[1])

    # Sort as collection
    #y=collections.Counter(a)
    #pwd_list = [i for i in y if y[i]>1]

    # Identifying duplicates and outputting
    for x in full_list:
        for user in full_list:
            if (user[0] != x[0]) and (user[0].lower() in x[0] and user[1] == x[1]):
                if args.output_report or z == 'summary':
                    print_report(str(x[0]) + " : " + password_masking(x[1]))
                    print_report(str(user[0]) + " : " + password_masking(user[1]))
                else:
                    output_pass(x[0],str(x[1]),"Password Re-Use: " + x[0])
                    output_pass(user[0],str(user[1]),"Password Re-Use: " + user[0])

# reuse_pass

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

def hashcat_mask_analysis(full_list):

    words = Counter()
    mask_list = []

    for x in full_list:
        password = x[1]
        full_mask = ""
        mask = []

        # Loop through each character in password string and regex against mask type
        for char in password:
            if re.match("[a-z]", char) is not None:
                mask.append("?l")
            elif re.match("[A-Z]", char) is not None:
                mask.append("?u")
            elif re.match("[0-9]", char) is not None:
                mask.append('?d')
            elif re.match("[!@£$%^&*()\[\]:;\\\/]", char) is not None:
                mask.append("?s")
            else:
                pass

        for z in mask:
            full_mask = full_mask + z

        if (len(full_mask) / 2) == len(password):
            mask_list.append(full_mask)

    words.update(mask_list)
    wordfreq = (words.most_common())

    w = 0
    ast = "*"
    mostUsed = (wordfreq[0])[1]

    if args.output_report:
        print ("The top 10 Hashcat masks:")


    for m in wordfreq:
        if w != args.masks_results_count: # Limit output to 10 most common entries
            mask_length = str(int(len(m[0]) / 2))
            mask_occurrence = str(m[1])
            if args.output_report:
                print_report(m[0] + " - Length:" + mask_length + " - Occurrence: " + mask_occurrence)
            else:
                output_pass(str(m[0]),mask_length,mask_occurrence)
                w += 1
    print ("")


def keyboard_patterns(full_list):
    keyboard_list = ["hjkl","asdf","lkjh","qwerty","qwer","zaqwsx","zaqxsw","qazwsx","qazxsw","zxc","zxcvbn","zxcdsa","1qaz","2wsx","poiuy","mnbvc","plm","nkoplm","qwer1234","2468","1357","3579","0864"]
    total_count = 0
    for x in full_list:
        count = 0
        for z in keyboard_list:
            if count > 0:
                continue
            if z.lower() in x[1].lower():
                if args.output_report:
                    print_report(str(x[0]) + " : " + password_masking(x[1]))
                    count += 1
                elif args.summary:
                     total_count += 1
                else:
                    output_pass(x[0],str(x[1]),"Keyboard Pattern " + z.rstrip())
                    count += 1

    if args.summary:
        return (total_count)

def remove_end_numeric(pass_list):
    f = open('wordlist-cleaned.txt','w')
    cleaned_pass_list = []

    for p in pass_list:
        p = p[1]
        length = (len(p) - 1)
        last_alpha = length
        z = False

        break_check_length = len(p)

        if (len(p) == 0):
            continue

        if re.match("[a-zA-Z]",p[length]):
            cleaned_pass_list.append(p)
            z = True

        for n in range(0,length):
            temp_char = p[n]

            if re.match("[a-zA-Z]",temp_char):
                last_alpha = n + 1

        final_pass = p[:last_alpha]
        if z is False:
            cleaned_pass_list.append(final_pass)
    for pwd in cleaned_pass_list:
        f.write(pwd + '\n')
    f.close()

def entropy_calculate(full_list):
    words = Counter()
    entropy_list = []
    for x in full_list:
        temp_list = []
        pwd = x[1]
        L = len(pwd)
        char_space = 0
        e = []
        count = 0
        for c in pwd:
            if re.match('[a-z]',c):
                e.append(math.log2(26))
            elif re.match('[A-Z]',c):
                e.append(math.log2(26))
            elif re.match('[0-9]',c):
                e.append(math.log2(10))
            else:
                e.append(math.log2(33))
        # for n in pwd:
#             if re.match('[a-z]',n):
#                 char_space += 26
#             elif re.match('[A-Z]',n):
#                 char_space += 26
#             elif re.match('[0-9]',n):
#                 char_space += 10
#             else: # 33 Special chars as per Hashcat !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ (including space)
#                 char_space += 33
        #entropy = L * math.log2(char_space)

        for x in e:
            count += x
        entropy_list.append([int(count),pwd])

    sorted_ent_list = sorted(entropy_list, reverse=True)
    if args.output_report:
        print ("\nThe following items are the top 10 estimated 'strongest' passwords (by entropy) that were able to be computed: ")
    else:
        output_pass("-" * 30,"-" * 30,"")
        output_pass("Entropy","Password","")
        output_pass("-" * 30,"-" * 30,"")

    w = 0 # Max output for top passwords
    for m in sorted_ent_list:

        pass_ent = m[0]
        if w != 10: # Limit output to 10 most common entries
            if args.output_report:
                print_report(str(pass_ent) + ' bits - ' + password_masking(m[1]))
                w += 1
            else:
                output_pass(str(pass_ent) + " bits",str(m[1]),"")
                w += 1

    sorted_ent_list = sorted(entropy_list, reverse=False)
    if args.output_report:
        print ("\nThe following items are the top 10 estimated 'weakest' passwords (by entropy) that were able to be computed: ")
    else:
        print ('\n')
        output_pass("-" * 30,"-" * 30,"")
        output_pass("Entropy","Password","")
        output_pass("-" * 30,"-" * 30,"")

    w = 0 # Max output for top passwords
    for m in sorted_ent_list:

        pass_ent = m[0]
        if w != 10: # Limit output to 10 most common entries
            if args.output_report:
                print_report(str(pass_ent) + ' bits - ' + password_masking(m[1]))
                w += 1
            else:
                output_pass(str(pass_ent) + " bits",str(m[1]),"")
                w += 1

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
    shared_count = 0
    keyboard_count = 0
    reuse_count = 0

    if (args.output_report is False):
        if ((args.freq_anal is None) and (args.freq_len is None) and (args.masks is None)):
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

    if args.reuse_pass:
        if args.output_report:
            print ("\nThe following accounts were found to share the same password between similarly named accounts. These are believed to be service accounts or individual user accounts that are operated by the same user. Password re-use should be investigated as when a password is reused between a low privileged and a high privileged account it can lead to a compromise of systems that the high privileged account is authorised to access:")
            check_reuse_pass(full_list,'summary')
        else:
            output_pass("-" * 30,"-" * 30,"")
            output_pass("Username","Password","Description")
            output_pass("-" * 30,"-" * 30,"")
            check_reuse_pass(full_list,'')

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

    elif args.summary:
        print ("A password audit was performed against the extracted password hashes. Password cracking methods and tools were used to enumerate the plaintext password counterparts, and as such not all of the passwords were able to be identified. In total, there were " + str(len(full_list)) + " username and password combinations that were obtained and have been analysed.")

        # Top 10 most used passwords
        print ("\nAs part of the password audit, the top 10 most commonly used passwords within the organisation have been compiled. This list has been broken up with the password, the percentage of the total passwords, and the numeric value of the total passwords:")
        check_frequency_analysis(full_list,10)

        # Top 10 password lengths
        print ("\nAlongside the list of the most common passwords used within the organisation, the top 10 most common password lengths were analysed and the results can be seen below in the format of the character length and the percentage of the total passwords for each respective password length:")
        check_frequency_length(full_list,10)

        # Count of commonly seen passwords
        common_summary_count = 0
        for item in full_list:
            user = item[0]
            pwd = item[1]
            if pwd == "":
                pwd = "*******BLANK-PASS*******"
            if (check_common_pass(user,pwd)) == 1:
                common_summary_count += 1
        if (common_summary_count > 0):
            print ("\nOne of the biggest threats to organisations in relation to passwords used by users and administrators is the use of passwords that are the same, or a variation of commonly used passwords and phrases. Overall, there were " + str(common_summary_count) + " passwords that were found to have a variation of one of these common words or phrases. Some of these passwords are based on the words 'password', 'qwerty', 'starwars', 'system', 'admin', 'letmein', and 'iloveyou'. Further details can be seen within the 'pwd_common.conf' file at https://www.github.com/ins1gn1a/pwdlyser.")

        # Count of collated instances of shared passwords
        #check_shared_pass(full_list)

        # Count of keyboard patterns
        keyboard_summary_count = keyboard_patterns(full_list)
        if keyboard_summary_count > 0:
            print ("\nAs part of the wider password analysis, each password was assessed and compared to common keyboard patterns. These keyboard patterns were defined by the QWERTY layout, where a password is made up of characters in close proximity such as 'qwer', 'zxcvbn', and 'qazwsx' as an example. In total, there were " + str(keyboard_summary_count) + " passwords in use that had at least one of these or other variations.")

        # Count of username as password variation
        userpass_summary_count = 0
        for item in full_list:
            user = item[0]
            pwd = item[1]
            if pwd == "":
                pwd = "*******BLANK-PASS*******"

            if (check_user_as_pass(user,pwd)) == 1:
                userpass_summary_count += 1
        if (userpass_summary_count > 0):
            print ("\nThere were " + str(userpass_summary_count) + " passwords that were identified as having a password set that was a variation of the username; this includes additional prefixed or suffixed characters, substitutions within the word (i.e. 3 instead of e), or the username as it appears. Penetration testers, and more importantly attackers, will often check system or administrative accounts that have a variation of the username set as the password and as such it is critical that organisations do not use this convention for password security." )

        # Count of organisation name in password
        # Requires -o parameter
        if args.org_name:
            org_summary_count = 0
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                if (check_org_name(user,pwd,organisation)) is not None:
                    org_summary_count += 1
            if (org_summary_count) > 0:
                print ("\nThe organisation name, or a variation of the name (such as an abbreviation), " + args.org_name + " was found to appear within " + str(org_summary_count) +  " of the passwords that were able to be obtained during the password audit. For any system or administrative user accounts that have a variation of the company name as their password, it is highly recommended that the passwords are changed to prevent targeted guessing attacks.")


        print ("\nThe following accounts were found to share the same password between similarly named accounts. These are believed to be service accounts or individual user accounts that are operated by the same user. Password re-use should be investigated as when a password is reused between a low privileged and a high privileged account it can lead to a compromise of systems that the high privileged account is authorised to access:")
        check_reuse_pass(full_list,'summary')


        if args.admin_path:
            admin_summary_list = []
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                tmp_admin_summ_out = check_admin(user,pwd)
                if tmp_admin_summ_out is not None:
                    admin_summary_list.append(check_admin(user,pwd))

            if len(admin_summary_list) > 0:

                print ("\nFinally, there were " + str(len(admin_summary_list)) + " administrative accounts (based upon 'Domain Admins', 'Enterprise Admins', etc.) that were able to be compromised. The account names and their respective passwords (masked) can be seen below:")
                for admin_summary_pass in admin_summary_list:
                    print (admin_summary_pass)

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

            print ("\nThe length of the following user accounts have passwords set that do not meet the recommended minimum of 9 characters:")
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

            if args.output_report and shared_count == 0:
                print ("\nThe following user accounts were found to have a passwords set that are re-used within other user accounts (with '*' representing a masked character). Usually, this is a coincidence with accounts using 'standard' weak password (such as 'Password1' or 'qwerty123', however where privileged/administrative accounts are used these should be reviewed further: ")
                shared_count += 1
                check_shared_pass(full_list)

            print ("\nThe following accounts were found to share the same password between similarly named accounts. These are believed to be service accounts or individual user accounts that are operated by the same user. Password re-use should be investigated as when a password is reused between a low privileged and a high privileged account it can lead to a compromise of systems that the high privileged account is authorised to access:")
            check_reuse_pass(full_list,'summary')


            print ("\nThe following user accounts were found to have a password that was a variation of a day or date (e.g. Monday01 or September2016):")
            for item in full_list:
                user = item[0]
                pwd = item[1]
                if pwd == "":
                    pwd = "*******BLANK-PASS*******"
                check_date_day(user,pwd)

            if args.output_report and common_count == 0:
                print ("\nThe following user accounts were found to have a password that was a variation of the most common user passwords, which can include 'password', 'letmein', '123456', 'admin', 'iloveyou', 'friday', or 'qwerty':")
                common_count += 1
                for item in full_list:
                    user = item[0]
                    pwd = item[1]
                    if pwd == "":
                        pwd = "*******BLANK-PASS*******"
                    check_common_pass(user,pwd)

            if args.output_report and keyboard_count == 0:
                print ("\nThe following user accounts were identified as having passwords that utilise common keyboard patterns such as qwer, zxcvbn, qazwsx, etc.: ")
                keyboard_count += 1
                keyboard_patterns(full_list)

            sys.exit() # Skip analysis functions below

        # Check for passwords that don't meet Min Length
        if (args.min_length is not None):
            if args.output_report and min_count == 0:
                print ("\nThe length of the following user accounts have passwords set that do not meet the required minimum of " + str(args.min_length) + " characters:")
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

        # Check for password reuse between accounts
        if args.shared_pass:
            if args.output_report and shared_count == 0:
                print ("\nThe following user accounts were found to have a passwords set that are re-used within other user accounts (with '*' representing a masked character). Usually, this is a coincidence with accounts using 'standard' weak password (such as 'Password1' or 'qwerty123', however where privileged/administrative accounts are used these should be reviewed further: ")
                shared_count += 1
            check_shared_pass(full_list)

        if args.keyboard_pattern:
            if args.output_report and keyboard_count == 0:
                print ("\nThe following user accounts were identified as having passwords that utilise common keyboard patterns such as qwer, zxcvbn, qazwsx, etc.: ")
                keyboard_count += 1
            keyboard_patterns(full_list)

        if args.masks:
            if args.output_report is False:
                output_pass("-" * 30,"-" * 30,"-" * 30)
                output_pass("Hashcat Mask","Mask Length","Occurrences")
                output_pass("-" * 30,"-" * 30,"-" * 30)
            hashcat_mask_analysis(full_list)

        if args.clean_pass_wordlists:
            print ("\n[*] Cleaned " + str(len(full_list)) + " words to 'wordlist-cleaned.txt'")
            remove_end_numeric(full_list)

        if args.entropy:
            entropy_calculate(full_list)
