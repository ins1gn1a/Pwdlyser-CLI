# Intro
The 'pwdlyser' tool is a Python-based CLI script that automates the arduous process of manually reviewing cracked passwords during password audits following security assessments or penetration tests. There are likely some false positives/negatives, so please Use at your own discretion.

## Installation
The installation of this tool is fairly straight forward. Use the following steps:
```
git clone https://www.github.com/ins1gn1a/pwdlyser.git
cd pwdlyser/
chmod +x setup.sh
./setup.sh
```

## Input: Passwords
Lists can be specified using the ```-p [path/to/file]``` argument, and should be colon delimited as ```username:password```, or just password (however, this will just assess passwords and use a generic username for each). No headers are necessary.

Should you only want to analyse passwords, just enter a colon (":") before each password in the list, which will just output blank usernames. To automate this I've added a script 'add-delimit.py' that will input a list of passwords (only) and append the colon to the start.

## Summary Output

One of the newest features of pwdlyser is the ability to quickly generate a management-level summary of the password health within the organisation. This output is provided in a paragraph format and dynamically details each of the respective checks (i.e. keyboard patterns, common passwords, etc). I would suggest using this for management summaries, whilst the ```-oR``` option should be used for a more technical reporting output.

## Reporting Output

The ```-oR``` argument can be used to generate a list of usernames and passwords that have been analysed within each of the respective checks (shared password reuse, variation of usernames as passwords, etc) in a more technical level. The passwords are masked, except the start and a certain amount of end characters (e.g. ```P*****rd1```). This output is more suitable for a technical commentary within a penetration testing or security assessment report.

## General Usage
There are a range of input arguments that can be used, but for a simple 'common password' search through a list use the ```-c``` argument to initiate the check. This will import the default ```pwd_common.conf``` file and use it as a basis to compare against the password list. Passwords and the common passwords are both converted to lower-case, with the inputted passwords also being 'de-leeted' and converted back to alpha characters (i.e. 3 to e). The reason for this, even though some passwords may end up reading 'iadmin' instead of '!admin' is that this is only a basic comparison, but it seems to work well.

Other arguments also include the check for any users that have their username as part of their password. This can be run using the ```-up``` or ```--user-as-pass``` arugments.

To display any passwords that have a minimum length less than 9 characters use ```-l 9```. The int can be changed to whatever the password policy is, although you should also really ensure that you verify against best-practice too.

Basic ('de-leeted') searches can be run using ```-S [word]```, with an exact search can be run using ```--exact [word]```. The exact search does not modify any characters for comparison and thus allows you to check for any passwords containing '123' or 'P4$$', for example. 

Organisation names often appear within passwords, at least from my experience during internal penetration tests. To check for this, a similar search to the 'basic' search is run, although the only difference is that the 'Description' will state 'Organisation name: [name]' on screen instead. Run this using ```-o [orgname or acronym]```.

If you want to verify whether you were able to crack the passwords for any admin accounts then you can put the usernames (only) in a file and use ```--admin [path/to/file]``` to display any of the admin passwords that could be cracked. This is of course useful for any escalation or pivoting that you may need to do, or to ensure that administrators are not using weak or reusing passwords.

For simple searches for usernames that may be in the password list use ```-u [username/part of username]```. This list also works with email:passwords, it doesn't discriminate. Part, or excerpts of usernames can also be used.

To just identify the top N of passwords, i.e. frequency analysis, use the ```-f [int]``` argument and specify the number of passwords you want to return. This will need to be an integer.

Other options can be seen within the ```-h``` menu or below:

```
usage: pwdlyser [-h] [--all] [--admin ADMIN_PATH] [-c] [--char-analysis]
                [--date] [-e] [--exact EXACT_SEARCH] [-f FREQ_ANAL]
                [-fl FREQ_LEN] [-k] [-l MIN_LENGTH] [-m]
                [-mc MASKS_RESULTS_COUNT] [-o ORG_NAME] [-oR] -p PASS_LIST
                [-S BASIC_SEARCH] [-s] [-u USER_SEARCH] [-up] [-w] [--summary]

Password Analyser

optional arguments:
  -h, --help            show this help message and exit
  --all, -A             Run all standard tests. Can be combined with -o [org-
                        name], --summary, --admin [path]
  --admin ADMIN_PATH    Import line separated list of Admin usernames to check
                        password list
  -c, --common          Check against list of common passwords
  --char-analysis       Perform character-level analysis
  --date                Check for common date/day passwords
  -e, --entropy         Output estimated entropy for the top 10 passwords (by
                        frequency used)
  --exact EXACT_SEARCH  Perform a search using the exact string.
  -f FREQ_ANAL, --frequency FREQ_ANAL
                        Perform frequency analysis
  -fl FREQ_LEN, --length-frequency FREQ_LEN
                        Perform frequency analysis on password length
  -k, --keyboard-pattern
                        Identify common keyboard pattern usage within password
                        lists
  -l MIN_LENGTH, --length MIN_LENGTH
                        Display passwords that do not meet the minimum length
  -m, --mask            Perform common Hashcat mask analysis
  -mc MASKS_RESULTS_COUNT, --mask-count MASKS_RESULTS_COUNT
                        (Optional) Specify the number of mask to output for
                        the -m / --masks option
  -o ORG_NAME, --org-name ORG_NAME
                        Enter the organisation name to identify any users that
                        will be using a variation of the word for their
                        password. Note: False Positives are possible
  -oR                   Output format set for reporting with "- " prefix
  -p PASS_LIST, --pass-list PASS_LIST
                        Enter the path to the list of passwords, either in the
                        format of passwords, or username:password.
  -S BASIC_SEARCH, --search BASIC_SEARCH
                        Run a basic search using a keyword. Non-alpha
                        characters will be stripped, i.e. syst3m will become
                        systm (although this will be compared against the same
                        stripped passwords
  -s, --shared          Display any reused/shared passwords.
  -u USER_SEARCH, --user USER_SEARCH
                        Return usernames that match string (case insensitive)
  -up, --user-as-pass   Check for passwords that use part of the username
  -w, --clean-wordlist  Enable this flag to append cleaned (no trailing
                        numerics) to a wordlist at wordlist-cleaned.txt
  --summary             Use --summary to provide a concise report-friendly
                        output.
```

## Example Outputs

### Basic Search
```
> pwdlyser -p sample-file -S pass

  #####  #    # #####  #      #   #  ####  ###### ##### 
  #    # #    # #    # #       # #  #      #      #    # 
  #    # #    # #    # #        #    ####  #####  #    # 
  #####  # ## # #    # #        #        # #      #####  
  #      ##  ## #    # #        #   #    # #      #   #  
  #      #    # #####  ######   #    ####  ###### #    # 

  ---- Password analysis & reporting tool -- v1.0.0 ----

------------------------------:    ------------------------------     :    ------------------------------
Username                      :    Password                           :    Description
------------------------------:    ------------------------------     :    ------------------------------
user1                         :    password1                          :    Variation of pass
                              :    testpass                           :    Variation of pass
```

### User As Pass

```
> pwdlyser -p sample-file -up

  #####  #    # #####  #      #   #  ####  ###### ##### 
  #    # #    # #    # #       # #  #      #      #    # 
  #    # #    # #    # #        #    ####  #####  #    # 
  #####  # ## # #    # #        #        # #      #####  
  #      ##  ## #    # #        #   #    # #      #   #  
  #      #    # #####  ######   #    ####  ###### #    # 

  ---- Password analysis & reporting tool -- v1.0.0 ----

------------------------------:    ------------------------------     :    ------------------------------
Username                      :    Password                           :    Description
------------------------------:    ------------------------------     :    ------------------------------
lenovo                        :    L3n0vo!                            :    Variation of lenovo
Bluecoat                      :    *blu3c0at$                         :    Variation of Bluecoat
system                        :    sy$t3m!                            :    Variation of system
```

### Common Passwords

```
> pwdlyser -p sample-file -c

  #####  #    # #####  #      #   #  ####  ###### ##### 
  #    # #    # #    # #       # #  #      #      #    # 
  #    # #    # #    # #        #    ####  #####  #    # 
  #####  # ## # #    # #        #        # #      #####  
  #      ##  ## #    # #        #   #    # #      #   #  
  #      #    # #####  ######   #    ####  ###### #    # 

  ---- Password analysis & reporting tool -- v1.0.0 ----

------------------------------:    ------------------------------     :    ------------------------------
Username                      :    Password                           :    Description
------------------------------:    ------------------------------     :    ------------------------------
user1                         :    password1                          :    Variation of password
user4                         :    l3tme1n_*                          :    Variation of letmein
```

### Frequency
```
> pwdlyser -p sample-file -f 3

  #####  #    # #####  #      #   #  ####  ###### ##### 
  #    # #    # #    # #       # #  #      #      #    # 
  #    # #    # #    # #        #    ####  #####  #    # 
  #####  # ## # #    # #        #        # #      #####  
  #      ##  ## #    # #        #   #    # #      #   #  
  #      #    # #####  ######   #    ####  ###### #    # 

  ---- Password analysis & reporting tool -- v1.0.0 ----

------------------------------:    ------------------------------          
Password                      :    Frequency                               
------------------------------:    ------------------------------          
password1                     :    3                                       
blu3c0at!                     :    1                                       
Friday924                     :    1                                       
```

### Report Format (-oR)
```
> pwdlyser -p sample-file -c -oR

  #####  #    # #####  #      #   #  ####  ###### ##### 
  #    # #    # #    # #       # #  #      #      #    # 
  #    # #    # #    # #        #    ####  #####  #    # 
  #####  # ## # #    # #        #        # #      #####  
  #      ##  ## #    # #        #   #    # #      #   #  
  #      #    # #####  ######   #    ####  ###### #    # 

  ---- Password analysis & reporting tool -- v1.0.0 ----


The following user accounts were found to have a password that was a variation 
of the most common user passwords, which can include 'password', 'letmein', 
'123456', 'admin', 'iloveyou', 'friday', or 'qwerty':
- user2 : P4****rd1
- user5 : Pa***ord
- user1 : Dec****r16
- user9 : zaq****23
```

### Summary Output (--summary)


> pwdlyser -p sample-file.txt --summary -o SAMPLE-ORG --admin admin-user-list.txt

A password audit was performed against the extracted password hashes from the specified system. Password cracking tools and methods were used to enumerate the plaintext password counterparts, and as such not all of the passwords were able to be identified. In total, there were 2448 username and password combinations that were obtained.

As part of the password audit, the top 10 most commonly used passwords within the organisation have been compiled. This list has been broken up with the password, the percentage of the total passwords, and the numeric value of the total passwords:
- Password01 : 31% | 481/2448
- Germany01 : 4% | 66/2448
- 123qwert!ZXC : 3% | 49/2448
- letm31n! : 2% | 38/2448
- Password2! : 2% | 35/2448
- starw4r$ : 0% | 22/2448
- Password2 : 1% | 14/2448
- W3lc0ome01 : 0% | 13/2448
- Bu773rfl1es : 0% | 12/2448
- letm31n234 : 0% | 10/2448

Alongside the list of the most common passwords used within the organisation, the top 10 most common password lengths were analysed and the results can be seen below in the format of the character length, along with the percentage of the total passwords for each password length:
- Length : 10 : 41%
- Length : 8 : 20%
- Length : 7 : 16%
- Length : 11 : 7%
- Length : 13 : 6%
- Length : 16 : 3%
- Length : 9 : 1%
- Length : 15 : 1%
- Length : 14 : 0%
- Length : 12 : 0%

One of the biggest threats to organisations in relation to the passwords used by users and administrators is the use of passwords that are exactly the same, or a variation of the more commonly used passwords. Overall, there were 603 passwords that were found to have a variation of one of these common words or phrases. Some of these passwords include 'password', 'qwerty', 'starwars', 'system', 'admin', 'letmein', and 'iloveyou'. Further details can be seen within the 'pwd_common.conf' file at https://www.github.com/ins1gn1a/pwdlyser.

As part of the wider password analysis, each password was assessed and compared to the commonly used keyboard patterns. These keyboard patterns are defined by the QWERTY layout, where a password is made up of characters in close proximity, such as qwer, zxcvbn, qazwsx, and so on. In total, there were 59 passwords in use that had at least one of these variations.

There were 10 passwords that were identified as having a password set that was a variation of the username; this includes additional prefixed or suffixed characters, substitutions within the word (i.e. 3 instead of e), or the username as it appears. Penetration testers, and more importantly attackers, will often check system or administrative accounts that have a variation of the username set as the password, and as such it is critical that organisations do not use this convention for password security.

The organisation name, or a variation of the name (such as an abbreviation) 'SAMPLE-ORG' was found to appear within 14 of the passwords that were able to be obtained during the password audit. For any system or administrative user accounts that have a variation of the company name as their password, it is highly recommended that the passwords are changed to prevent targeted guessing attacks.

Finally, there were 3 Domain administrative accounts (Domain Admins, Enterprise Admins, etc.) that were able to be compromised through password analysis. The account names and their respective passwords (masked) can be seen below:
- user.admin1 : Run****3!
- sys.admin : $!x***az1
- svc-wsus : a4a*****tYc
- user.admin2 : P4****rd2
- user2 : P4****rd!2

