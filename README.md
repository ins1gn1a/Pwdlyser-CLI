# Intro
The pwdlyser tool is a Python-based CLI script that was intended to be used to somewhat automate the arduous process of manually reviewing cracked passwords during password audits or for penetration testing. It is by no-means a perfect tool and is an accompaniment to actual manual testing (i.e. there are likely some false positives/negatives and I don't want to be held responsible). Use at your own discretion, blah blah etc.

## Input: Passwords
I originally did intend for either ```passwords```, ```username:passwords```, and ```username:hash:passwords``` to be processed but to be honest for what I use it for I would only really ever use username:password (":") delimited lists so that's what I focused on, although I think there are remnants of code should anyone want to modify it back to the original intentions.

Lists can be specified using the ```-p [path/to/file]``` argument, and should be colon delimited with username followed by password. No headers are necessary.

Should you only want to analyse passwords, just enter a colon (":") before each password in the list, which will just output blank usernames.

## Usage
There are a range of input arguments that can be used, but for a simple 'common password' search through a list use the ```-c``` argument to initiate the check. This will import the default pwd_common.conf file and use it as a basis to compare against the password list. Passwords and the common passwords are both converted to lower-case, with the inputted passwords also being 'de-leeted' and converted back to alpha characters (i.e. 3 to e). The reason for this, even though some passwords may end up reading 'iadmin' instead of '!admin' is that this is only a basic comparison, but it seems to work well.

Other arguments also include the check for any users that have their username as part of their password. This can be run using the ```-up``` or ```--user-as-pass``` arugments.

To display any passwords that have a minimum length less than 9 characters use ```-l 9```. The int can be changed to whatever the password policy is, although you should also really ensure that you verify against best-practice too.

Basic ('de-leeted') searches can be run using ```-s [word]```, however an exact search can be run using ```-e [word]``` or ```--exact [word]```. The exact search does not modify any characters for comparison and thus allows you to check for any passwords containing '123' or 'P4$$'. 

Organisation names often appear within passwords, at least from my experience during internal penetration tests. To check for this, a similar search to the 'basic' search is run, although the only difference is that the 'Description' will state 'Organisation name: [name]' on screen instead. Run this using ```-o [orgname or acronym]```.

If you want to verify whether you were able to crack the passwords for any admin accounts then you can put the usernames (only) in a file and use ```--admin [path/to/file]``` to display any of the admin passwords that could be cracked. This is of course useful for any escalation or pivoting that you may need to do - I'm sure you could find some use for this.

To just search for a user that may be in the list use ```-u [username/part of username]```. This list also works with email:passwords, it doesn't discriminate.

To just identify the top [num] of passwords, i.e. frequency analysis, use the ```-f [int]``` argument and specify the top number of passwords you want to return within the int.

Other options can be seen within the ```-h``` menu or below:

```
usage: pwdlyser.py [-h] -p PASS_LIST [-a ADMIN_LIST] [-o ORG_NAME]
                   [-l MIN_LENGTH] [-A] [-s BASIC_SEARCH] [-oR] [-c]
                   [-f FREQ_ANAL] [--exact EXACT_SEARCH] [-u USER_SEARCH]
                   [--admin ADMIN_PATH]

Password Analyser

optional arguments:
  -h, --help            show this help message and exit
  -p PASS_LIST, --pass-list PASS_LIST
                        Enter the path to the list of passwords, either in the
                        format of passwords, or username:password.
  -a ADMIN_LIST, --admin-list ADMIN_LIST
                        Enter the path to the list of admin accounts that will
                        be highlighted if they are seen within the password
                        list
  -o ORG_NAME, --org-name ORG_NAME
                        Enter the organisation name to identify any users that
                        will be using a variation of the word for their
                        password. Note: False Positives are possible
  -l MIN_LENGTH, --length MIN_LENGTH
                        Display passwords that do not meet the minimum length
  -A, --all             Print only usernames
  -s BASIC_SEARCH, --search BASIC_SEARCH
                        Run a basic search using a keyword. Non-alpha
                        characters will be stripped, i.e. syst3m will become
                        systm (although this will be compared against the same
                        stripped passwords
  -oR                   Output format set for reporting with "- " prefix
  -c, --common          Check against list of common passwords
  -f FREQ_ANAL, --freq FREQ_ANAL
                        Perform frequency analysis
  --exact EXACT_SEARCH  Perform a search using the exact string.
  -u USER_SEARCH, --user USER_SEARCH
                        Return usernames that match string (case insensitive)
  --admin ADMIN_PATH    Import line separated list of Admin usernames to check
                        password list
```

## Example Outputs

### Basic Search
```
> ./pwdlyser.py -p /mnt/hgfs/shared/user -s pass

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
> ./pwdlyser.py -p /mnt/hgfs/shared/user -up

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
lenovo                        :    L3n0vo!                            :    Variation of surecloud
bluecoat                      :    *blu3c0at$                         :    Variation of bluecoat

```

### Common Passwords

```
> ./pwdlyser.py -p /mnt/hgfs/shared/user -c

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
> ./pwdlyser.py -p /mnt/hgfs/shared/user -f 3

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
