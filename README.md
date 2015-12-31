# pwdlyser
Python-based CLI Password Analyser (Reporting Tool)

# Usage

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
