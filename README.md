# Password Strength Calculator

This program calculates and then shows the strength of the password from 1 to 10

The calculation is based on my own simple algorithm.

# How to use

You can run this program with optional parameters:

 `-b, --blacklist` - your black list of passwords

 `-u, --users_info` - your personal user's information

 `-h, --help` - use it for more details

```bash
$ python get_password_strength.py [-h] [-b, --blacklist] [-u, --users_info] path/to/text/file/*.*
# possibly requires call of python3 executive instead of just python
```

### Example

```bash
$ python password_strength.py -b blacklist.txt -u userlist.txt
Enter your password: fUr<2!fi

evalation of password fUr<2!fi

rating is 8
password is not in the black list or users personal information list

```

# Project Goals

The code is written for educational purposes. Training course for web-developers - [DEVMAN.org](https://devman.org)
