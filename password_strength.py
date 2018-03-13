import re
import argparse


def get_parser_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=('''
            -This program shows the strength of the password from 1 to 10-

            Requierments:

            1. Password length is at least 4 characters
            2. Valid characters for use in the password:
              - Uppercase and lowercase characters of latin alphabet (A-Z, a-z)
              - Base 10 digits (0 through 9)
              - Non-alphanumeric characters (special characters):
                (~!@#$%^&*_+=`|\()}{[\]:;"'<>,.?/-)
        ''')
    )
    parser.add_argument(
        '-b',
        '--blacklist',
        help='path to password blacklist file',
        default=None,
        metavar='file/path/.*',
    )
    parser.add_argument(
        '-u',
        '--users_info',
        help='path to user\'s information file',
        default=None,
        metavar='file/path/.*',
    )
    return parser.parse_args()


def check_pass_allow(password):
    if re.match(
        r'^[A-Za-z](?:[A-Za-z\d~!@#$%^&*_+=`|\\()}{[\]:;\"\'<>,.?/-]){3,}$',
        password,
    ):
        return True
    else:
        return False


def get_regex_list(flag):
    if flag == 'positive':
        return [
            r'[.\S]{8,}',
            r'\d',
            r'.*\d+.*\d+.*',
            r'[A-Z]',
            r'.*[A-Z]+.*[A-Z]+.*',
            r'[a-z]',
            r'.*[a-z]+.*[a-z]+.*',
            r'[~!@#$%^&*_+=`|\\()}{[\]:;\"\'<>,.?/-]',
            r'.*[~!@#$%^&*_+=`|\\()}{[\]:;\"\'<>,.?/-]+'
            r'.*[~!@#$%^&*_+=`|\\()}{[\]:;\"\'<>,.?/-]+.*',
        ]
    elif flag == 'negative':
        return [
            r'\d\d\W\d\d\W\d{4}',
            r'[ABEKMHOPCTYX]\d{3}[ABEKMHOPCTYX]{2}(\d{2,3})?',
        ]


def print_password_strength(password_strength):
    if password_strength['rating'] < 0:
        password_strength['rating'] = 1
    print(
        '\nstrength of password %s\n' % password,
        'rating is %s' % password_strength['rating'],
        password_strength['detail'],
        sep='\n',
        end='\n\n',
    )


def get_password_strength(password, blacklist, users_info):
    password_strength = {
        'rating': 1,
        'detail': 'password is not in the black list or '
        'user\'s personal information list'
    }
    for regex in get_regex_list('positive'):
        if re.search(regex, password):
            password_strength['rating'] += 1
    for regex in get_regex_list('negative'):
        if re.search(regex, password, re.I):
            password_strength['rating'] -= 2
    password_strength = check_matches_in_file(
        blacklist,
        password,
        password_strength,
    )
    password_strength = check_matches_in_file(
        users_info,
        password,
        password_strength,
    )
    return password_strength


def check_matches_in_file(file_to_check, password, password_strength):
    if file_to_check:
        text_file = open(file_to_check, 'r')
        for pattern in text_file.read().split():
            if re.search(pattern, password):
                password_strength['rating'] -= 5
                password_strength['detail'] = 'warning: password or '\
                    'part of it was found in the <%s>!' % text_file.name
        text_file.close()
        return password_strength
    else:
        return password_strength


if __name__ == '__main__':
    try:
        args = get_parser_args()
        password = input('Enter your password: ')
        if check_pass_allow(password):
            password_strength = get_password_strength(
                password,
                args.blacklist,
                args.users_info,
            )
            print_password_strength(password_strength)
        else:
            print(
                '\nerror: the password contains unsupported characters '
                'or it\'s to short\n'
                'for more details run this with -h key\n'
            )
    except (ValueError, UnicodeDecodeError, TypeError):
        print(
            '\nerror:\tthere is no text in the file '
            '\nspecify the text data file\n'
        )
    except FileNotFoundError:
        print(
            '\nerror:\tfile is not found\ntry:\t$ python password_strength.py '
            '[-b path/to/text/file/*.*] [-u path/to/text/file/*.*] password\n'
        )
