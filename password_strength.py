import re
import argparse


def get_parser_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=('''
            -This program shows the strength of the password-

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


def get_password_strength(password, blacklist, users_info):
    pass_evaluation = {
        'rating': 1,
        'detail': 'password is not in the black list or '
        'user\'s personal information list'
    }
    if re.match(
        r'[A-Za-z](?:[A-Za-z\d~!@#$%^&*_+=`|\\()}{[\]:;"\'<>,.?/-]){3,}',
        password,
    ):
        positive_regex_list = [
            r'[.\S]{8,}',
            r'\d',
            r'.*\d+.*\d+.*',
            r'[A-Z]',
            r'.*[A-Z]+.*[A-Z]+.*',
            r'[a-z]',
            r'.*[a-z]+.*[a-z]+.*',
            r'[~!@#$%^&*_+=`|\\()}{[\]:;"\'<>,.?/-]',
            r'.*[~!@#$%^&*_+=`|\\()}{[\]:;"\'<>,.?/-]+'
            r'.*[~!@#$%^&*_+=`|\\()}{[\]:;"\'<>,.?/-]+.*',
        ]
        negative_regex_list = [
            r'\d\d\W\d\d\W\d{4}',
            r'[ABEKMHOPCTYX]\d{3}[ABEKMHOPCTYX]{2}(\d{2,3})?',
        ]

        for regex in positive_regex_list:
            if re.search(regex, password):
                pass_evaluation['rating'] += 1

        for regex in negative_regex_list:
            if re.search(regex, password, re.I):
                pass_evaluation['rating'] -= 2

        if blacklist:
            pass_evaluation = check_matches_in_file(
                blacklist,
                password,
                pass_evaluation,
            )
        if users_info:
            pass_evaluation = check_matches_in_file(
                users_info,
                password,
                pass_evaluation,
            )
        if pass_evaluation['rating'] < 0:
            pass_evaluation['rating'] = 1
        return pass_evaluation
    else:
        pass_evaluation['detail'] = (
            'error: the password contains unsupported characters '
            'or it\'s to short\n'
            'for more details run this with -h key'
        )
        return pass_evaluation


def check_matches_in_file(file_to_check, password, pass_evaluation):
    with open(file_to_check, 'r') as file_to_check:
        for pattern in file_to_check.read().split():
            if re.search(pattern, password):
                pass_evaluation['rating'] -= 5
                pass_evaluation['detail'] = (
                    'warning: password or part of it '
                    'was found in the <%s>!' % file_to_check.name
                )
    return pass_evaluation

if __name__ == '__main__':
    try:
        args = get_parser_args()
        password = str(input('Enter your password: '))
        pass_evaluation = get_password_strength(
            password,
            args.blacklist,
            args.users_info,
        )
        print(
            '\nevalation of password %s\n' % password,
            'rating is %s' % pass_evaluation['rating'],
            pass_evaluation['detail'],
            sep='\n',
            end='\n\n',
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
