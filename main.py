import requests
import hashlib
import sys


def request(query_character):
    url2 = 'https://api.pwnedpasswords.com/range/' + query_character
    rep = requests.get(url2)
    if rep.status_code != 200:
        raise RuntimeError(f'Error fetching {rep.status_code}, please try again')
    return rep


def get_password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for hashed, count in hashes:
        if hashed == hash_to_check:
            return count
    return 0



def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'Your {password} was found {count} times....you should change your password')
        else:
            print(f'Your {password} is safe')
    return 'done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
