import argparse
import socket

class PasswordHacker:
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

    def send_msg(self, msg):
        with socket.socket() as hacking_socket:
            hacking_socket.connect((self.ip_address, self.port))
            hacking_socket.send(msg.encode())
            return hacking_socket.recv(32768).decode()

def main():
    parser = argparse.ArgumentParser(description='Process IP address, port, message for sending.')
    parser.add_argument('ip_address', metavar='IP', help='IP address for connection.')
    parser.add_argument('port', type=int, help='Port to connect.')
    parser.add_argument('msg', help='Message for sending.')
    args = parser.parse_args()

    password_hacker = PasswordHacker(args.ip_address, args.port)
    print(password_hacker.send_msg(args.msg))

if __name__ == '__main__':
    main()
