import fcntl
import json
import os
import selectors
import socket
import sys

from src.logger import get_logger
from src.protocol import Protocol


class Caller:

    def __init__(self, host, port, name):
        self.host = host
        self.port = port
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.sock, selectors.EVENT_READ, self.read)
        self.logger = get_logger(__name__)

        try:
            self.sock.connect((self.host, self.port))
            # Ask server to join
            Protocol.join_caller_request(self.sock, self.name)
        except ConnectionRefusedError:
            print('Connection refused')
            self.close()

        orig_fl = fcntl.fcntl(sys.stdin, fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin, fcntl.F_SETFL, orig_fl | os.O_NONBLOCK)
        self.sel.register(sys.stdin, selectors.EVENT_READ, self.keyboard_input)

    def loop(self):
        while True:
            events = self.sel.select()
            for key, _ in events:
                callback = key.data
                callback(key.fileobj)

    def close(self):
        self.logger.info("Closing connection")
        self.sel.close()
        self.sock.close()
        exit()

    def read(self, conn):
        data_size = int.from_bytes(conn.recv(4), 'big')
        if data_size != 0:
            data = conn.recv(data_size)
            data = data.decode('utf-8')
            data = json.loads(data)

            if data["type"] == "join_caller_response":
                if data["status"] == "ok":
                    self.logger.info(f"Joined as caller")
                else:
                    self.logger.info(f"A caller already exists")
                    self.close()

    def keyboard_input(self, stdin):
        input_msg = stdin.read()

        if input_msg.startswith("/start"):
            Protocol.start_game(self.sock)
        else:
            print("Invalid command")
