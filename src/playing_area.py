import json
import selectors
import socket
from collections import defaultdict, namedtuple

from src.logger import get_logger
from src.protocol import Protocol
from src.utils.status import GameStatus

Player = namedtuple('Player', ['name', 'sock'])


class PlayingArea:

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen()
        self.sock.setblocking(False)
        self.sel.register(self.sock, selectors.EVENT_READ, self.accept)
        self.connections = defaultdict()
        self.logger = get_logger(__name__)
        self.caller = None
        self.players: list[Player] = []
        self.game_status: GameStatus = GameStatus.NOT_STARTED

    def accept(self, sock):
        conn, addr = sock.accept()
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def loop(self):
        while True:
            events = self.sel.select()
            for key, _ in events:
                callback = key.data
                callback(key.fileobj)

    def read(self, conn):
        data_size = int.from_bytes(conn.recv(4), 'big')
        if data_size != 0:
            data = conn.recv(data_size)
            data = data.decode('utf-8')
            data = json.loads(data)

            print(data)

            if data["type"] == "join_player":
                self.join_player(conn, data)
            elif data["type"] == "join_caller":
                self.join_caller(conn, data)
            elif data["type"] == "start_game":
                self.start_game()

    def join_player(self, conn, data):
        if self.game_status == GameStatus.NOT_STARTED:
            self.logger.info(f"New player from {data['name']}")
            self.players.append(Player(data["name"], conn))
            Protocol.join_response(conn, "ok")
        else:
            self.logger.info(f"Game already started")
            Protocol.join_response(conn, "error")

    def join_caller(self, conn: socket.socket, data: dict):
        if self.caller is None:
            self.logger.info(f"New caller from {data['name']}")
            self.caller = conn
            Protocol.join_caller_response(conn, "ok")
        else:
            self.logger.info(f"Caller already exists")
            Protocol.join_caller_response(conn, "error")

    def start_game(self):
        self.game_status = GameStatus.STARTED

        for player in self.players:
            Protocol.start_game(player.sock)
