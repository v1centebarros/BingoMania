import json
import selectors
import socket
from collections import namedtuple, defaultdict

from src.utils.logger import get_logger
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
        self.logger = get_logger(__name__)
        self.caller = None
        self.players: list[Player] = []
        self.validated_cards = defaultdict(list)
        self.game_status: GameStatus = GameStatus.NOT_STARTED
        self.cards = {}
        self.decks = []
        self.logger.info(f"Playing Area started")

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

            if data["type"] == "join_player":
                self.join_player(conn, data)
            elif data["type"] == "join_caller":
                self.join_caller(conn, data)
            elif data["type"] == "start_game":
                self.start_game(data)
            elif data["type"] == "card":
                self.receive_card(conn, data)
            elif data["type"] == "validate_cards_success":
                self.cards_validated(conn, data)
            elif data["type"] == "validate_cards_error":
                self.logger.info(f"Cards not validated")
            elif data["type"] == "generate_deck_response":
                self.decks.append((conn, data["deck"]))
                Protocol.shuffle_request(self.players[0].sock, data["deck"])
            elif data["type"] == "shuffle_response":
                self.handle_shuffle_response(conn, data)
        else:
            self.handle_disconnect(conn)

    def handle_disconnect(self, conn):
        self.sel.unregister(conn)
        if self.caller == conn:
            self.logger.info(f"Caller disconnected")
            self.caller = None
        else:
            self.logger.info(f"Player disconnected")
            self.players = [player for player in self.players if player.sock != conn]
        conn.close()

    def join_player(self, conn, data):
        if self.game_status == GameStatus.NOT_STARTED:
            self.logger.info(f"New player from {data['name']}")
            self.players.append(Player(data["name"], conn))
            Protocol.join_response(conn, "ok", len(self.players))
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

    def start_game(self, data):
        self.game_status = GameStatus.STARTED

        for player in self.players:
            Protocol.start_game(player.sock, data["size"])

    # TODO: Create decorator to check if caller is connected
    def receive_card(self, conn, data):
        for player in self.players:
            if player.sock == conn and player.name not in self.cards.keys():
                self.logger.info(f"Received card from {player.name}")
                self.cards[player.name] = data["card"]
        else:
            if len(self.cards) == len(self.players):
                self.logger.info(f"All cards received")
                self.request_cards_validation()

    def request_cards_validation(self):
        Protocol.validate_cards(self.caller, self.cards)
        for player in self.players:
            Protocol.validate_cards(player.sock, self.cards)

    def cards_validated(self, conn, data):
        self.validated_cards[conn] = data["cards"]

        if len(self.validated_cards) == len(self.players) + 1:
            self.logger.info(f"All cards validated")
            Protocol.generate_deck_request(self.caller)

    def handle_shuffle_response(self, conn, data):
        self.decks.append((conn, data["deck"]))
        if len(self.decks) == len(self.players) + 1:
            self.logger.info(f"All decks shuffled")
        else:
            Protocol.shuffle_request(self.players[data["id"]].sock, data["deck"])
