import json
import selectors
import socket

from src.utils.logger import get_logger
from src.protocol import Protocol
from src.utils.Game import Game


class Player:
    def __init__(self, host, port, name):
        self.id = None
        self.host = host
        self.port = port
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.sock, selectors.EVENT_READ, self.read)
        self.logger = get_logger(__name__)
        self.deck_size = -1

        try:
            self.sock.connect((self.host, self.port))
            # Ask server to join
            Protocol.join_request(self.sock, self.name)
        except ConnectionRefusedError:
            print('Connection refused')
            self.close()

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

            if data["type"] == "join_response":
                self.join(data)
            elif data["type"] == "start_game":
                self.generate_card(conn, data)
            elif data["type"] == "validate_cards":
                self.validate_cards(conn, data)
            elif data["type"] == "shuffle":
                self.shuffle(conn, data)

        else:
            self.logger.info("Server disconnected")
            self.close()

    def join(self, data):
        if data["status"] == "ok":
            self.logger.info(f"Joined as player")
            self.id = data["id"]
        else:
            self.logger.info(f"Failed to join")
            self.close()

    def generate_card(self, conn, data):
        self.logger.info(f"Game started")
        self.deck_size = data["size"]
        card = Game.generate_card(self.deck_size)
        self.logger.info(f"Generated card: {card}")
        Protocol.send_card(conn, card)

    def shuffle(self, conn, data):
        self.logger.info(f"Shuffling deck")
        shuffled_deck = Game.shufle_deck(data["deck"])
        Protocol.shuffle_response(conn, shuffled_deck, self.id)

    def validate_cards(self, conn, data):
        self.logger.info(f"Validating cards")
        for card in data["cards"]:
            self.logger.info(f"Validating {card}'s card")
            if not Game.validate_card(self.deck_size, card):
                self.logger.info(f"Invalid card")
                Protocol.validate_cards_error(self.sock, "Invalid Card", card)
        else:
            self.logger.info(f"Valid cards")
            Protocol.validate_cards_success(conn, data["cards"])
