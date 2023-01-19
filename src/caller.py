import fcntl
import json
import os
import selectors
import socket
import sys

from src.utils.logger import get_logger
from src.protocol import Protocol
from src.utils.Game import Game

DEFAULT_SIZE = 100


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
                self.join(data)
            elif data["type"] == "validate_cards":
                self.validate_cards(conn, data)
            elif data["type"] == "generate_deck_request":
                self.generate_deck()
            elif data["type"] == "playing_area_closing":
                self.close()

            elif data["type"] == "validate_decks":
                self.validate_decks(conn, data)
            elif data["type"] == "choose_winner":
                self.choose_winner(conn, data)
            elif data["type"] == "announce_winner":
                self.logger.info(f"Winner: {data['winner']}")
            elif data["type"] == "winner_decision_failed":
                self.logger.info(f"Winner decision failed")
                self.close()
            else:
                self.logger.info(f"Unknown message type: {data['type']}")
        else:
            self.logger.info(f"Server closed connection")
            self.close()

    def join(self, data):
        if data["status"] == "ok":
            self.logger.info(f"Joined as caller")
        else:
            self.logger.info(f"A caller already exists")
            self.close()

    def validate_cards(self, conn, data):
        for card in data["cards"]:
            self.logger.info(f"Validating {card}'s card")
            if not Game.validate_card(DEFAULT_SIZE, card):
                self.logger.info(f"Invalid card")
                Protocol.validate_cards_error(self.sock, "Invalid Card", card)
        else:
            self.logger.info(f"Valid cards")
            Protocol.validate_cards_success(conn, data["cards"])

    def keyboard_input(self, stdin):
        input_msg = stdin.read()

        if input_msg.startswith("/start"):
            Protocol.start_game(self.sock, DEFAULT_SIZE)

        elif input_msg.startswith("/end"):
            Protocol.close_game(self.sock)
        else:
            print("Invalid command")

    def generate_deck(self):
        self.logger.info(f"Generating deck")
        deck = Game.generate_deck(DEFAULT_SIZE)
        Protocol.generate_deck_response(self.sock, deck)

    def validate_decks(self, conn, data):
        # TODO: Validate decks
        self.logger.info(f"Validating decks")
        Protocol.validate_decks_success(conn, data["decks"])

    def choose_winner(self, conn, data):
        self.logger.info(f"Choose winner")
        winner = Game.winner(data["deck"], data["cards"])
        self.logger.info(f"I decided that the winner is {winner}")
        Protocol.choose_winner_response(conn, winner)
