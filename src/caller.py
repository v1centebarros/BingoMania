import fcntl
import json
import os
import selectors
import socket
import sys
from pprint import pprint

from src.utils.RSA import RSA
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
        self.private_key, self.public_key = RSA.generate_key_pair()
        self.playing_area_public_key = None

        try:
            self.sock.connect((self.host, self.port))
            # Ask server to join
            Protocol.join_caller_request(self.sock, self.private_key, self.name)
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
            elif data["type"] == "sign_player_data":
                self.sign_player_data(conn, data)
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
            self.playing_area_public_key = data["playing_area_public_key"]
            if data["players_not_validated"]:
                for player in data["players_not_validated"]:
                    self.logger.info(f"Player {player} not Signed")
                    # TODO: Sign player data

        else:
            self.logger.info(f"A caller already exists")
            self.close()

    def validate_cards(self, conn, data):
        for card in data["cards"]:
            self.logger.info(f"Validating {card}'s card")
            if not Game.validate_card(DEFAULT_SIZE, card):
                self.logger.info(f"Invalid card")
                Protocol.validate_cards_error(self.sock, self.private_key, "Invalid Card", card)
        else:
            self.logger.info(f"Valid cards")
            Protocol.validate_cards_success(conn, self.private_key, data["cards"])

    def keyboard_input(self, stdin):
        input_msg = stdin.read()

        if input_msg.startswith("/start"):
            Protocol.start_game(self.sock, self.private_key, DEFAULT_SIZE)

        elif input_msg.startswith("/end"):
            Protocol.close_game(self.sock, self.private_key)
        else:
            print("Invalid command")

    def generate_deck(self):
        self.logger.info(f"Generating deck")
        deck = Game.generate_deck(DEFAULT_SIZE)
        Protocol.generate_deck_response(self.sock, self.private_key, deck)

    def validate_decks(self, conn, data):
        # TODO: Validate decks
        self.logger.info(f"Validating decks")
        Protocol.validate_decks_success(conn, self.private_key, data["decks"])

    def choose_winner(self, conn, data):
        self.logger.info(f"Choose winner")
        winner = Game.winner(data["deck"], data["cards"])
        self.logger.info(f"I decided that the winner is {winner}")
        Protocol.choose_winner_response(conn, self.private_key, winner)

    def sign_player_data(self, conn, data):
        pprint(data)
        if self.check_signature(data):
            self.logger.info(f"Message correctly signed")
        else:
            self.logger.info(f"Message not correctly signed")
        self.logger.info(f"Signing player data")
        signed_player_data = RSA.sign(self.private_key, data["player"])
        Protocol.sign_player_data_response(conn, self.private_key, signed_player_data, data["player"])

    def check_signature(self, data):
        signature = data.pop("signature")
        return RSA.verify_signature(self.playing_area_public_key, signature, json.dumps(data).encode('utf-8'))
