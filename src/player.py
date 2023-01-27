import fcntl
import json
import os
import selectors
import socket
import sys

from src.protocol import Protocol
from src.utils.AES import AES
from src.utils.Game import Game
from src.utils.RSA import RSA
from src.utils.logger import get_logger
from src.utils.types import Keys, PlayerTuple


class Player:
    def __init__(self, host, port, name):
        self.id = None
        self.host = host
        self.port = port
        self.name = name
        # Start Player's Socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.sock, selectors.EVENT_READ, self.read)
        self.logger = get_logger(__name__)
        self.deck_size = -1
        orig_fl = fcntl.fcntl(sys.stdin, fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin, fcntl.F_SETFL, orig_fl | os.O_NONBLOCK)
        self.sel.register(sys.stdin, selectors.EVENT_READ, self.keyboard_input)
        self.private_key, self.public_key = RSA.generate_key_pair()
        self.players: list[PlayerTuple] = []
        self.playing_area_public_key = None

        try:
            self.sock.connect((self.host, self.port))
            # Ask server to join
            Protocol.join_request(self.sock, self.private_key, self.name)
        except ConnectionRefusedError:
            print('Connection refused')
            self.close()

        # Personal keys
        self.keys = Keys(*RSA.generate_key_pair(), AES.generate_key())

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
            elif data["type"] == "login_response":
                self.handle_login_response(data)
            elif data["type"] == "validate_cards":
                self.validate_cards(conn, data)
            elif data["type"] == "shuffle":
                self.shuffle(conn, data)
            elif data["type"] == "validate_decks":
                self.validate_decks(conn, data)
            elif data["type"] == "playing_area_closing":
                self.logger.info(f"Playing area closed")
                self.close()
            elif data["type"] == "choose_winner":
                self.choose_winner(conn, data)
            elif data["type"] == "announce_winner":
                self.logger.info(f"Winner: {data['winner']}")

            elif data["type"] == "players_list":
                self.get_players(data["players"])
            elif data["type"] == "winner_decision_failed":
                self.logger.info(f"Winner decision failed")
                self.close()
            else:
                self.logger.info(f"Unknown message type: {data['type']}")

        else:
            self.logger.info("Server disconnected")
            self.close()

    def keyboard_input(self, stdin):
        input_msg = stdin.read()

        if input_msg.startswith("/log"):
            self.logger.info(f"I want the log!")
        elif input_msg.startswith("/players"):
            self.print_players()
        else:
            print("Invalid command")

    def join(self, data):
        if data["status"] == "ok":
            self.logger.info(f"Joined as player")
            self.id = data["id"]
            self.playing_area_public_key = data["playing_area_public_key"]
            Protocol.publish_data(self.sock, self.private_key, self.id, self.public_key)
        else:
            self.logger.info(f"Failed to join")
            self.close()

    def generate_card(self, conn, data):
        self.logger.info(f"Game started")
        self.deck_size = data["size"]
        card = Game.generate_card(self.deck_size)
        self.logger.info(f"Generated card: {card}")
        Protocol.send_card(conn, self.private_key, card)

    def shuffle(self, conn, data):
        self.logger.info(f"Shuffling deck")
        shuffled_deck = Game.shufle_deck(data["deck"])
        Protocol.shuffle_response(conn, self.private_key, shuffled_deck, self.id)

    def validate_cards(self, conn, data):
        for card in data["cards"]:
            self.logger.info(f"Validating {card}'s card")
            if not Game.validate_card(self.deck_size, card):
                self.logger.info(f"Invalid card")
                Protocol.validate_cards_error(self.sock, self.private_key, "Invalid Card", card)
        else:
            self.logger.info(f"Valid cards")
            Protocol.validate_cards_success(conn, self.private_key, data["cards"])

    def validate_decks(self, conn, data):
        # TODO: Validate decks
        self.logger.info(f"Validating decks")
        Protocol.validate_decks_success(conn, self.private_key, data["decks"])

    def choose_winner(self, conn, data):
        self.logger.info(f"Choosing winner")
        winner = Game.winner(data["deck"], data["cards"])
        self.logger.info(f"I decided that the winner is {winner}")
        Protocol.choose_winner_response(conn, self.private_key, winner)

    def handle_login_response(self, data):
        if data["status"] == "ok":
            self.logger.info(f"Logged in")
        else:
            self.logger.info(f"Failed to log in")
            self.close()

    def print_players(self):
        print("Players:")
        for player in self.players:
            print(f"SEQ: {player.seq}, Nick: {player.nick}")

    def get_players(self, players):
        for player in players:
            self.players.append(PlayerTuple(*player))
