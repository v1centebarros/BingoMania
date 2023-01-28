import fcntl
import json
import os
import selectors
import socket
import sys
from base64 import b64encode, b64decode
import random

from src.protocol import Protocol, InvalidSignatureException
from src.utils.AES import AES
from src.utils.Game import Game
from src.utils.RSA import RSA
from src.utils.logger import get_logger
from src.utils.types import Keys, PlayerTuple


class Player:
    def __init__(self, host, port, name, rsa_cheat, aes_cheat, winner_cheat, deck_cheat, card_cheat):
        self.seq = None
        self.host = host
        self.port = port
        self.name = name
        self.rsa_cheat = rsa_cheat
        self.aes_cheat = aes_cheat
        self.winner_cheat = winner_cheat
        self.deck_cheat = deck_cheat
        self.card_cheat = card_cheat
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
        self.symmetric_key = AES.generate_key()
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
            elif data["type"] == "choose_winner":
                self.choose_winner(conn, data)
            elif data["type"] == "announce_winner":
                self.logger.info(f"Winner: {data['winner']}")
            elif data["type"] == "players_list":
                self.get_players(conn, data)
            elif data["type"] == "share_key":
                self.share_key(data)
            elif data["type"] == "winner_decision_failed":
                self.logger.info(f"Winner decision failed")
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
            self.seq = data["id"]
            self.playing_area_public_key = data["playing_area_public_key"]
            Protocol.publish_data(self.sock, self.private_key, self.seq, self.public_key)
        else:
            self.logger.info(f"Failed to join")
            self.close()

    def generate_card(self, conn, data):
        self.check_signature(data)
        self.logger.info(f"Game started")
        self.deck_size = data["size"]

        if random.randint(1, 100) > self.card_cheat:
            card = Game.generate_card(self.deck_size)
        else:
            self.logger.info(f"CHEATING Card generation")
            card = Game.generate_card(random.randint(0, 1000))
        self.logger.info(f"Generated card: {card}")
        Protocol.send_card(conn, self.randomize_private_key(), card)

    def shuffle(self, conn, data):
        self.logger.info(f"Shuffling deck")
        self.check_signature(data)
        shuffled_deck = Game.shufle_deck([b64decode(number) for number in data["deck"]])
        shuffled_deck = AES.encrypt_list(self.randomize_symmetric_key(), shuffled_deck)
        Protocol.shuffle_response(conn, self.randomize_private_key(), [b64encode(number).decode() for number in shuffled_deck],
                                  self.seq)

    def validate_cards(self, conn, data):
        self.check_signature(data)
        for player, card in data["cards"].items():
            self.logger.info(f"Validating {player}'s card")
            print("CARD SIZE: ", self.deck_size)
            if Game.failed_card_validation(self.deck_size, card):
                self.logger.info(f"Invalid card")
                Protocol.validate_cards_error(self.sock, self.private_key, "Invalid Card", card)
                break
        else:
            self.logger.info(f"Valid cards")
            Protocol.validate_cards_success(conn, self.randomize_private_key(), data["cards"])

    def validate_decks(self, conn, data):
        self.check_signature(data)
        self.logger.info(f"Validating decks")
        deserialized_symmetric_keys = [b64decode(key) for seq, key in data["symmetric_keys"]]
        deserialized_decks = [[b64decode(number) for number in deck] for seq, deck in data["decks"]]

        for i in range(len(deserialized_decks) - 1, 0, -1):
            next_deck = AES.decrypt_list(deserialized_symmetric_keys[i], deserialized_decks[i])
            if set(next_deck).difference(set(deserialized_decks[i - 1])):
                self.logger.info(f"Invalid deck")
                Protocol.validate_decks_error(conn, self.randomize_private_key(), "Invalid Deck", self.name)
                break
        else:
            self.logger.info(f"All decks are valid")
            self.logger.info(f"Generating final deck")
            final_deck = deserialized_decks[-1]
            for symmetric_key in reversed(deserialized_symmetric_keys):
                final_deck = AES.decrypt_list(symmetric_key, final_deck)
            Protocol.validate_decks_success(conn, self.randomize_private_key(), AES.lst_bytes_to_int(final_deck))

    def choose_winner(self, conn, data):
        self.check_signature(data)
        self.logger.info(f"Choosing winner")
        if random.randint(1, 100) > self.winner_cheat:
            winner = Game.winner(data["deck"], data["cards"])
        else:
            self.logger.info(f"CHEATING Winner Choice")
            # winner = random.choice(list(data["cards"].keys()))
            winner = self.name
        self.logger.info(f"I decided that the winner is {winner}")
        Protocol.choose_winner_response(conn, self.randomize_private_key(), winner)

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

    def get_players(self, conn, data):
        self.check_signature(data)
        self.players = []
        for player in data["players"]:
            self.players.append(PlayerTuple(*player))

    def check_signature(self, data):
        try:
            signature = data.pop("signature")
            if not RSA.verify_signature(self.playing_area_public_key, signature, json.dumps(data).encode('utf-8')):
                self.logger.info(f"Invalid signature")
                raise InvalidSignatureException()
            else:
                self.logger.info(f"Valid signature")
        except InvalidSignatureException:
            Protocol.invalid_signature(self.sock, self.private_key, self.seq)

    def share_key(self, data):
        self.check_signature(data)
        self.logger.info(f"Sharing key")
        Protocol.share_key_response(self.sock, self.randomize_private_key(), b64encode(self.symmetric_key).decode(), self.seq)

    def randomize_private_key(self):
        if random.randint(1, 100) > self.rsa_cheat:
            return self.private_key
        else:
            self.logger.info(f"CHEATING: Using random private key")
            return RSA.generate_key_pair()[0]

    def randomize_symmetric_key(self):
        if random.randint(1, 100) > self.aes_cheat:
            return self.symmetric_key
        else:
            self.logger.info(f"CHEATING: Using random symmetric key")
            return AES.generate_key()
