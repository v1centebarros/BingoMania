import fcntl
import json
import os
import random
import selectors
import socket
import sys
from base64 import b64encode, b64decode

from src.protocol import Protocol, InvalidSignatureException
from src.utils.AES import AES
from src.utils.Game import Game
from src.utils.RSA import RSA
from src.utils.logger import get_logger

DEFAULT_SIZE = 100


class Caller:

    def __init__(self, host, port, name, rsa_cheat, aes_cheat, winner_cheat):
        self.host = host
        self.port = port
        self.name = name
        self.rsa_cheat = rsa_cheat
        self.aes_cheat = aes_cheat
        self.winner_cheat = winner_cheat
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.sock, selectors.EVENT_READ, self.read)
        self.logger = get_logger(__name__)
        self.private_key, self.public_key = RSA.generate_key_pair()
        self.playing_area_public_key = None
        self.symmetric_key = AES.generate_key()

        try:
            self.sock.connect((self.host, self.port))
            # Ask server to join
            Protocol.join_caller_request(self.sock, self.private_key, self.name, self.public_key)
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
                self.logger.info(f"Playing area closed")
            elif data["type"] == "share_key":
                self.share_key(conn, data)

            elif data["type"] == "validate_decks":
                self.validate_decks(conn, data)
            elif data["type"] == "choose_winner":
                self.choose_winner(conn, data)
            elif data["type"] == "announce_winner":
                self.logger.info(f"Winner: {data['winner']}")
            elif data["type"] == "winner_decision_failed":
                self.logger.info(f"Winner decision failed")
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
                    self.logger.info(f"Player {player[2]} not Signed")
                    self.sign_player_data(self.sock, {"player": player, "signature": data["signature"]},need_signature=False)
        else:
            self.logger.info(f"A caller already exists")
            self.close()

    def validate_cards(self, conn, data):
        self.check_signature(data)
        for player, card in data["cards"].items():
            self.logger.info(f"Validating {player}'s card")
            print("CARD SIZE", DEFAULT_SIZE)
            if Game.failed_card_validation(DEFAULT_SIZE, card):
                self.logger.info(f"Invalid card")
                Protocol.validate_cards_error(self.sock, self.private_key, "Invalid Card", card)
                break
        else:
            self.logger.info(f"Valid cards")
            Protocol.validate_cards_success(conn, self.randomize_private_key(), data["cards"])

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
        self.logger.info(f"Caller's deck: {deck}")
        deck = AES.encrypt_list(self.randomize_symmetric_key(), AES.lst_int_to_bytes(deck))
        Protocol.generate_deck_response(self.sock, self.randomize_private_key(), [b64encode(number).decode() for number in deck])

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
            #  Check caller's deck
            caller_deck = AES.decrypt_list(deserialized_symmetric_keys[0], deserialized_decks[0])
            if not all(isinstance(number, int) and number <= DEFAULT_SIZE for number in AES.lst_bytes_to_int(caller_deck)):
                self.logger.info(f"Invalid deck")
                Protocol.validate_decks_error(conn, self.randomize_private_key(), "Invalid Deck", self.name)
            else:
                self.logger.info(f"All decks are valid")
                self.logger.info(f"Generating final deck")
                final_deck = deserialized_decks[-1]
                for symmetric_key in reversed(deserialized_symmetric_keys):
                    final_deck = AES.decrypt_list(symmetric_key, final_deck)
                Protocol.validate_decks_success(conn, self.randomize_private_key(), AES.lst_bytes_to_int(final_deck))

    def choose_winner(self, conn, data):
        self.check_signature(data)
        self.logger.info(f"Choose winner")

        if random.randint(1, 100) > self.winner_cheat:
            winner = Game.winner(data["deck"], data["cards"])
        else:
            self.logger.info(f"CHEATING Winner Choice")
            winner = random.choice(list(data["cards"].keys()))
        self.logger.info(f"I decided that the winner is {winner}")
        Protocol.choose_winner_response(conn, self.randomize_private_key(), winner)

    def sign_player_data(self, conn, data, need_signature=True):
        if need_signature:
            # If the caller receives a list of players the original message is signed a verified in join function
            self.check_signature(data)

        self.logger.info(f"Signing player data")
        signed_player_data = RSA.sign(self.randomize_private_key(), data["player"])
        Protocol.sign_player_data_response(conn, self.randomize_private_key(), signed_player_data, data["player"])

    def check_signature(self, data):
        try:
            signature = data.pop("signature")
            if not RSA.verify_signature(self.playing_area_public_key, signature, json.dumps(data).encode('utf-8')):
                self.logger.info(f"Invalid signature")
                raise InvalidSignatureException()
            else:
                self.logger.info(f"Valid signature")
        except InvalidSignatureException:
            Protocol.invalid_signature(self.sock, self.private_key)

    def share_key(self, conn, data):
        self.logger.info(f"Sharing key")
        self.check_signature(data)
        Protocol.share_key_response(conn, self.private_key, b64encode(self.symmetric_key).decode(), 0)

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
