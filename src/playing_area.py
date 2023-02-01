import json
import os
import selectors
import socket
from base64 import b64encode, b64decode
from collections import defaultdict
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend as db
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1, Hash

from src.protocol import Protocol, InvalidSignatureException, PlayerNotFoundException
from src.utils.RSA import RSA
from src.utils.logger import get_logger
from src.utils.status import GameStatus
from src.utils.types import PlayerType, CallerType


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
        self.players: list[PlayerType] = []
        self.validated_cards = defaultdict(list)
        self.validated_decks = defaultdict(tuple)
        self.game_status: GameStatus = GameStatus.NOT_STARTED
        self.cards = {}
        self.decks = []
        self.winner_choices = []
        self.logger.info(f"Playing Area started")
        self.private_key, self.public_key = RSA.generate_key_pair()
        self.audit_log = []
        self.player_counter = 0

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
        data_size = int.from_bytes(conn.recv(8), 'big')
        if data_size != 0:
            data = b''
            while len(data) < data_size:
                data += conn.recv(data_size - len(data))
            data = json.loads(data.decode('utf-8'))
            self.write_log(conn, data)

            if data["type"] == "join_player":
                self.join_player(conn, data)

            elif data["type"] == "join_caller":
                self.join_caller(conn, data)

            elif data["type"] == "publish_data":
                self.publish_data(conn, data)

            elif data["type"] == "sign_player_data_response":
                self.sign_player_response(conn, data)

            elif data["type"] == "start_game":
                self.start_game(conn, data)

            elif data["type"] == "card":
                self.receive_card(conn, data)

            elif data["type"] == "validate_cards_success":
                self.cards_validated(conn, data)

            elif data["type"] == "validate_cards_error":
                self.validate_cards_error_handler(conn)

            elif data["type"] == "generate_deck_response":
                self.caller_deck(conn, data)

            elif data["type"] == "validate_decks_error":
                self.validate_decks_error_handler(conn, data)

            elif data["type"] == "shuffle_response":
                self.handle_shuffle_response(conn, data)

            elif data["type"] == "validate_decks_success":
                self.decks_validated(conn, data)

            elif data["type"] == "choose_winner_response":
                self.handle_choose_winner_response(conn, data)

            elif data["type"] == "close_game":
                self.close()

            elif data["type"] == "send_log":
                self.send_log_reponse(conn)

            elif data["type"] == "share_key_response":
                self.handle_share_key_response(conn, data)
            elif data["type"] == "invalid_signature":
                self.handle_invalid_signature(conn, data)
        else:
            self.handle_disconnect(conn)

    def validate_cards_error_handler(self, conn):
        self.logger.info(f"Cards not validated")
        self.validated_cards[conn] = [None]
        if len(self.validated_cards) == len(self.players):
            for player in self.players:
                msg = Protocol.playing_area_closing(player.sock, self.private_key)
                self.write_log(-1, msg)
            msg = Protocol.playing_area_closing(self.caller.sock, self.private_key)
            self.write_log(-1, msg)

    def caller_deck(self, conn, data):
        self.decks.append((0, data["deck"]))
        msg = Protocol.shuffle_request(self.players[0].sock, self.private_key, data["deck"])
        self.write_log(-1, msg)

    def handle_disconnect(self, conn):
        self.sel.unregister(conn)
        if self.caller == conn:
            self.logger.info(f"Caller disconnected")
            self.caller = None
            if GameStatus.STARTED:
                for player in self.players:
                    msg = Protocol.playing_area_closing(player.sock)
                    self.write_log(-1, msg)
        else:
            self.logger.info(f"Player disconnected")
            self.players = list(filter(lambda x: x.sock != conn, self.players))
            self.update_players_list()
        conn.close()
    
    def check_cert_caller(self, cert):
        files = os.listdir("certs")
        for filename in files:
            with open("certs/"+filename,"rb") as f:
                file_content = f.read()
            
            cert = bytes.fromhex(cert)
            if file_content == cert:
                return True
        return False

    def join_player(self, conn, data):
        self.check_signature(conn, data, data["cc_key"])
        if not self.validate_certificate(data["cert"]):
            print("ERRO NA VALIDAÇÂO DA CADEIA DE CERTIFICADOS")
            pass

        if self.game_status == GameStatus.NOT_STARTED:
            self.logger.info(f"New player from {data['name']}")
            player_seq = self.players[-1].seq+1 if len(self.players) > 0 else 1
            self.players.append(PlayerType(seq=player_seq, nick=data["name"], sock=conn, public_key=None,
                                           caller_signature=None))
            msg = Protocol.join_response(conn, self.private_key, "ok", self.give_seq(), self.public_key)
            self.write_log(-1, msg)
        else:
            self.logger.info(f"Game already started")
            msg = Protocol.join_response(conn, self.private_key, "error")
            self.write_log(-1, msg)

    def join_caller(self, conn: socket.socket, data: dict):
        self.check_signature(conn, data, data["cc_key"])
        if not self.validate_certificate(data["cert"]):
            self.logger.info(f"Invalid certificate")
            msg = Protocol.join_caller_response(conn, self.private_key, "invalid_cert")
            self.write_log(-1, msg)
        
        if not self.check_cert_caller(data["cert"]):
            self.logger.info(f"Caller not authorized")
            msg = Protocol.join_caller_response(conn, self.private_key, "unauthorized_caller")
            self.write_log(-1, msg)

        elif self.caller is None:
            self.logger.info(f"New caller from {data['name']}")
            self.caller = CallerType(seq=0, nick=data["name"], sock=conn, public_key=data["public_key"])
            # Check all the players that need to be validated
            players_not_validated = [player.to_list() for player in self.players if not player.caller_signature]
            msg = Protocol.join_caller_response(conn, self.private_key, "ok", players_not_validated, self.public_key)
            self.write_log(-1, msg)
        else:
            self.logger.info(f"Caller already exists")
            msg = Protocol.join_caller_response(conn, self.private_key, "error")
            self.write_log(-1, msg)

    def start_game(self, conn, data):
        self.check_signature(conn, data)
        self.game_status = GameStatus.STARTED

        for player in self.players:
            msg = Protocol.start_game(player.sock, self.private_key, data["size"])
            self.write_log(-1, msg)

    def receive_card(self, conn, data):
        self.check_signature(conn, data)
        for player in self.players:
            if player.sock == conn and player.seq not in self.cards.keys():
                self.logger.info(f"Received card from {player.nick}")
                self.cards[player.seq] = data["card"]
        else:
            if len(self.cards) == len(self.players):
                self.logger.info(f"All cards received")
                self.request_cards_validation()

    def request_cards_validation(self):
        msg = Protocol.validate_cards(self.caller.sock, self.private_key, self.cards)
        self.write_log(-1, msg)
        for player in self.players:
            msg = Protocol.validate_cards(player.sock, self.private_key, self.cards)
            self.write_log(-1, msg)

    def cards_validated(self, conn, data):
        self.check_signature(conn, data)
        self.validated_cards[conn] = data["cards"]

        if len(self.validated_cards) == len(self.players) + 1:
            self.logger.info(f"All cards validated")
            msg = Protocol.generate_deck_request(self.caller.sock, self.private_key)
            self.write_log(-1, msg)

    def handle_shuffle_response(self, conn, data):
        self.check_signature(conn, data)
        self.decks.append((data["id"], data["deck"]))
        if len(self.decks) == len(self.players) + 1:
            self.logger.info(f"All decks shuffled")
            self.logger.info(f"Please share you symmetric key")
            msg = Protocol.share_key(self.caller.sock, self.private_key)
            self.write_log(-1, msg)
            for player in self.players:
                msg = Protocol.share_key(player.sock, self.private_key)
                self.write_log(-1, msg)
        else:
            msg = Protocol.shuffle_request(self.players[data["id"]].sock, self.private_key, data["deck"])
            self.write_log(-1, msg)

    def request_decks_validation(self):
        symmetric_keys = [(0, b64encode(self.caller.symmetric_key).decode())] + [
            (player.seq, b64encode(player.symmetric_key).decode()) for player in self.players]
        msg = Protocol.validate_decks(self.caller.sock, self.private_key, self.decks, symmetric_keys)
        self.write_log(-1, msg)
        for player in self.players:
            msg = Protocol.validate_decks(player.sock, self.private_key, self.decks, symmetric_keys)
            self.write_log(-1, msg)

    def decks_validated(self, conn, data):
        self.check_signature(conn, data)
        self.validated_decks[conn] = tuple(data["final_deck"])

        if len(self.validated_decks) == len(self.players) + 1:
            self.logger.info(f"All decks validated")
            # Check if all players have the same deck
            if len(set(self.validated_decks.values())) == 1:
                self.logger.info(f"All players got the same deck")
                final_deck = self.validated_decks[self.caller.sock]
                msg = Protocol.choose_winner(self.caller.sock, self.private_key, final_deck, self.cards)
                self.write_log(-1, msg)
                for player in self.players:
                    msg = Protocol.choose_winner(player.sock, self.private_key, final_deck, self.cards)
                    self.write_log(-1, msg)

    def handle_choose_winner_response(self, conn, data):
        self.check_signature(conn, data)
        self.winner_choices.append(data["winner"])

        if len(self.winner_choices) == len(self.players) + 1:
            self.logger.info(f"All winners chosen")
            if len(set(self.winner_choices)) == 1:
                self.logger.info(f"All players chose the same winner")
                winner_name = next(filter(lambda x: x.seq == int(self.winner_choices[0]), self.players)).nick
                self.logger.info(f"Winner is {winner_name}")
                msg = Protocol.announce_winner(self.caller.sock, self.private_key, winner_name)
                self.write_log(-1, msg)
                for player in self.players:
                    msg = Protocol.announce_winner(player.sock, self.private_key, winner_name)
                    self.write_log(-1, msg)
            else:
                self.logger.info(f"Players chose different winners")
                self.logger.info(f"Something went wrong")
                msg = Protocol.winner_decision_failed(self.caller.sock, self.private_key)
                self.write_log(-1, msg)
                for player in self.players:
                    msg = Protocol.winner_decision_failed(player.sock, self.private_key)
                    self.write_log(-1, msg)

    def close(self):
        self.sel.close()
        self.sock.close()
        self.logger.info(f"Goodbye!")
        exit()

    def publish_data(self, conn, data):
        self.logger.info(f"Sending Data to be Signed by the caller")

        player = next(filter(lambda p: p.seq == data["id"], self.players), None)
        if player:
            player.public_key = data["public_key"]

        if self.caller:
            msg = Protocol.sign_player_data(self.caller.sock, self.private_key, player.to_list())
            self.write_log(-1, msg)

    def sign_player_response(self, conn, data):
        self.check_signature(conn, data)
        self.logger.info(f"Sending Signed Data to the player")
        player = next(filter(lambda p: p.seq == data["player"][0], self.players))
        player.caller_signature = data["signed_player_data"]
        msg = Protocol.login_response(player.sock, self.private_key, "ok", data["signed_player_data"])
        self.write_log(-1, msg)
        self.update_players_list()

    def update_players_list(self):
        for player in self.players:
            msg = Protocol.players_list(player.sock, self.private_key, [p.to_list() for p in self.players])
            self.write_log(-1, msg)

    def load_local_certs(self):
        """
        Load local SSL certificates
        :return: List of local SSL certificates
        """
        local_certs = []
        for entry in os.scandir("/etc/ssl/certs"):
            if entry.is_file():
                with open(entry.path, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                    local_certs.append(cert)
        return local_certs

    def validate_certificate(self, certificate):
        """
        Validate certificate chain
        :param certificate: certificate data
        :return: True if valid, False otherwise
        """
        cert = bytes.fromhex(certificate)
        cert = x509.load_pem_x509_certificate(cert)
        if self.get_country(certificate) != "PT":
            return False

        local_certs = self.load_local_certs()
        while cert.issuer != cert.subject:
            for local_cert in local_certs:
                if cert.issuer == local_cert.subject and self.valid_date(local_cert):
                    cert = local_cert
                    break
            else:
                return False
        return True

    def valid_date(self, cert) -> bool:
        """
        Check if certificate is within valid date range
        :param cert: certificate
        :return: True if valid, False otherwise
        """
        current_date = datetime.now()
        valid_from = cert.not_valid_before
        valid_to = cert.not_valid_after
        return valid_from <= current_date <= valid_to

    def get_country(self, cert_data):
        """
        Get country from certificate
        :param cert_data: certificate data
        :return: country
        """
        cert_data = bytes.fromhex(cert_data)
        cert = x509.load_pem_x509_certificate(cert_data, db())
        country = cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value
        return country

    def verify_signature(self, message, signature, public_key):
        """ 
        Verify signature with public key
        :param message: message to verify
        :param signature: signature to verify
        :param public_key: public key to verify
        :return: True if signature is valid, False otherwise
        """
        md = Hash(SHA1(), backend=db())
        md.update(message)
        message_hash = md.finalize()

        signature = bytes.fromhex(signature)
        public_key = bytes.fromhex(public_key)
        public_key = serialization.load_pem_public_key(public_key)

        try:
            public_key.verify(
                signature,
                message_hash,
                PKCS1v15(),
                SHA1()
            )
            return True
        except:
            pass

        try:
            public_key.verify(
                signature,
                message,
                PKCS1v15(),
                SHA1()
            )
            return True
        except:
            return False

    def check_signature(self, conn, data, public_key=None):
        if public_key:
            signature = data.pop("signature")
            # ! TODO : NÃO APARECE NO LOG 
            if not self.verify_signature(json.dumps(data).encode('utf-8'), signature, public_key):
                # ! TODO: SUBSTIRUIR (?) POR NICK DO JOGADOR
                self.logger.info(f"Invalid signature from (?) the game has been compromised")
                self.close()
            else:
                self.logger.info(f"Valid signature")
            return

        try:
            public_key = self.find_public_key(conn)
            signature = data.pop("signature")
            if not RSA.verify_signature(public_key, signature, json.dumps(data).encode('utf-8')):
                self.logger.info(f"Invalid signature")
                raise InvalidSignatureException()
            else:
                self.logger.info(f"Valid signature")
        except InvalidSignatureException:
            if conn == self.caller.sock:
                cheater = "caller"
            else:
                cheater = next(filter(lambda p: p.sock == conn, self.players), None).nick
            self.logger.info(f"Invalid signature from {cheater} the game has been compromised")
            self.close()

    def find_public_key(self, sock):
        if sock == self.caller.sock:
            return self.caller.public_key
        else:
            player = next(filter(lambda p: p.sock == sock, self.players), None)
            if player:
                return player.public_key
            else:
                raise PlayerNotFoundException()

    def handle_share_key_response(self, conn, data):
        print(data)
        if data["seq"] == 0:
            self.logger.info(f"Caller symmetric key received")
            self.caller.symmetric_key = b64decode(data["symmetric_key"])
        else:
            player = next(filter(lambda p: p.seq == data["seq"], self.players), None)
            if player:
                self.logger.info(f"Player {player.seq} symmetric key received")
                player.symmetric_key = b64decode(data["symmetric_key"])
            else:
                raise PlayerNotFoundException()

        # check if symmetric_key is not None for all players and caller
        if all([p.symmetric_key for p in self.players]) and self.caller.symmetric_key:
            self.logger.info(f"All symmetric keys received")
            self.request_decks_validation()

    def handle_invalid_signature(self, conn, data):
        self.logger.info(f"The player {data['seq']} detected a signature error the game has been compromised")
        msg = Protocol.playing_area_closing(self.caller.sock, self.private_key)
        self.write_log(-1, msg)
        for player in self.players:
            msg = Protocol.playing_area_closing(player.sock, self.private_key)
            self.write_log(-1, msg)

    def validate_decks_error_handler(self, conn, data):

        self.logger.info(f"Player {data['nick']} detected a signature error the game has been compromised")
        self.validated_decks[conn] = tuple([None])
        if len(self.validated_decks) == len(self.players):
            msg = Protocol.playing_area_closing(self.caller.sock, self.private_key)
            self.write_log(-1, msg)
            for player in self.players:
                msg = Protocol.playing_area_closing(player.sock, self.private_key)
                self.write_log(-1, msg)

    def write_log(self, conn, data):
        if conn == -1:
            seq = -1
        elif self.caller and conn == self.caller.sock:
            seq = 0
        else:
            player = next(filter(lambda p: p.sock == conn, self.players), None)
            # In the beggining of the game the player do not have a seq
            seq = player.seq if player else None

        if len(self.audit_log) > 0:
            prev_entry_hashed = hash(self.audit_log[-1])
        else:
            prev_entry_hashed = hash("")

        if "signature" in data.keys():
            signature = data["signature"]
        else:
            signature = ""
        text = {k: v for k, v in data.items() if k != "signature"}
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.audit_log.append(f"{seq} {timestamp} {prev_entry_hashed} {text} {signature}")

    def send_log_reponse(self, conn):
        msg = Protocol.send_log_response(conn, self.private_key, self.audit_log)
        self.write_log(-1, msg)

    def give_seq(self):
        self.player_counter += 1
        return self.player_counter
