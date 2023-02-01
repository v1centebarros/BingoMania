import json

from src.utils.RSA import RSA
from src.utils.logger import get_logger

logger = get_logger(__name__)


def send_message(func):
    def wrapper(sock, private_key, *args, **kwargs):
        logger.info(f"Sending message {func.__name__}")
        payload = func(*args, **kwargs)
        
        if callable(private_key):
            payload["signature"] = private_key(json.dumps(payload).encode('utf-8'))
        else:
            payload["signature"] = RSA.sign(private_key, json.dumps(payload).encode('utf-8'))
        payload = json.dumps(payload).encode('utf-8')
        sent = 0
        sock.send(len(payload).to_bytes(8, byteorder='big'))
        while sent < len(payload):
            sent += sock.send(payload[sent:])

        return json.loads(payload.decode('utf-8'))
    return wrapper


class Protocol:

    @staticmethod
    @send_message
    def playing_area_closing():
        return {"type": "playing_area_closing"}

    @staticmethod
    @send_message
    def join_caller_request(name, public_key,cert,public_key_cc):
        return {
            "type": "join_caller",
            "name": name,
            "public_key": public_key,
            "cert": cert,
            "cc_key": public_key_cc
        }

    @staticmethod
    @send_message
    def join_caller_response(status, players_not_validated=None, playing_area_public_key=None):
        return {
            "type": "join_caller_response",
            "status": status,
            "players_not_validated": players_not_validated,
            "playing_area_public_key": playing_area_public_key
        }

    @staticmethod
    @send_message
    def join_request(name, cert , public_key_cc):
        return {
            "type": "join_player",
            "name": name,
            "cert": cert,
            "cc_key": public_key_cc
        }

    @staticmethod
    @send_message
    def join_response(status, _id=None, playing_area_public_key=None):
        return {
            "type": "join_response",
            "status": status,
            "id": _id,
            "playing_area_public_key": playing_area_public_key
        }

    @staticmethod
    @send_message
    def start_game(size: int):
        return {
            "type": "start_game",
            "size": size
        }

    @staticmethod
    @send_message
    def send_card(card):
        return {
            "type": "card",
            "card": card
        }

    @staticmethod
    @send_message
    def validate_cards(cards):
        return {
            "type": "validate_cards",
            "cards": cards
        }

    @staticmethod
    @send_message
    def validate_cards_success(cards):
        return {
            "type": "validate_cards_success",
            "cards": cards
        }

    @staticmethod
    @send_message
    def validate_cards_error(error, cheater):
        return {
            "type": "validate_cards_error",
            "error": error,
            "cheater": cheater
        }

    @staticmethod
    @send_message
    def generate_deck_request():
        return {
            "type": "generate_deck_request",
        }

    @staticmethod
    @send_message
    def generate_deck_response(deck):
        return {
            "type": "generate_deck_response",
            "deck": deck
        }

    @staticmethod
    @send_message
    def shuffle_request(deck):
        return {
            "type": "shuffle",
            "deck": deck
        }

    @staticmethod
    @send_message
    def shuffle_response(deck, _id):
        return {
            "type": "shuffle_response",
            "deck": deck,
            "id": _id
        }

    @staticmethod
    @send_message
    def validate_decks(decks, symmetric_keys):
        return {
            "type": "validate_decks",
            "decks": decks,
            "symmetric_keys": symmetric_keys
        }

    @staticmethod
    @send_message
    def validate_decks_success(final_deck):
        return {
            "type": "validate_decks_success",
            "final_deck": final_deck
        }

    @staticmethod
    @send_message
    def choose_winner(deck, cards):
        return {
            "type": "choose_winner",
            "deck": deck,
            "cards": cards
        }

    @staticmethod
    @send_message
    def choose_winner_response(winner):
        return {
            "type": "choose_winner_response",
            "winner": winner
        }

    @staticmethod
    @send_message
    def announce_winner(winner):
        return {
            "type": "announce_winner",
            "winner": winner
        }

    @staticmethod
    @send_message
    def winner_decision_failed():
        return {
            "type": "winner_decision_failed",
        }

    @staticmethod
    @send_message
    def close_game():
        return {
            "type": "close_game"
        }

    @staticmethod
    @send_message
    def publish_data(_id, public_key):
        return {
            "type": "publish_data",
            "id": _id,
            "public_key": public_key
        }

    @staticmethod
    @send_message
    def sign_player_data(data):
        return {
            "type": "sign_player_data",
            "player": data
        }

    @staticmethod
    @send_message
    def sign_player_data_response(signed_player_data, player):
        return {
            "type": "sign_player_data_response",
            "signed_player_data": signed_player_data,
            "player": player
        }

    @staticmethod
    @send_message
    def login_response(status, signed_player_data):
        return {
            "type": "login_response",
            "status": status,
            "signed_player_data": signed_player_data
        }

    @staticmethod
    @send_message
    def players_list(players):
        return {
            "type": "players_list",
            "players": players
        }

    @staticmethod
    @send_message
    def share_key():
        return {
            "type": "share_key"
        }

    @staticmethod
    @send_message
    def share_key_response(symmetric_key, seq):
        return {
            "type": "share_key_response",
            "symmetric_key": symmetric_key,
            "seq": seq
        }

    @staticmethod
    @send_message
    def invalid_signature(seq):
        return {
            "type": "invalid_signature",
            "seq": seq
        }

    @staticmethod
    @send_message
    def validate_decks_error(error, nick):
        return {
            "type": "validate_decks_error",
            "error": error,
            "nick": nick
        }

    @staticmethod
    @send_message
    def send_log():
        return {
            "type": "send_log",
        }

    @staticmethod
    @send_message
    def send_log_response(audit_log):
        return {
            "type": "send_log_response",
            "audit_log": audit_log
        }


class InvalidSignatureException(Exception):
    def __init__(self):
        super().__init__("Invalid signature")


class PlayerNotFoundException(Exception):
    def __init__(self):
        super().__init__("Player not found")
