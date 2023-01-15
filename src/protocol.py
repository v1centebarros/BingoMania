import json


def send_message(func):
    def wrapper(*args, **kwargs):
        payload = func(*args, **kwargs)
        payload = json.dumps(payload)
        message = len(payload).to_bytes(4, 'big') + payload.encode('utf-8')
        args[0].send(message)
        return message

    return wrapper


class Protocol:

    @staticmethod
    @send_message
    def playing_area_closing(sock):
        return {"type": "playing_area_closing"}

    @staticmethod
    @send_message
    def join_caller_request(sock, name):
        return {
            "type": "join_caller",
            "name": name
        }

    @staticmethod
    @send_message
    def join_caller_response(sock, status):
        return {
            "type": "join_caller_response",
            "status": status
        }

    @staticmethod
    @send_message
    def join_request(sock, name):
        return {
            "type": "join_player",
            "name": name
        }

    @staticmethod
    @send_message
    def join_response(sock, status, _id):
        return {
            "type": "join_response",
            "status": status,
            "id" : _id
        }

    @staticmethod
    @send_message
    def start_game(sock, size: int):
        return {
            "type": "start_game",
            "size": size
        }

    @staticmethod
    @send_message
    def send_card(sock, card):
        return {
            "type": "card",
            "card": card
        }

    @staticmethod
    @send_message
    def validate_cards(sock, cards):
        return {
            "type": "validate_cards",
            "cards": cards
        }

    @staticmethod
    @send_message
    def validate_cards_success(sock,cards):
        return {
            "type": "validate_cards_success",
            "cards": cards
        }

    @staticmethod
    @send_message
    def validate_cards_error(sock, error, cheater):
        return {
            "type": "validate_cards_error",
            "error": error,
            "cheater": cheater
        }

    @staticmethod
    @send_message
    def generate_deck_request(sock):
        return {
            "type": "generate_deck_request",
        }

    @staticmethod
    @send_message
    def generate_deck_response(sock, deck):
        return {
            "type": "generate_deck_response",
            "deck": deck
        }

    @staticmethod
    @send_message
    def shuffle_request(sock, deck):
        return {
            "type": "shuffle",
            "deck": deck
        }

    @staticmethod
    @send_message
    def shuffle_response(sock, deck, _id):
        return {
            "type": "shuffle_response",
            "deck": deck,
            "id": _id
        }