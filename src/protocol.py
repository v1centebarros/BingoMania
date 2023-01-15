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
    def join_response(sock, status):
        return {
            "type": "join_response",
            "status": status
        }
