import socket
from collections import namedtuple
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

PlayerTuple = namedtuple('Player', ['seq', 'public_key', 'nick', 'caller_signature'])
Keys = namedtuple('Keys', ['private', 'public', 'symmetric'], defaults=[RSAPrivateKey, RSAPublicKey, bytes])
Signed_card_tuple = namedtuple('SignedCard', ['card', 'signature'], defaults=[list[int], bytes])
Signed_deck_tuple = namedtuple('SignedDeck', ['deck', 'signature'], defaults=[list[int], bytes])


@dataclass
class CallerType:
    seq: int
    nick: str
    public_key: RSAPublicKey | None
    sock: socket.socket

    def to_tuple(self):
        # TODO: remove this method
        return PlayerTuple(self.seq, self.public_key, self.nick, None)

    def to_list(self):
        return [self.seq, self.public_key, self.nick]


@dataclass
class PlayerType:
    seq: int
    nick: str
    public_key: RSAPublicKey | None
    symmetric_key: bytes | None
    caller_signature: bytes | None
    sock: socket.socket

    def __init__(self, seq, nick, public_key, caller_signature, sock):
        self.seq = seq
        self.nick = nick
        self.public_key = public_key
        self.caller_signature = caller_signature
        self.sock = sock
        self.symmetric_key = None

    def to_tuple(self):
        return PlayerTuple(self.seq, self.public_key, self.nick, self.caller_signature)

    def to_list(self):
        return [self.seq, self.public_key, self.nick, self.caller_signature]
