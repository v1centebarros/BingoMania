from collections import namedtuple

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

Player_tuple = namedtuple('Player', ['seq', 'public_key', 'nick'], defaults=[int, RSAPublicKey, str])
Keys = namedtuple('Keys', ['private', 'public', 'symmetric'], defaults=[RSAPrivateKey, RSAPublicKey, bytes])
Signed_card_tuple = namedtuple('SignedCard', ['card', 'signature'], defaults=[list[int], bytes])
Signed_deck_tuple = namedtuple('SignedDeck', ['deck', 'signature'], defaults=[list[int], bytes])
