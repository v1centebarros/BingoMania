import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.hazmat.primitives.ciphers.modes import ECB


class AES:
    @staticmethod
    def generate_key():
        return os.urandom(32)

    @staticmethod
    def encrypt(key, number: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(number) + encryptor.finalize()

    @staticmethod
    def decrypt(key, number: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(number) + decryptor.finalize()

    @staticmethod
    def encrypt_list(key, lst: list[bytes]) -> list[bytes]:
        return [AES.encrypt(key, number) for number in lst]

    @staticmethod
    def decrypt_list(key, lst: list[bytes]) -> list[bytes]:
        return [AES.decrypt(key, number) for number in lst]

    @staticmethod
    def lst_int_to_bytes(lst: list[int]) -> list[bytes]:
        return [number.to_bytes(16, byteorder='big') for number in lst]

    @staticmethod
    def lst_bytes_to_int(lst: list[bytes]) -> list[int]:
        return [int.from_bytes(number, byteorder='big') for number in lst]

