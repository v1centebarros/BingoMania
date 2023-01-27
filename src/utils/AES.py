import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.hazmat.primitives.ciphers.modes import ECB


class AES:
    @staticmethod
    def generate_key():
        """ Generate a symmetric key, using AES algorithm.
        :return: a symmetric key"""

        return os.urandom(32)

    @staticmethod
    def encrypt(key, number: bytes) -> bytes:
        """
        Encrypt a number using the symetric key.
        :param key: the symetric key to use
        :param number: the number to encrypt
        :return: the encrypted number
        """

        cipher = Cipher(algorithms.AES(key), ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(number) + encryptor.finalize()

    @staticmethod
    def decrypt(key, number: bytes) -> bytes:
        """
        Decrypt a number using the symetric key.
        :param key: the symetric key to use
        :param number: the number to decrypt
        :return: the decrypted number
        """

        cipher = Cipher(algorithms.AES(key), ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(number) + decryptor.finalize()

    @staticmethod
    def encrypt_list(key, lst: list[bytes]) -> list[bytes]:
        """
        Encrypt a list of numbers using the symetric key.
        :param key: the symetric key to use
        :param lst: the list of numbers to encrypt
        :return: the encrypted list of numbers
        """
        return [AES.encrypt(key, number) for number in lst]

    @staticmethod
    def decrypt_list(key, lst: list[bytes]) -> list[bytes]:
        """
        Decrypt a list of numbers using the symetric key.
        :param key: the symetric key to use
        :param lst: the list of numbers to decrypt
        :return: the decrypted list of numbers
        """

        return [AES.decrypt(key, number) for number in lst]

    @staticmethod
    def lst_int_to_bytes(lst: list[int]) -> list[bytes]:
        """
        Convert a list of integers to a list of bytes.
        :param lst: the list of integers to convert
        :return: the list of bytes
        """
        return [number.to_bytes(16, byteorder='big') for number in lst]

    @staticmethod
    def lst_bytes_to_int(lst: list[bytes]) -> list[int]:
        """
        Convert a list of bytes to a list of integers.
        :param lst: the list of bytes to convert
        :return: the list of integers
        """
        
        return [int.from_bytes(number, byteorder='big') for number in lst]

