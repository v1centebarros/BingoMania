from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class RSA:
    @staticmethod
    def __serialize_public_key(public_key):
        """
        Serialize a public key.
        :param public_key: the public key to serialize
        :return: the serialized public key
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    @staticmethod
    def __deserialize_public_key(public_key):
        """
        Deserialize a public key.
        :param public_key: the public key to deserialize
        :return: the deserialized public key
        """

        return serialization.load_pem_public_key(
            public_key.encode('utf-8'),
            backend=default_backend()
        )

    @staticmethod
    def generate_key_pair():

        """ Generate a pair of assymetric key (private and public), using RSA algorithm.
        :return: a tuple of private and public key"""

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        public_key = RSA.__serialize_public_key(public_key)

        return private_key, public_key

    @staticmethod
    def encrypt(message):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        return digest.finalize()

    @staticmethod
    def encrypt_rsa(public_key, message):
        """
        Encrypt a message using the public key.
        :param public_key: the public key to use
        :param message: the message to encrypt
        :return: the encrypted message
        """
        public_key = RSA.__deserialize_public_key(public_key)
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_rsa(private_key, message):
        """
        Decrypt a message using the private key.
        :param private_key: the private key to use
        :param message: the message to decrypt
        :return: the decrypted message
        """

        message = private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return message

    @staticmethod
    def sign(private_key, message):

        """ Sign a message using the private key.
        :param private_key: the private key to use
        :param message: the message to sign
        :return: the signature of the message"""

        message = message.__repr__().encode('utf-8')
        message_encrypt = RSA.encrypt(message)

        return private_key.sign(
            message_encrypt,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        ).hex()

    @staticmethod
    def verify_signature(public_key, signature, message):
        """ Verify the signature of a message using the public key.
        :param public_key: the public key to use
        :param signature: the signature of the message
        :param message: the message
        :return: True if the signature is valid, False otherwise"""

        message = message.__repr__().encode('utf-8')
        signature = bytes.fromhex(signature)
        public_key = RSA.__deserialize_public_key(public_key)
        message_encrypt = RSA.encrypt(message)
        try:
            public_key.verify(
                signature,
                message_encrypt,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
