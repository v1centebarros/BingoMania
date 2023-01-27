from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class RSA:
    @staticmethod
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    @staticmethod
    def deserialize_public_key(public_key):
        return serialization.load_pem_public_key(
            public_key.encode('utf-8'),
            backend=default_backend()
        )

    @staticmethod
    def generate_key_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        public_key = RSA.serialize_public_key(public_key)

        return private_key, public_key

    @staticmethod
    def encrypt(message):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        return digest.finalize()

    @staticmethod
    def encrypt_rsa(public_key, message):
        public_key = RSA.deserialize_public_key(public_key)
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
        message = message.__repr__().encode('utf-8')
        signature = bytes.fromhex(signature)
        public_key = RSA.deserialize_public_key(public_key)
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
