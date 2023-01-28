import base64
import PyKCS11
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend as db
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1, Hash
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime

PKCS11_LIB = '/usr/local/lib/libpteidpkcs11.so'
# PKCS11_LIB = '/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so'
# PKCS11_LIB = '/usr/lib/opensc-pkcs11.so'

class CC:

    def __init__(self, pin):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(PKCS11_LIB)
        self.slots = self.pkcs11.getSlotList(tokenPresent=True)
        self.pin = pin

    def get_cc_cert(self):
        """ get certificate data from card
        :return: certificate data
        """
        session = self.pkcs11.openSession(self.slots[0],PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        session.login(self.pin)
        cert_obj = session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')
                ])[0]

        cert_der_data = bytes(cert_obj.to_dict()['CKA_VALUE'])
        cert = x509.load_der_x509_certificate(cert_der_data, db())

        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        session.logout()
        session.closeSession()
        return cert_pem.hex()

        
    def get_cc_public_key(self):
        """
        get public key from card
        :return: public key
        """
        session = self.pkcs11.openSession(self.slots[0], PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        session.login(self.pin)
        objs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)])[0]
        cert = session.getAttributeValue(objs, [PyKCS11.CKA_VALUE])[0]
        cert = bytes(cert)
        cert = serialization.load_der_public_key(cert, db())
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        session.logout()
        session.closeSession()
        return cert_pem.hex()

    def sign_message(self, message):
        """
        Sign message with card
        :param message: message to sign
        :return: signature
        """

        session = self.pkcs11.openSession(self.slots[0], PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        session.login(self.pin)
        objs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA)])[0]
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
        signature = bytes(session.sign(key = objs, data = message, mecha = mechanism))
        session.logout()
        session.closeSession()
        return signature.hex()

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
        except :
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


# ** Function **

def get_name_and_number(cert_data):
    """
    Get name and citizen number from certificate
    :param cert_data: certificate data
    :return: name and citizen number
    """
    cert_data = bytes.fromhex(cert_data)
    cert = x509.load_pem_x509_certificate(cert_data, db())
    name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    citizen_number = cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
    return name, citizen_number

def get_country(cert_data):
    """
    Get country from certificate
    :param cert_data: certificate data
    :return: country
    """
    cert_data = bytes.fromhex(cert_data)
    cert = x509.load_pem_x509_certificate(cert_data, db())
    country = cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value
    return country

def load_local_certs():
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

def validate_certificate(certificate):
    """
    Validate certificate chain
    :param certificate: certificate data
    :return: True if valid, False otherwise
    """
    cert = bytes.fromhex(certificate)
    cert = x509.load_pem_x509_certificate(cert)
    if get_country(certificate) != "PT":
        return False

    local_certs = load_local_certs()
    while cert.issuer != cert.subject:
        for local_cert in local_certs:
            if cert.issuer == local_cert.subject and valid_date(local_cert):
                cert = local_cert
                break
        else:
            return False
    return True

def valid_date(cert)->bool:
    """
    Check if certificate is within valid date range
    :param cert: certificate
    :return: True if valid, False otherwise
    """
    current_date = datetime.now()
    valid_from = cert.not_valid_before
    valid_to = cert.not_valid_after
    return valid_from <= current_date <= valid_to
