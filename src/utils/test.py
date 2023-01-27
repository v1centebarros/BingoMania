import click

from AES import AES
from RSA import RSA
from Auth import CC, get_country, get_name_and_number, validate_certificate

# *RSA*
def test_generate_key_pair():
    private_key, public_key = RSA.generate_key_pair()
    assert private_key is not None
    assert public_key is not None
    print("test_generate_key_pair: OK")

def test_sign_RSA():
    private_key, public_key = RSA.generate_key_pair()
    private_key2, public_key2 = RSA.generate_key_pair()
    message = b"Hello World"
    message2 = b"Hello World2"
    signature = RSA.sign(private_key, message)
    signature2 = RSA.sign(private_key2,message)

    assert RSA.verify_signature(public_key, signature, message) == True
    assert RSA.verify_signature(public_key2, signature2, message) == True
    assert RSA.verify_signature(public_key2, signature, message) == False
    assert RSA.verify_signature(public_key, signature2, message) == False
    assert RSA.verify_signature(public_key, signature, message2) == False

    print("test_sign_RSA: OK")

def test_encrypt_RSA():
    private_key, public_key = RSA.generate_key_pair()
    private_key2, public_key2 = RSA.generate_key_pair()
    message = b"Hello World"
    message2 = b"Hello World2"
    encrypted = RSA.encrypt_rsa(public_key, message)
    encrypted2 = RSA.encrypt_rsa(public_key2, message2)

    assert RSA.decrypt_rsa(private_key, encrypted) == message
    assert RSA.decrypt_rsa(private_key2, encrypted2) == message2
    print("test_encrypt_RSA: OK")

def test_RSA():
    test_generate_key_pair()
    test_sign_RSA()
    test_encrypt_RSA()

# *AES*
def test_generate_key_symetrics():
    key = AES.generate_key()
    assert key is not None
    print("test_generate_key_symetrics: OK")


def test_encryption_decryption_number():
    key = AES.generate_key()
    number = 1234
    number_bytes = number.to_bytes(16, byteorder='big')
    number2 = 1
    number2_bytes = number2.to_bytes(16, byteorder='big')
    encrypted_number = AES.encrypt(key, number_bytes)
    decrypted_number = AES.decrypt(key, encrypted_number)
    encrypted_number2 = AES.encrypt(key, number2_bytes)
    decrypted_number2 = AES.decrypt(key, encrypted_number2)

    assert number_bytes == decrypted_number
    assert number2_bytes == decrypted_number2
    assert number_bytes != decrypted_number2
    assert number2_bytes != decrypted_number
    print("test_encryption_decryption_number: OK")

def test_list_encryption_decryption():
    key = AES.generate_key()
    test_list = [1, 2, 3, 4]
    test_list_bytes = AES.lst_int_to_bytes(test_list)
    encrypted_list = AES.encrypt_list(key, test_list_bytes)
    decrypted_list = AES.decrypt_list(key, encrypted_list)
    assert test_list_bytes == decrypted_list
    print("test_list_encryption_decryption: OK")

def test_int_bytes_conversion():
    test_list = [1, 2, 3, 4]
    test_list_bytes = AES.lst_int_to_bytes(test_list)
    converted_list = AES.lst_bytes_to_int(test_list_bytes)
    assert test_list == converted_list
    print("test_int_bytes_conversion: OK")


def test_AES():
    test_generate_key_symetrics()
    test_encryption_decryption_number()
    test_int_bytes_conversion()
    test_list_encryption_decryption()

# *CC*
def test_cc_info(pin):
    cc = CC(pin)
    cert = cc.get_cc_cert()
    country = get_country(cert)
    name, number = get_name_and_number(cert)
    assert country == "PT"
    assert name is not None
    assert number is not None
    print("test_cc_info: OK")

def test_cc_valid(pin):
    cc = CC(pin)
    cert = cc.get_cc_cert()
    assert validate_certificate(cert) == True
    print("test_cc_valid: OK")

def test_cc_sign(pin):
    cc = CC(pin)
    message = b"Hello World"
    signature = cc.sign_message(message)
    public_key = cc.get_cc_public_key()
    assert signature is not None
    assert public_key is not None
    assert cc.verify_signature(message, signature, public_key) == True
    print("test_cc_sign: OK")

def test_cc(pin):
    test_cc_info(pin)
    test_cc_sign(pin)
    test_cc_valid(pin) 



# *MAIN*
@click.command()
@click.option('--test', '-t', help='choose from: [sign_message]')
@click.option('--pin', '-p', help='Pin of the cc')
def main(test, pin):
    if test == "RSA":
        print("-"*30 + "RSA" + "-"*30)
        test_RSA()
    elif test == "AES":
        print("-"*30 + "AES" + "-"*30)
        test_AES()
    elif test == "CC":
        print("-"*30 + "CC" + "-"*30)
        if pin is None:
            print("Pin is needed")
            return
        test_cc(pin)

    else:
        print("No test chosen")
        return 
    
if __name__ == "__main__":
    main()
