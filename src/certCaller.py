from utils.Auth import CC
import os
import click

#  GUARDAR O CERTIFICADO DE UM CALLER NUMA Pasta
def save_cert(cert, path):
    file = open(path, "wb")
    file.write(cert)
    file.close()

#  VERFICAR SE O CERFICADO ESTA NA PASTA

def check_cert(path):
    return os.path.isfile(path)

@click.command()
@click.option('--pin', '-p', help='Pin of the cc')
def main(pin):
    if pin is None:
        print("Pin is needed")
        return
    cc = CC(pin)
    cert = cc.get_cc_cert()
    save_cert(cert, "certs/caller_cert.pem")
    print(check_cert("certs/caller_cert.pem"))

if __name__ == "__main__":
    main()