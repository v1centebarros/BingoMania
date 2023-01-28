import argparse

from src.caller import Caller

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str, default='localhost')
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--name', type=str, default='caller')
    parser.add_argument('--rsa_cheat', type=int, default=0)
    parser.add_argument('--aes_cheat', type=int, default=0)
    parser.add_argument('--winner_cheat', type=int, default=0)
    args = parser.parse_args()

    caller = Caller(args.host, args.port, args.name, args.rsa_cheat, args.aes_cheat, args.winner_cheat)
    caller.loop()
