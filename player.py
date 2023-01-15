import argparse
from src.player import Player

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str, default='localhost')
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--name', type=str, default='caller')
    args = parser.parse_args()

    caller = Player(args.host, args.port, args.name)
    caller.loop()