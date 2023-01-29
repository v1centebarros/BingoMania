import argparse

from src.playing_area import PlayingArea

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str, default='localhost')
    parser.add_argument('--port', type=int, default=9090)
    args = parser.parse_args()

    parea = PlayingArea(args.host, args.port)
    parea.loop()