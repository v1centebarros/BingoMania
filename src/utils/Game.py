import random

CHEATING_PROB = 0


class Game:

    @staticmethod
    def generate_card(n) -> list[int]:
        if random.randint(0, 100) < CHEATING_PROB:
            print("CHEATING GENERATING CARD")
            n = random.randint(1, 1000)

        return random.sample(range(1, n + 1), n // 4)

    @staticmethod
    def generate_deck(n) -> list[int]:
        return random.sample(range(1, n + 1), n)

    @staticmethod
    def shufle_deck(deck: list[int]|list[bytes]) -> list[int]|list[bytes]:
        """Shuffle the deck."""
        return random.sample(deck, len(deck))

    @staticmethod
    def validate_card(n: int, my_guess: list[int]) -> bool:
        """Check if the player submits a valid card."""
        return len(my_guess) != n // 4 or len(set(my_guess)) != len(my_guess) or max(my_guess) > n or min(my_guess) < 1

    @staticmethod
    def count_turns(deck: list[int], card: list[int]) -> int:
        """Count the number of turns for the player to win."""
        return max([i for i in range(len(deck)) if deck[i] in card]) + 1

    @staticmethod
    def return_winner(players: list[tuple[int, int]]) -> int:
        """Return the name of the player with the least number of turns."""
        if random.randint(0, 100) < CHEATING_PROB:
            print("CHEATING RETURNING WINNER")
            return random.choice(players)[0]

        return min(players, key=lambda x: x[1])[0]

    @staticmethod
    def winner(deck: list[int], cards: dict[int, list[int]]) -> int:
        """Play the game with the given players and return the name of the winning player."""
        return Game.return_winner([(seq, Game.count_turns(deck, card)) for seq, card in cards.items()])
