from enum import Enum


class GameStatus(Enum):
    """Game status."""
    NOT_STARTED = 0
    STARTED = 1
    FINISHED = 2
