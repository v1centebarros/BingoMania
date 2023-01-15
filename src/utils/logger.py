import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)


def get_logger(module):
    """Get Logger for module."""
    return logging.getLogger(module)
