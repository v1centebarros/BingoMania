
class Serializer:

    @staticmethod
    def lst_int_to_bytes(lst: list[int]) -> list[bytes]:
        return [number.to_bytes(16, byteorder='big') for number in lst]

    @staticmethod
    def lst_bytes_to_int(lst: list[bytes]) -> list[int]:
        return [int.from_bytes(number, byteorder='big') for number in lst]
