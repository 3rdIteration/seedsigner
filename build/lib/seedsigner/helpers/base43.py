BASE43_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:"

def base43_encode(data: bytes) -> str:
    count = 0
    for b in data:
        if b == 0:
            count += 1
        else:
            break
    num = 0
    for b in data:
        num = num * 256 + b
    result = ''
    while num > 0:
        num, mod = divmod(num, 43)
        result = BASE43_ALPHABET[mod] + result
    return BASE43_ALPHABET[0] * count + result

def base43_decode(s: str) -> bytes:
    num = 0
    for c in s:
        if c not in BASE43_ALPHABET:
            raise ValueError("Invalid character in base43: {}".format(c))
        num = num * 43 + BASE43_ALPHABET.index(c)
    # convert num to bytes
    result = bytearray()
    while num > 0:
        num, mod = divmod(num, 256)
        result.insert(0, mod)
    # count leading zeroes
    count = 0
    for c in s:
        if c == BASE43_ALPHABET[0]:
            count += 1
        else:
            break
    return bytes([0] * count) + bytes(result)
