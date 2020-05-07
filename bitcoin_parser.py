import math


def parse_cuint(cuint: bytes) -> int:
    """Parses a compact uint
    >>> parse_cuint(bytes([0xfa]))
    250
    >>> parse_cuint(bytes([0xfd, 0xd2, 0x04]))
    1234
    >>> parse_cuint(bytes([0xfe, 0x15, 0xcd, 0x5b, 0x07]))
    123456789
    >>> parse_cuint(bytes([0xff, 0x15, 0x5f, 0xd0, 0xac, 0x4b, 0x9b, 0xb6, 0x01]))
    123456789123456789
    """
    if cuint[0] < 0xfd:
        return cuint[0]
    elif cuint[0] == 0xfd:
        return int.from_bytes(cuint[1:3], "little")
    elif cuint[0] == 0xfe:
        return int.from_bytes(cuint[1:5], "little")
    else: # cuint[0] == 0xff:
        return int.from_bytes(cuint[1:9], "little")


def format_cuint(value: int) -> bytes:
    """Formats an integer value as a cuint
    >>> format_cuint(250)
    b'\\xfa'
    >>> format_cuint(1234)
    b'\\xfd\\xd2\\x04'
    >>> format_cuint(123456789)
    b'\\xfe\\x15\\xcd[\\x07'
    >>> format_cuint(123456789123456789)
    b'\\xff\\x15_\\xd0\\xacK\\x9b\\xb6\\x01'
    """
    if value < 0xfd:
        return value.to_bytes(1, "little")
    elif value <= 2 ** 16 - 1:
        return b"\xfd" + value.to_bytes(2, "little")
    elif value <= 2 ** 32 - 1:
        return b"\xfe" + value.to_bytes(4, "little")
    elif value <= 2**64 - 1:
        return b"\xff" + value.to_bytes(8, "little")
    else:
        raise ValueError("{0} too large for u64".format(value))


def parse_nbits(nbits: bytes) -> int:
    """Parses u256 represented as nbits into an integer
    >>> parse_nbits(bytes([0x30, 0xc3, 0x1b, 0x18])) # 0x1bc330 * 256**(0x18-3)
    680733321990486529407107157001552378184394215934016880640
    """
    exponent = nbits[3]
    mantissa = int.from_bytes(nbits[:3], "little")
    return mantissa * 256 ** (exponent - 3)


def format_nbits(value: int) -> bytes:
    """Formats an integer into a 4 bytes nbits representation
    >>> format_nbits(680733321990486529407107157001552378184394215934016880640)
    b'0\\xc3\\x1b\\x18'
    """
    exponent = math.ceil(math.log(value, 256))
    mantissa = value // (256 ** (exponent - 3))
    return mantissa.to_bytes(3, "little") + exponent.to_bytes(1, "little")


def parse_block_header(header: bytes) -> dict:
    """Parses a header header from its raw bytes representation
    >>> raw_header = bytes.fromhex(
    ... '02000000'                         # Block version: 2
    ... 'b6ff0b1b1680a2862a30ca44d346d9e8'
    ... '910d334beb48ca0c0000000000000000' # Hash of previous header's header
    ... '9d10aa52ee949386ca9385695f04ede2'
    ... '70dda20810decd12bc9b048aaab31471' # Merkle root
    ... '24d95a54'                         # Unix time: 1415239972
    ... '30c31b18'                         # Target: 0x1bc330 * 256**(0x18-3)
    ... 'fe9f0864')
    >>> header = parse_block_header(raw_header)
    >>> header['version']
    2
    """
    return {
        "version": int.from_bytes(header[0:4], "little", signed=True),
        "previous_hash": header[4:36],
        "merkle_root": header[36:68],
        "timestamp": int.from_bytes(header[68:72], "little"),
        "target": parse_nbits(header[72:76]),
        "nonce": int.from_bytes(header[76:80], "little"),
    }


def format_block_header(header: dict) -> bytes:
    """Formats a block header into its raw byte representation
    >>> raw_header = bytes.fromhex( # same block as 
    ... '02000000b6ff0b1b1680a2862a30ca44d346d9e8910d334beb48ca0c0000000000000000'
    ... '9d10aa52ee949386ca9385695f04ede270dda20810decd12bc9b048aaab31471'
    ... '24d95a5430c31b18fe9f0864')
    >>> header = parse_block_header(raw_header)
    >>> assert(format_block_header(header) == raw_header)
    """
    return (
        header["version"].to_bytes(4, "little", signed=True) +
        header["previous_hash"] +
        header["merkle_root"] +
        header["timestamp"].to_bytes(4, "little") +
        format_nbits(header["target"]) +
        header["nonce"].to_bytes(4, "little")
    )
