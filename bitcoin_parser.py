from typing import List
import math


def parse_cuint(cuint: bytes) -> (int, int):
    """Parses a compact uint and return the value as well as the number of
    bytes consumed
    >>> parse_cuint(bytes([0xfa]))
    (250, 1)
    >>> parse_cuint(bytes([0xfd, 0xd2, 0x04]))
    (1234, 3)
    >>> parse_cuint(bytes([0xfe, 0x15, 0xcd, 0x5b, 0x07]))
    (123456789, 5)
    >>> parse_cuint(bytes([0xff, 0x15, 0x5f, 0xd0, 0xac, 0x4b, 0x9b, 0xb6, 0x01]))
    (123456789123456789, 9)
    """
    if cuint[0] < 0xfd:
        return cuint[0], 1
    elif cuint[0] == 0xfd:
        return int.from_bytes(cuint[1:3], "little"), 3
    elif cuint[0] == 0xfe:
        return int.from_bytes(cuint[1:5], "little"), 5
    else: # cuint[0] == 0xff:
        return int.from_bytes(cuint[1:9], "little"), 9


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


def parse_vector(raw_vector: bytes, parse_element: callable) -> (list, int):
    """Given a parsing function, parses a vector
    >>> parse_vector(bytes([0x4, 0x0, 0x1, 0x2, 0x3]), lambda v: (v[0], 1))
    ([0, 1, 2, 3], 5)
    """
    element_count, offset = parse_cuint(raw_vector)
    results = []
    for _ in range(element_count):
        element, new_offset = parse_element(raw_vector[offset:])
        offset += new_offset
        results.append(element)
    return results, offset


def format_vector(vector: list, format_element: callable) -> bytes:
    """Given a formatting function, formats a vector
    >>> format_vector([0, 1, 2, 3], lambda v: v.to_bytes(1, 'little'))
    b'\\x04\\x00\\x01\\x02\\x03'
    """
    result = format_cuint(len(vector))
    for element in vector:
        result += format_element(element)
    return result


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


def parse_transaction_input(raw_tx_input: bytes) -> (dict, int):
    """Parses a raw transaction input
    >>> raw_tx_input = bytes.fromhex(
    ... "7b1eabe0209b1fe794124575ef807057"
    ... "c77ada2138ae4fa8d6c4de0398a14f3f"   # Outpoint TXID
    ... "00000000"                           # Outpoint index number
    ... "49"                                 # Bytes in sig. script: 73
    ... "48"                                 # Push 72 bytes as data
    ... "30450221008949f0cb400094ad2b5eb3"
    ... "99d59d01c14d73d8fe6e96df1a7150de"
    ... "b388ab8935022079656090d7f6bac4c9"
    ... "a94e0aad311a4268e082a725f8aeae05"
    ... "73fb12ff866a5f01"                   # Secp256k1 signature
    ... "ffffffff")
    >>> tx_input, _consumed = parse_transaction_input(raw_tx_input)
    >>> assert(tx_input["previous_index"] == 0)
    >>> assert(len(tx_input["script"]) == 73)
    >>> assert(tx_input["sequence"] == 0xffffffff)
    >>> assert(tx_input["previous_hash"] == bytes.fromhex("7b1eabe0209b1fe794124575ef807057c77ada2138ae4fa8d6c4de0398a14f3f"))
    """
    previous_hash = raw_tx_input[0:32]
    previous_index = int.from_bytes(raw_tx_input[32:36], "little")
    script_size, consumed = parse_cuint(raw_tx_input[36:])
    index = consumed + 36
    script = raw_tx_input[index:index + script_size]
    index += script_size
    sequence = int.from_bytes(raw_tx_input[index:index + 4], "little")
    return {
        "previous_hash": previous_hash,
        "previous_index": previous_index,
        "script": script,
        "sequence": sequence,
    }, index + 4


def parse_transaction_output(raw_tx_output: bytes) -> (dict, int):
    """Parses a raw transaction output
    >>> raw_tx_output = bytes.fromhex(
    ...   "f0ca052a01000000"                   # Satoshis (49.99990000 BTC)
    ...   "19"                                 # Bytes in pubkey script: 25
    ...   "76"                                 # OP_DUP
    ...   "a9"                                 # OP_HASH160
    ...   "14"                                 # Push 20 bytes as data
    ...   "cbc20a7664f2f69e5355aa427045bc15"
    ...   "e7c6c772"                           # PubKey hash
    ...   "88"                                 # OP_EQUALVERIFY
    ...   "ac")                                # OP_CHECKSIG
    >>> tx_output, _consumed = parse_transaction_output(raw_tx_output)
    >>> assert(tx_output["value"] == 4999990000)
    >>> assert(len(tx_output["script"]) == 25)
    """
    value = int.from_bytes(raw_tx_output[0:8], "little", signed=False)
    script_size, consumed = parse_cuint(raw_tx_output[8:])
    index = 8 + consumed
    script = raw_tx_output[index:index + script_size]
    return {
        "value": value,
        "script": script,
    }, index + script_size



def parse_witness(raw_witness: bytes) -> (bytes, int):
    """Parse a transaction witnesses
    """
    size, consumed = parse_cuint(raw_witness)
    return raw_witness[0:size], consumed + size


def parse_transaction(raw_transaction: bytes) -> (dict, int):
    """Parse a raw transaction
    >>> raw_tx = bytes.fromhex("0200000000010140d43a99926d43eb0e619bf0b3d83b4a31f60c176beecfb9d35bf45e54d0f7420100000017160014a4b4ca48de0b3fffc15404a1acdc8dbaae226955ffffffff0100e1f5050000000017a9144a1154d50b03292b3024370901711946cb7cccc387024830450221008604ef8f6d8afa892dee0f31259b6ce02dd70c545cfcfed8148179971876c54a022076d771d6e91bed212783c9b06e0de600fab2d518fad6f15a2b191d7fbd262a3e0121039d25ab79f41f75ceaf882411fd41fa670a4c672c23ffaf0e361a969cde0692e800000000")
    >>> tx = parse_transaction(raw_tx)
    >>> assert(tx["version"] == 2)
    >>> assert(len(tx["inputs"]) == 1)
    >>> assert(len(tx["inputs"][0]["witnesses"]) == 2)
    >>> assert(len(tx["inputs"][0]["witnesses"][0]) == 72)
    >>> assert(len(tx["inputs"][0]["witnesses"][1]) == 33)
    >>> assert(len(tx["outputs"]) == 1)
    >>> assert(tx["locktime"] == 0)
    """
    version = int.from_bytes(raw_transaction[0:4], "little", signed=True)
    if version not in [1, 2]:  # supported versions
        raise ValueError("unsupported version: {0}".format(version))
    inputs, consumed = parse_vector(raw_transaction[4:], parse_transaction_input)
    index = consumed + 4
    has_witness = len(inputs) == 0
    if has_witness:
        flags = raw_transaction[5]  # must currently be 1
        if flags != 1:
            raise ValueError("invalid flag: {0}".format(flags))
        inputs, consumed = parse_vector(raw_transaction[6:], parse_transaction_input)
        index += consumed + 1
    outputs, consumed = parse_vector(raw_transaction[index:], parse_transaction_output)
    index += consumed
    if has_witness:
        for tx_input in inputs:
            witnesses, consumed = parse_vector(raw_transaction[index:], parse_witness)
            tx_input["witnesses"] = witnesses
            index += consumed
    locktime = int.from_bytes(raw_transaction[index:index + 4], "little")
    return dict(
        version=version,
        inputs=inputs,
        outputs=outputs,
        locktime=locktime,
    )
