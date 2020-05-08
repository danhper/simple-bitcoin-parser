from typing import List
import math
import hashlib


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
    exponent = 0
    while value > 256 ** 3 or value % 256 == 0:
        value //= 256
        exponent += 1
    return value.to_bytes(3, "little") + (exponent + 3).to_bytes(1, "little")


def parse_vector(raw_vector: bytes, parse_element: callable = None) -> (list, int):
    """Given a parsing function, parses a vector
    Defaults to parsing elements as simple `uint8`
    >>> parse_vector(bytes([0x4, 0x0, 0x1, 0x2, 0x3]), lambda v: (v[0], 1))
    ([0, 1, 2, 3], 5)
    """
    if parse_element is None:
        parse_element = lambda raw_bytes: (raw_bytes[0], 1)
    element_count, offset = parse_cuint(raw_vector)
    results = []
    for _ in range(element_count):
        element, new_offset = parse_element(raw_vector[offset:])
        offset += new_offset
        results.append(element)
    return results, offset


def format_vector(vector: list, format_element: callable = None) -> bytes:
    """Given a formatting function, formats a vector
    Defaults to formatting elements as simple `uint8`
    >>> format_vector([0, 1, 2, 3], lambda v: v.to_bytes(1, 'little'))
    b'\\x04\\x00\\x01\\x02\\x03'
    """
    if format_element is None:
        format_element = lambda elem: elem.to_bytes(1, 'little')
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
    >>> tx_input, consumed = parse_transaction_input(raw_tx_input)
    >>> assert(consumed == len(raw_tx_input))
    >>> assert(tx_input["previous_index"] == 0)
    >>> assert(len(tx_input["script"]) == 73)
    >>> assert(tx_input["sequence"] == 0xffffffff)
    >>> assert(tx_input["previous_hash"] == bytes.fromhex("7b1eabe0209b1fe794124575ef807057c77ada2138ae4fa8d6c4de0398a14f3f"))
    """
    previous_hash = raw_tx_input[0:32]
    previous_index = int.from_bytes(raw_tx_input[32:36], "little")
    script, consumed = parse_vector(raw_tx_input[36:])
    index = consumed + 36
    sequence = int.from_bytes(raw_tx_input[index:index + 4], "little")
    return {
        "previous_hash": previous_hash,
        "previous_index": previous_index,
        "script": script,
        "sequence": sequence,
    }, index + 4


def format_transaction_input(tx_input: dict) -> bytes:
    """Formats a transaction input into its serialized representation
    >>> raw_tx_input = bytes.fromhex(
    ... "7b1eabe0209b1fe794124575ef807057c77ada2138ae4fa8d6c4de0398a14f3f"
    ... "00000000494830450221008949f0cb400094ad2b5eb399d59d01c14d73d8fe6e96df1a7150de"
    ... "b388ab8935022079656090d7f6bac4c9a94e0aad311a4268e082a725f8aeae0573fb12ff866a5f01ffffffff")
    >>> tx_input, _consumed = parse_transaction_input(raw_tx_input)
    >>> assert(format_transaction_input(tx_input) == raw_tx_input)
    """
    result = tx_input["previous_hash"]
    result += tx_input["previous_index"].to_bytes(4, "little")
    result += format_vector(tx_input["script"])
    result += tx_input["sequence"].to_bytes(4, "little")
    return result


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
    >>> tx_output, consumed = parse_transaction_output(raw_tx_output)
    >>> assert(consumed == len(raw_tx_output))
    >>> assert(tx_output["value"] == 4999990000)
    >>> assert(len(tx_output["script"]) == 25)
    """
    value = int.from_bytes(raw_tx_output[0:8], "little", signed=True)
    script, consumed = parse_vector(raw_tx_output[8:])
    return {
        "value": value,
        "script": script,
    }, 8 + consumed


def format_transaction_output(tx_output: dict) -> bytes:
    """Formats a transaction output in its bytes representation
    >>> raw_tx_output = bytes.fromhex(
    ...   "f0ca052a010000001976a914"
    ...   "cbc20a7664f2f69e5355aa427045bc15e7c6c77288ac")
    >>> tx_output, _consumed = parse_transaction_output(raw_tx_output)
    >>> assert(format_transaction_output(tx_output) == raw_tx_output)
    """
    return tx_output["value"].to_bytes(8, "little", signed=True) + \
           format_vector(tx_output["script"])


def parse_transaction(raw_transaction: bytes) -> (dict, int):
    """Parses a raw transaction
    >>> raw_tx = bytes.fromhex("0200000000010140d43a99926d43eb0e619bf0b3"
    ...                        "d83b4a31f60c176beecfb9d35bf45e54d0f74201"
    ...                        "00000017160014a4b4ca48de0b3fffc15404a1ac"
    ...                        "dc8dbaae226955ffffffff0100e1f50500000000"
    ...                        "17a9144a1154d50b03292b3024370901711946cb"
    ...                        "7cccc387024830450221008604ef8f6d8afa892d"
    ...                        "ee0f31259b6ce02dd70c545cfcfed81481799718"
    ...                        "76c54a022076d771d6e91bed212783c9b06e0de6"
    ...                        "00fab2d518fad6f15a2b191d7fbd262a3e012103"
    ...                        "9d25ab79f41f75ceaf882411fd41fa670a4c672c"
    ...                        "23ffaf0e361a969cde0692e800000000")
    >>> tx, consumed = parse_transaction(raw_tx)
    >>> assert(consumed == len(raw_tx))
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
            witnesses, consumed = parse_vector(raw_transaction[index:], parse_vector)
            tx_input["witnesses"] = witnesses
            index += consumed
    locktime = int.from_bytes(raw_transaction[index:index + 4], "little")
    return dict(
        version=version,
        inputs=inputs,
        outputs=outputs,
        locktime=locktime,
    ), index + 4


def double_sha256(raw_bytes: bytes) -> bytes:
    """Computes a double SHA256 hash
    """
    return hashlib.sha256(hashlib.sha256(raw_bytes).digest()).digest()


def format_transaction(transaction: dict, with_witness: bool = True) -> bytes:
    """Formats a transaction in its bytes representation
    >>> raw_tx = bytes.fromhex("0200000000010140d43a99926d43eb0e619bf0b3"
    ...                        "d83b4a31f60c176beecfb9d35bf45e54d0f74201"
    ...                        "00000017160014a4b4ca48de0b3fffc15404a1ac"
    ...                        "dc8dbaae226955ffffffff0100e1f50500000000"
    ...                        "17a9144a1154d50b03292b3024370901711946cb"
    ...                        "7cccc387024830450221008604ef8f6d8afa892d"
    ...                        "ee0f31259b6ce02dd70c545cfcfed81481799718"
    ...                        "76c54a022076d771d6e91bed212783c9b06e0de6"
    ...                        "00fab2d518fad6f15a2b191d7fbd262a3e012103"
    ...                        "9d25ab79f41f75ceaf882411fd41fa670a4c672c"
    ...                        "23ffaf0e361a969cde0692e800000000")
    >>> tx, _consumed = parse_transaction(raw_tx)
    >>> assert(format_transaction(tx) == raw_tx)
    >>> expected_txid = bytes.fromhex("c586389e5e4b3acb9d6c8be1c19ae8ab2795397633176f5a6442a261bbdefc3a")[::-1]
    >>> expected_hash = bytes.fromhex("b759d39a8596b70b3a46700b83e1edb247e17ba58df305421864fe7a9ac142ea")[::-1]
    >>> assert(double_sha256(raw_tx) == expected_hash)
    >>> assert(double_sha256(format_transaction(tx, with_witness=True)) == expected_hash)
    >>> assert(double_sha256(format_transaction(tx, with_witness=False)) == expected_txid)
    """
    has_witness = any("witnesses" in tx_in for tx_in in transaction["inputs"])
    include_witness = with_witness and has_witness

    result = transaction["version"].to_bytes(4, "little", signed=True)
    if include_witness:
        result += bytes([0, 1])  # marker and flags
    result += format_vector(transaction["inputs"], format_transaction_input)
    result += format_vector(transaction["outputs"], format_transaction_output)
    if include_witness:
        for tx_input in transaction["inputs"]:
            result += format_vector(tx_input.get("witnesses", []), format_vector)
    result += transaction["locktime"].to_bytes(4, "little")
    return result


SAMPLE_PROOF = (
    "00000020ecf348128755dbeea5deb8eddf64566d9d4e59bc65d485000000000000000000901f0d92"
    "a66ee7dcefd02fa282ca63ce85288bab628253da31ef259b24abe8a0470a385a45960018e8d672f8"
    "a90a00000d0bdabada1fb6e3cef7f5c6e234621e3230a2f54efc1cba0b16375d9980ecbc023cbef3"
    "ba8d8632ea220927ec8f95190b30769eb35d87618f210382c9445f192504074f56951b772efa43b8"
    "9320d9c430b0d156b93b7a1ff316471e715151a0619a39392657f25289eb713168818bd5b37476f1"
    "bc59b166deaa736d8a58756f9d7ce2aef46d8004c5fe3293d883838f87b5f1da03839878895b7153"
    "0e9ff89338bb6d4578b3c3135ff3e8671f9a64d43b22e14c2893e8271cecd420f11d2359307403bb"
    "1f3128885b3912336045269ef909d64576b93e816fa522c8c027fe408700dd4bdee0254c069ccb72"
    "8d3516fe1e27578b31d70695e3e35483da448f3a951273e018de7f2a8f657064b013c6ede75c74bb"
    "d7f98fdae1c2ac6789ee7b21a791aa29d60e89fff2d1d2b1ada50aa9f59f403823c8c58bb092dc58"
    "dc09b28158ca15447da9c3bedb0b160f3fe1668d5a27716e27661bcb75ddbf3468f5c76b7bed1004"
    "c6b4df4da2ce80b831a7c260b515e6355e1c306373d2233e8de6fda3674ed95d17a01a1f64b27ba8"
    "8c3676024fbf8d5dd962ffc4d5e9f3b1700763ab88047f7d0000"
)


def parse_merkle_proof(raw_merkle_proof: bytes) -> (dict, int):
    """Parses a Merkle proof as returned by `gettxoutproof`
    >>> raw_proof = bytes.fromhex(SAMPLE_PROOF)
    >>> proof, consumed = parse_merkle_proof(raw_proof)
    >>> assert(consumed == len(raw_proof))
    >>> assert(proof["transactions_count"] == 2729)
    >>> assert(len(proof["hashes"]) == 13)
    >>> assert(len(proof["flags"]) == 4)
    >>> expected_merkle_root = bytes.fromhex("a0e8ab249b25ef31da538262ab8b2885ce63ca82a22fd0efdce76ea6920d1f90")[::-1]
    >>> assert(proof["block_header"]["merkle_root"] == expected_merkle_root)
    """
    block_header = parse_block_header(raw_merkle_proof)
    transactions_count = int.from_bytes(raw_merkle_proof[80:84], "little")
    hashes, consumed = parse_vector(raw_merkle_proof[84:], lambda x: (x[:32], 32))
    index = consumed + 84
    flags, consumed = parse_vector(raw_merkle_proof[index:])
    return {
        "block_header": block_header,
        "transactions_count": transactions_count,
        "hashes": hashes,
        "flags": flags,
    }, consumed + index


def format_merkle_proof(proof: dict) -> bytes:
    """Format a merkle proof into its byte representation
    >>> raw_proof = bytes.fromhex(SAMPLE_PROOF)
    >>> proof, _consumed = parse_merkle_proof(raw_proof)
    >>> assert(format_merkle_proof(proof) == raw_proof)
    """
    result = format_block_header(proof["block_header"])
    result += proof["transactions_count"].to_bytes(4, "little")
    result += format_vector(proof["hashes"], lambda x: x)
    result += format_vector(proof["flags"])
    return result
