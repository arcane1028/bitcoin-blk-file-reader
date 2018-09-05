import binascii
import struct
import datetime
import hashlib
import base58
import sys


def log(string):
    print(string)


def starts_with_op_n_code(pub):
    try:
        value: int = int(pub[0:2], 16)
        if 1 <= value <= 75:
            return True
    except RuntimeError:
        pass
    return False


def public_key_decode(pub):
    if pub.lower().startswith('76a914'):
        pub = pub[6:-4]
        result = b'\x00' + binascii.unhexlify(pub)
        h5 = hashlib.sha256(result)
        h6 = hashlib.sha256(h5.digest())
        result += h6.digest()[:4]
        return base58.b58encode(result)
    elif pub.lower().startswith('a9'):
        return ""
    elif starts_with_op_n_code(pub):
        pub = pub[2:-2]
        h3 = hashlib.sha256(binascii.unhexlify(pub))
        h4 = hashlib.new('ripemd160', h3.digest())
        result = b'\x00' + h4.digest()
        h5 = hashlib.sha256(result)
        h6 = hashlib.sha256(h5.digest())
        result += h6.digest()[:4]
        return base58.b58encode(result)
    return ""


def string_little_endian_to_big_endian(string):
    string = binascii.hexlify(string)
    n = len(string) / 2
    fmt = '%dh' % n
    return struct.pack(fmt, *reversed(struct.unpack(fmt, string)))


def read_short_little_endian(block_file):
    return struct.pack(">H", struct.unpack("<H", block_file.read(2))[0])


def read_long_little_endian(block_file):
    return struct.pack(">Q", struct.unpack("<Q", block_file.read(8))[0])


def read_int_little_endian(block_file):
    return struct.pack(">I", struct.unpack("<I", block_file.read(4))[0])


def hex2int(value):
    return int(binascii.hexlify(value), 16)


def hex2str(value):
    return str(binascii.hexlify(value))


def read_var_int(block_file):
    var_int = ord(block_file.read(1))
    return_int = 0
    if var_int < 0xfd:
        return var_int
    if var_int == 0xfd:
        return_int = read_short_little_endian(block_file)
    if var_int == 0xfe:
        return_int = read_int_little_endian(block_file)
    if var_int == 0xff:
        return_int = read_long_little_endian(block_file)
    return int(binascii.hexlify(return_int), 16)


def read_input(block_file):
    previous_hash = binascii.hexlify(block_file.read(32)[::-1])
    out_id = binascii.hexlify(read_int_little_endian(block_file))
    script_length = read_var_int(block_file)
    script_signature_raw = hex2str(block_file.read(script_length))
    script_signature = script_signature_raw
    seq_no = binascii.hexlify(read_int_little_endian(block_file))

    log("\n" + "Input")
    log("-" * 20)
    log("> Previous Hash: " + str(previous_hash))
    log("> Out ID: " + str(out_id))
    log("> Script length: " + str(script_length))
    log("> Script Signature (PubKey) Raw: " + str(script_signature_raw))
    log("> Script Signature (PubKey): " + str(script_signature))
    log("> Seq No: " + str(seq_no))


def read_output(block_file):
    value = hex2int(read_long_little_endian(block_file)) / 100000000.0
    script_length = read_var_int(block_file)
    script_signature_raw = hex2str(block_file.read(script_length))
    script_signature = script_signature_raw
    address = ''
    try:
        address = public_key_decode(script_signature)
    except Exception as e:
        print(e)
        address = ''
    log("\n" + "Output")
    log("-" * 20)
    log("> Value: " + str(value))
    log("> Script length: " + str(script_length))
    log("> Script Signature (PubKey) Raw: " + str(script_signature_raw))
    log("> Script Signature (PubKey): " + str(script_signature))
    log("> Address: " + address)


def read_transaction(block_file):
    extended_format = False
    begin_byte = block_file.tell()
    input_ids = []
    output_ids = []
    version = hex2int(read_int_little_endian(block_file))
    cut_start1 = block_file.tell()
    cut_end1 = 0
    input_count = read_var_int(block_file)
    log("\n\n" + "Transaction")
    log("-" * 100)
    log("Version: " + str(version))

    if input_count == 0:
        extended_format = True
        flags = ord(block_file.read(1))
        cut_end1 = block_file.tell()
        if flags != 0:
            input_count = read_var_int(block_file)
            log("\nInput Count: " + str(input_count))
            for input_index in range(0, input_count):
                input_ids.append(read_input(block_file))
            output_count = read_var_int(block_file)
            for output_index in range(0, output_count):
                output_ids.append(read_output(block_file))
    else:
        cut_start1 = 0
        cut_end1 = 0
        log("\nInput Count: " + str(input_count))
        for input_index in range(0, input_count):
            input_ids.append(read_input(block_file))
        output_count = read_var_int(block_file)
        log("\nOutput Count: " + str(output_count))
        for output_index in range(0, output_count):
            output_ids.append(read_output(block_file))

    cut_start2 = 0
    cut_end2 = 0
    if extended_format:
        if flags & 1:
            cut_start2 = block_file.tell()
            for input_index in range(0, input_count):
                count_of_stack_items = read_var_int(block_file)
                for stackItemIndex in range(0, count_of_stack_items):
                    stack_length = read_var_int(block_file)
                    stack_item = block_file.read(stack_length)[::-1]
                    log("Witness item: " + hex2str(stack_item))
            cut_end2 = block_file.tell()

    lock_time = hex2int(read_int_little_endian(block_file))
    if lock_time < 500000000:
        log("\nLock Time is Block Height: " + str(lock_time))
    else:
        log("\nLock Time is Timestamp: " + datetime.datetime.fromtimestamp(lock_time).strftime('%d.%m.%Y %H:%M'))

    end_byte = block_file.tell()
    block_file.seek(begin_byte)
    length_to_read = end_byte - begin_byte
    data_to_hash_for_transaction_id = block_file.read(length_to_read)
    if extended_format and cut_start1 != 0 and cut_end1 != 0 and cut_start2 != 0 and cut_end2 != 0:
        data_to_hash_for_transaction_id = data_to_hash_for_transaction_id[ :(cut_start1 - begin_byte)] + data_to_hash_for_transaction_id[(cut_end1 - begin_byte):( cut_start2 - begin_byte)] + data_to_hash_for_transaction_id[(cut_end2 - begin_byte):]
    elif extended_format:
        print(cut_start1, cut_end1, cut_start2, cut_end2)
        quit()
    first_hash = hashlib.sha256(data_to_hash_for_transaction_id)
    second_hash = hashlib.sha256(first_hash.digest())
    hash_little_endian = second_hash.hexdigest()
    hash_transaction = string_little_endian_to_big_endian(binascii.unhexlify(hash_little_endian))
    log("\nHash Transaction: " + str(hash_transaction))
    if extended_format:
        print(hash_transaction)


def read_block(block_file):
    magic_number = binascii.hexlify(block_file.read(4))
    try:
        block_size = hex2int(read_int_little_endian(block_file))
    except RuntimeError:
        return False
    version = hex2int(read_int_little_endian(block_file))
    previous_hash = binascii.hexlify(block_file.read(32))
    merkle_hash = binascii.hexlify(block_file.read(32))
    creation_time_timestamp = hex2int(read_int_little_endian(block_file))
    creation_time = datetime.datetime.fromtimestamp(creation_time_timestamp).strftime('%d.%m.%Y %H:%M')
    bits = hex2int(read_int_little_endian(block_file))
    nonce = hex2int(read_int_little_endian(block_file))
    count_of_transactions = read_var_int(block_file)

    log("Magic Number: " + str(magic_number))
    log("Blocksize: " + str(block_size))
    log("Version: " + str(version))
    log("Previous Hash: " + str(previous_hash))
    log("Merkle Hash: " + str(merkle_hash))
    log("Time: " + creation_time)
    log("Bits: " + str(bits))
    log("Nonce: " + str(nonce))
    log("Count of Transactions: " + str(count_of_transactions))

    for transactionIndex in range(0, count_of_transactions):
        read_transaction(block_file)
    return True


def main():
    block_filename = sys.argv[1]
    with open(block_filename, "rb") as blockFile:
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            if not read_block(blockFile):
                break


if __name__ == "__main__":
    main()
