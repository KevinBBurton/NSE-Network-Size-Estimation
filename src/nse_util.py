#!/usr/bin/python3
import struct
import math

from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss

NSE_PROXIMITY = 522
NSE_EARLY_MESSAGE = 523
NSE_BOOTSTRAP_RESPONSE = 525


def calc_estimate(proximity) -> int:
    """
    :param proximity: number of leading overlapping bits between an identifier and a random key
    :return: the expected number of peers in the network based on the proximity
    """
    return int(2 ** (proximity - 0.332747))


def calc_time_to_gossip(periodicity, estimate, last_estimate) -> float:
    """
    :param periodicity: time between two rounds in seconds
    :param estimate: the estimate for which the waiting time is to be calculated
    :param last_estimate: last rounds estimate
    :return: time to wait until the estimate is to be gossiped in seconds
    """
    return periodicity / 2 - periodicity / math.pi * math.atan(estimate - last_estimate)


def sha256_padding(buf) -> bytes:
    """
    Function that pads a buffer for sha256 hashing in accordance to RFC6234
    :param buf: buffer to be padded
    :return: correctly padded buffer
    """
    L = len(buf)
    buf += b'\x80'
    K = 56 - (L + 1) % 64
    for i in range(int(K)):
        buf += b'\x00'

    buf += struct.pack(">Q", L)
    return buf


def proof_of_work(message, identifier, w) -> tuple[bytes, SHA256Hash]:
    """
    Function that calculates proof of work for the estimate announcements
    :param message: the message to be included in the proof of work hash
    :param identifier: node identifier which was calculated by hashing the public key
    :param w: number of leading bytes that have to match in order for valid proof of work
    :return: data of the announcement and the hashed data to be able to get a signature
    """
    while True:
        nonce = get_random_bytes(8)
        data = nonce + message  # append the nonce to the front of the message
        hashed_data = SHA256.new(sha256_padding(data))
        if hashed_data.hexdigest()[:w] == identifier.hexdigest()[:w]:
            return data, hashed_data


def calc_proximity(identifier, round_key) -> int:
    """
    Function that calculates a proximity between an identifier and a round key
    :param identifier: node identifier which was calculated by hashing the public key
    :param round_key: round key derived from the starting time of a round
    :return: leading overlapping bits between the two parameters
    """
    bin_identifier = bin(int(identifier.hexdigest(), base=16))
    bin_round_key = bin(int(round_key.hexdigest(), base=16))

    proximity = 0
    for i in range(len(bin_round_key)):
        if bin_round_key[i] == bin_identifier[i]:
            proximity += 1
        else:
            break

    # the first two chars in the round key and identifier are "0b", so we have to skip those
    return proximity - 2


def verify_messages(data, pub_key, signature, w, round_key, dtype) -> int:
    """
    Function that verifies messages based on their signature, provided proof of work and that the estimate was derived
    using the key of the round and the peer's identifier
    :param data:
    :param pub_key: public key of the sender
    :param signature:
    :param w: number of leading bytes that have to match in order for valid proof of work
    :param dtype: the data type of the message that has to be verified; depending on the data type the estimate is in a
        different field and for bootstrap responses the estimate could have been derived outside an actual estimation round
    """
    hashed_data = SHA256.new(sha256_padding(data))
    verifier = pss.new(pub_key)
    try:
        verifier.verify(hashed_data, signature)
    except ValueError:
        return -1

    identifier = SHA256.new(pub_key.export_key(format='PEM'))

    if not hashed_data.hexdigest()[:w] == identifier.hexdigest()[:w]:
        return -2

    if dtype == NSE_BOOTSTRAP_RESPONSE or dtype == NSE_EARLY_MESSAGE:
        sent_estimate = struct.unpack(">QI", data)[1]
    else:
        sent_estimate = struct.unpack(">Q4sHHI", data)[4]

    if not dtype == NSE_BOOTSTRAP_RESPONSE:
        # first try to verify the proximity with the most recent round key
        proximity = calc_proximity(identifier, round_key)
        if not sent_estimate == calc_estimate(proximity):
            return -3

    return 0
