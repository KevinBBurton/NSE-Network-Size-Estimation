#!/usr/bin/python3
import argparse
import asyncio
import configparser
import math
import socket
import struct
import sys
import time
import hexdump

import nse_util
from collections import deque
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss

# Message types
NSE_QUERY = 520
NSE_ESTIMATE = 521
NSE_PROXIMITY = 522
NSE_EARLY_MESSAGE = 523
NSE_BOOTSTRAP_REQUEST = 524
NSE_BOOTSTRAP_RESPONSE = 525

GOSSIP_ANNOUNCE = 500
GOSSIP_NOTIFY = 501
GOSSIP_NOTIFICATION = 502
GOSSIP_VALIDATION = 503


async def handle_nse_query(buf, reader, writer):
    """
    Function that handles messages of type 520 (QUERY)
    The calling client receives an answer of type 521 (ESTIMATE) containing the most recent estimate and the standard deviation over all estimates
    :param buf:
    :param reader:
    :param writer:
    """

    raddr, rport = writer.get_extra_info('socket').getpeername()
    print(f"[NSE] {raddr}:{rport} >>> NSE_QUERY")

    # wait until there is an actual bootstrapped value to respond with
    while NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 1] == 1:
        await asyncio.sleep(1)

    # since there is always a round going on and the current value is always subject to change, the second to last value
    # is used and the last value is taken out of the calculation
    async with HISTORY_LOCK:
        estimate = NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 2]
        history_list = [i for i in NSE_HISTORY_QUEUE]
        del history_list[len(history_list) - 1]

    mean = sum(history_list) / len(history_list)
    variance = sum(((x - mean) ** 2) for x in history_list) / len(history_list)
    std_deviation = int(math.sqrt(variance))

    answer = struct.pack(">HHII", 12, NSE_ESTIMATE,
                         estimate,
                         std_deviation)
    async with WRITER_LOCK:
        writer.write(answer)
        await writer.drain()

    print(f"[NSE] {raddr}:{rport} <<< NSE_ESTIMATE(Estimate: {estimate}, Std deviation: {std_deviation})")


async def handle_early_message(buf, reader, writer):
    """
    Function responsible for handling messages of type 523 (NSE_EARLY_MESSAGE) which occur whenever we send out an estimate
    too early and contain a higher estimate
    """

    raddr, rport = writer.get_extra_info('socket').getpeername()
    print(f"[NSE] {raddr}:{rport} >>> NSE_EARLY_MESSAGE")

    body = buf[4:]
    packed_data = body[:12]
    signature = body[12:524]
    pub_key = RSA.import_key(body[524:1323])

    verif_code = nse_util.verify_messages(packed_data, pub_key, signature, W, CURRENT_ROUND_KEY,
                                          dtype=NSE_EARLY_MESSAGE)
    n = 1  # how much has to be subtracted from the length of the queue to receive the current round's estimate
    if verif_code == -1:
        print(f"[NSE] {raddr}:{rport} >>> Signature verification failed")
        return
    elif verif_code == -2:
        print(f"[NSE] {raddr}:{rport} >>> Proof of work verification failed")
        return
    elif verif_code == -3:
        # if the round key verification fails for the current key, maybe the estimate was calculated using
        # the previous round's key and the message was just received late
        if nse_util.verify_messages(packed_data, pub_key, signature, W, LAST_ROUND_KEY,
                                              dtype=NSE_EARLY_MESSAGE) < 0:
            print(f"[NSE] {raddr}:{rport} >>> Round key verification failed, discarding message")
            return
        else:
            # in case it was the previous rounds key we have to consider the estimate from the last round
            n = 2

    estimate = struct.unpack(">QI", packed_data)[1]

    async with HISTORY_LOCK:
        last_estimate = NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - n]
        if last_estimate is None or estimate > last_estimate:
            NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - n] = estimate
        else:
            NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - n] = last_estimate


async def handle_nse_bootstrap_response(buf, reader, writer):
    raddr, rport = writer.get_extra_info('socket').getpeername()
    print(f"[NSE] {raddr}:{rport} >>> NSE_BOOTSTRAP_RESPONSE")

    body = buf[4:]
    packed_data = body[:12]
    signature = body[12:524]
    pub_key = RSA.import_key(body[524:1323])

    # when bootstrapping there is no round key available, and since we don't need to verify the calculation
    # was done using it, we simply pass None
    verif_code = nse_util.verify_messages(packed_data, pub_key, signature, W, round_key=None,
                                          dtype=NSE_BOOTSTRAP_RESPONSE)
    if verif_code == -1:
        print(f"[NSE] {raddr}:{rport} >>> Signature verification failed during bootstrapping")
        return
    elif verif_code == -2:
        print(f"[NSE] {raddr}:{rport} >>> Proof of work verification failed during bootstrapping")
        return

    estimate = struct.unpack(">QI", packed_data)[1]

    # we overwrite the estimate only in case it is 1 as that is the value written at initialization
    # therefore the value is only overwritten once
    async with HISTORY_LOCK:
        if NSE_HISTORY_QUEUE[0] == 1 and estimate > NSE_HISTORY_QUEUE[0]:
            print(f"[NSE] Got a bootstrap estimate of {estimate}")
            NSE_HISTORY_QUEUE[0] = estimate


async def handle_nse_bootstrap_request(buf, reader, writer):
    raddr, rport = writer.get_extra_info('socket').getpeername()
    print(f"[NSE] {raddr}:{rport} >>> GOSSIP_NOTIFICATION | NSE_BOOTSTRAP_REQUEST")

    header = struct.unpack(">HHHH", buf[:8])
    body = struct.unpack(">4sHH", buf[8:16])
    mid = header[2]  # message id

    answer = struct.pack(">HHHH", 8, GOSSIP_VALIDATION, mid, 1)
    async with WRITER_LOCK:
        writer.write(answer)
        await writer.drain()

    ip = socket.inet_ntoa(body[0])
    port = body[2]

    async with HISTORY_LOCK:
        estimate = NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 1]
        if estimate is None:
            estimate = NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 2]

    # the bootstrap response consists of a header, the estimate, a random nonce for proof of work, a signature and the public key of the responder
    header = struct.pack(">HH", 4 + 4 + 8 + 512 + 799, NSE_BOOTSTRAP_RESPONSE)
    data, hashed_data = nse_util.proof_of_work(struct.pack(">I", estimate), IDENTIFIER, W)

    signature = pss.new(HOSTKEY).sign(hashed_data)
    header += data
    header += signature
    header += HOSTKEY.public_key().export_key(format='PEM')
    print(f"[NSE] {ip}:{port} <<< NSE_BOOTSTRAP_RESPONSE")

    reader, writer = await asyncio.open_connection(host=ip, port=port)
    writer.write(header)
    await writer.drain()
    writer.close()


async def handle_nse_proximity(buf, reader, writer):
    raddr, rport = writer.get_extra_info('socket').getpeername()
    print(f"[NSE] {raddr}:{rport} >>> GOSSIP_NOTIFICATION | NSE_PROXIMITY")

    header = struct.unpack(">HHHH", buf[:8])
    mid = header[2]  # message id

    body = buf[8:]
    packed_data = body[:20]
    signature = body[20:532]
    pub_key = RSA.import_key(body[532:1331])

    try:
        verif_code = nse_util.verify_messages(packed_data, pub_key, signature, W, CURRENT_ROUND_KEY, dtype=NSE_PROXIMITY)
        n = 1  # see handle_early_message for explanation of this variable
        if verif_code < 0:
            if verif_code == -1:
                print(f"[NSE] {raddr}:{rport} >>> Signature verification failed")

            elif verif_code == -2:
                print(f"[NSE] {raddr}:{rport} >>> Proof of work verification failed")

            elif verif_code == -3:
                if nse_util.verify_messages(packed_data, pub_key, signature, W, LAST_ROUND_KEY,
                                            dtype=NSE_EARLY_MESSAGE) < 0:
                    print(f"[NSE] {raddr}:{rport} >>> Round key verification failed, discarding message")
                else:
                    n = 2

            if n != 2:
                answer = struct.pack(">HHHH", 8, GOSSIP_VALIDATION, mid, 0)
                async with WRITER_LOCK:
                    writer.write(answer)
                    await writer.drain()
                    return

    # this would occur when another peer sends a proximity when we haven't yet started our first round
    except Exception:
        return

    answer = struct.pack(">HHHH", 8, GOSSIP_VALIDATION, mid, 1)

    async with WRITER_LOCK:
        writer.write(answer)
        await writer.drain()

    data = struct.unpack(">Q4sHHI", packed_data)
    peer_ip = socket.inet_ntoa(data[1])
    peer_port = data[3]
    estimate = data[4]

    async with HISTORY_LOCK:
        last_estimate = NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - n]
    # in the case of the last estimate and the received estimate being the same we don't have to do anything
    # this occurs for example if we got our own original announcement back through another node relaying the estimate
    if last_estimate is None or estimate > last_estimate:
        # in case the received estimate is higher than current one we write it into the queue and begin to gossip that new best estimate to our peers at the appropriate time
        # because of being constrained by gossip we cannot realize the peer specific random delay proposed by Evans et al.
        print(f"[NSE] Writing estimate of {estimate} to storage")
        async with HISTORY_LOCK:
            NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - n] = estimate

        # simply announce the same message we got
        header = struct.pack(">HHBBH", 8 + 20 + 512 + 799, GOSSIP_ANNOUNCE, 0, 0, NSE_PROXIMITY)
        buf = header + body

        gossip_addr, gossip_port = writer.get_extra_info('socket').getpeername()
        print(f"[NSE] {gossip_addr}:{gossip_port} <<< GOSSIP_ANNOUNCE | NSE_PROXIMITY")

        # this is here because sometimes gossip will not receive fast enough and part of the announcement is in the validation
        await asyncio.sleep(1)
        async with WRITER_LOCK:
            writer.write(buf)
            await writer.drain()

    elif estimate < last_estimate:
        # in case the estimate is lower we message the peer directly to alert it that a higher estimate already exists
        message = struct.pack(">I", estimate)
        data, hashed_data = nse_util.proof_of_work(message, IDENTIFIER, W)

        signature = pss.new(HOSTKEY).sign(hashed_data)

        buf = struct.pack(">HH", 4 + 12 + 512 + 799, NSE_EARLY_MESSAGE)
        buf += data
        buf += signature
        buf += HOSTKEY.public_key().export_key(format='PEM')
        print(f"[NSE] {peer_ip}:{peer_port} <<< NSE_EARLY_MESSAGE")

        reader, writer = await asyncio.open_connection(host=peer_ip, port=peer_port)
        writer.write(buf)
        await writer.drain()
        writer.close()


async def read_gossip_notification(reader, writer):
    """
    Function responsible for handling GOSSIP_NOTIFICATION messages and discriminating them into either NSE_PROXIMITY or NSE_BOOTSTRAP
    """
    while True:
        msizebuf = await reader.read(2)
        buflen = struct.unpack(">H", msizebuf)[0]
        buf = msizebuf + await reader.read(buflen)

        raddr, rport = writer.get_extra_info('socket').getpeername()

        header = struct.unpack(">HHHH", buf[:8])
        dtype = header[3]
        mid = header[2]  # message id

        if dtype == NSE_PROXIMITY:
            asyncio.create_task(handle_nse_proximity(buf, reader, writer))
        elif dtype == NSE_BOOTSTRAP_REQUEST:
            asyncio.create_task(handle_nse_bootstrap_request(buf, reader, writer))
        else:
            print(f"[NSE] {raddr}:{rport} >>> Unknown data type when gossip notification was expected")
            hexdump.hexdump(buf)
            answer = struct.pack(">HHHH", 8, GOSSIP_VALIDATION, mid, 0)
            async with WRITER_LOCK:
                writer.write(answer)
                await writer.drain()


async def handler(reader, writer):
    msizebuf = await reader.read(2)
    buflen = struct.unpack(">H", msizebuf)[0]
    buf = msizebuf + await reader.read(buflen)

    header = buf[:4]

    mtype = struct.unpack(">HH", header)[1]
    if mtype == NSE_QUERY:
        asyncio.create_task(handle_nse_query(buf, reader, writer))
    elif mtype == NSE_EARLY_MESSAGE:
        asyncio.create_task(handle_early_message(buf, reader, writer))
    elif mtype == NSE_BOOTSTRAP_RESPONSE:
        asyncio.create_task(handle_nse_bootstrap_response(buf, reader, writer))


async def nse_round_coro(goss_reader, goss_writer):
    """
    Function responsible for calculating the proximity of a random key generated by hashing the time of the round and a node identifier
    represented by the hashed public key of the node, and for a GOSSIP_ANNOUNCE with datatype 522 (NSE_PROXIMITY) containing that information.
    The GOSSIP_ANNOUNCE has to contain at least the port of the respective NSE module to make it possible to answer in case of detected clock skew
    """
    # have both the last and the current round keys available for verification of received estimates
    global CURRENT_ROUND_KEY
    CURRENT_ROUND_KEY = None
    global LAST_ROUND_KEY

    # because the time until gossip is dependent on the last estimate, we need to wait until we got a bootstrapping estimate
    # otherwise this peer will send announcements with low estimates very early in the round
    while not NSE_HISTORY_QUEUE[0] > 1:
        await asyncio.sleep(1)

    while True:
        # the round key used for proximity generation is needed during the round for verification, but to calculate
        # the proximity of the next round the next rounds key is needed
        current_time = int(time.time())
        next_round_key = SHA256.new(bytes(current_time + (NSE_FREQ - current_time % NSE_FREQ)))

        proximity = nse_util.calc_proximity(IDENTIFIER, next_round_key)

        estimate = nse_util.calc_estimate(proximity)
        message = struct.pack(">4sHHI", socket.inet_aton(NSE_ADDR), 0, NSE_PORT, estimate)
        data, hashed_data = nse_util.proof_of_work(message, IDENTIFIER, W)

        # cryptographically sign the data
        signature = pss.new(HOSTKEY).sign(hashed_data)
        # TTL is irrelevant here since the Gossip mockup module doesn't use it
        # for a real gossip we'd have to calculate an appropriate TTL based on the last estimation
        buf = struct.pack(">HHBBH", 8 + 20 + 512 + 799, GOSSIP_ANNOUNCE, 0, 0, NSE_PROXIMITY)
        # adding the public key so that the receiver can verify the signature
        buf += data  # 20B of data: 8B Nonce, 4B IP, 2B Port, 2B reserved, 4B Proximity
        buf += signature  # 512B
        buf += HOSTKEY.public_key().export_key(format='PEM')  # 799B

        time_to_round = NSE_FREQ - time.time() % NSE_FREQ
        print(f"[NSE] Time to next round: {int(time_to_round)} seconds")

        await asyncio.sleep(time_to_round)
        # await the waiting and gossip of the last round in case it somehow is too late, which otherwise would result
        # in it gossiping because it sees the none of the new round in the queue
        # furthermore we await its completion so in the case that everybody gets a very bad proximity then we need a
        # last estimate for the next round, and that is then provided by that task
        try:
            await task
        except Exception:
            pass

        # calculate the time to gossip at the start of a new round so that it is assured that the last estimate is final
        async with HISTORY_LOCK:
            last_estimate = NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 1]
            time_to_gossip = nse_util.calc_time_to_gossip(NSE_FREQ, estimate, last_estimate)

            # append None at the start of the round which is overwritten when a new proximity is received
            NSE_HISTORY_QUEUE.append(None)

        LAST_ROUND_KEY = CURRENT_ROUND_KEY
        CURRENT_ROUND_KEY = next_round_key

        # moved the waiting and then announcing into its own function to enable it to be async, so that the NSE can
        # already do the necessary calculations for the next round
        task = asyncio.create_task(wait_and_gossip(time_to_gossip, estimate, goss_reader, goss_writer, buf))


async def wait_and_gossip(time_to_gossip, estimate, goss_reader, goss_writer, buf):
    # for some reason the sleep time was off and this function waited too long, therefore the time that has passed
    # since the round has started is calculated and taken away from the time to gossip
    passed_time = time.time() % NSE_FREQ
    await asyncio.sleep(time_to_gossip - passed_time)

    # we only gossip our calculated estimate in the case we haven't already received one that's higher
    # when we get to gossip our own estimate we assume that it is the highest
    async with HISTORY_LOCK, WRITER_LOCK:
        current_estimate = NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 1]
        if current_estimate is None or estimate > current_estimate:
            print(f"[NSE] Writing estimate of {estimate} to storage")
            NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 1] = estimate
            gossip_addr, gossip_port = goss_writer.get_extra_info('socket').getpeername()
            print(f"[NSE] {gossip_addr}:{gossip_port} <<< GOSSIP_ANNOUNCE | NSE_PROXIMITY")
            goss_writer.write(buf)
            await goss_writer.drain()


async def main() -> int:
    global NSE_ADDR
    global NSE_PORT
    global NSE_FREQ  # frequency of rounds given in seconds between rounds
    global NSE_HISTORY_QUEUE, HISTORY_LOCK  # queue containing estimates and a lock for it
    global W  # number of leading bytes necessary to provide a valid proof of work
    global HOSTKEY
    global IDENTIFIER

    cmd = argparse.ArgumentParser()
    parser = configparser.ConfigParser()
    cmd.add_argument("-c", "--config",
                     help="Path to a valid .ini configuration file")

    args = cmd.parse_args()

    if args.config is not None:
        parser.read(args.config)
    else:
        parser.read('default.ini')

    try:
        NSE_ADDR, NSE_PORT = parser.get('nse', 'api_address').split(':')
        NSE_PORT = int(NSE_PORT)
        NSE_FREQ = parser.getint('nse', 'frequency')
        nse_history_size = parser.getint('nse', 'history_size')
        W = parser.getint('nse', 'w')

        gossip_addr , gossip_port = parser.get('gossip', 'api_address').split(':')
        gossip_port = int(gossip_port)

        # if the hostkey line is omitted in the .ini file we generate one and write it to a new file
        if parser.has_option('key', 'hostkey'):
            keyfile = parser.get('key', 'hostkey')
            HOSTKEY = RSA.import_key(open(keyfile, 'rb').read())
        else:
            HOSTKEY = RSA.generate(4096)
            file_out = open("nse_hostkey.pem", "wb")
            file_out.write(HOSTKEY.export_key(format='PEM'))
            file_out.close()

    except Exception as e:
        print(f"[NSE] Couldn't parse .ini config file: {e}")
        return -1
    except FileNotFoundError as e:
        print(f"[NSE] Couldn't find .pem file containing hostkey: {e}")
        return -1

    # generate the node identifier by hashing the node's public key
    IDENTIFIER = SHA256.new(HOSTKEY.public_key().export_key(format='PEM'))
    NSE_HISTORY_QUEUE = deque(maxlen=nse_history_size)
    HISTORY_LOCK = asyncio.Lock()

    # bootstrapping

    # communication is done using two reader and writer pairs, so that we don't get behavior where gossip doesn't receive
    # quick enough and reads part of the other messages as it would be all one stream

    # everyone has to subscribe to NSE_BOOTSTRAP notifications to be able to answer new peers with estimates
    boot_reader, boot_writer = await asyncio.open_connection(host=gossip_addr, port=gossip_port)
    buf = struct.pack(">HHHH", 8, GOSSIP_NOTIFY, 0, NSE_BOOTSTRAP_REQUEST)
    boot_writer.write(buf)
    await boot_writer.drain()

    # subscribe to NSE_PROXIMITY notifications and set up a lock on the writer
    global WRITER_LOCK
    WRITER_LOCK = asyncio.Lock()
    try:
        goss_reader, goss_writer = await asyncio.open_connection(host=gossip_addr, port=gossip_port)
    except socket.error as e:
        print(f"[NSE] Couldn't connect to gossip, shutting down: {e}")
        return -1

    buf = struct.pack(">HHHH", 8, GOSSIP_NOTIFY, 0, NSE_PROXIMITY)
    goss_writer.write(buf)
    await goss_writer.drain()

    print(
        f"[NSE] Communicating with Gossip on {boot_writer.get_extra_info('socket').getsockname()} and {goss_writer.get_extra_info('socket').getsockname()}")

    # append 1 as the first value which is then overwritten by answers to the NSE_BOOTSTRAP_REQUEST
    NSE_HISTORY_QUEUE.append(1)

    # start the main server
    serv = await asyncio.start_server(handler,
                                      host=NSE_ADDR, port=NSE_PORT,
                                      family=socket.AddressFamily.AF_INET,
                                      reuse_address=True,
                                      reuse_port=True)
    print(f"[NSE] Listening on {NSE_ADDR}:{NSE_PORT}")

    # bootstrapping request announcement to receive the first estimate
    buf = struct.pack(">HHBBH4sHH", 16, GOSSIP_ANNOUNCE, 0, 0, NSE_BOOTSTRAP_REQUEST, socket.inet_aton(NSE_ADDR), 0,
                      NSE_PORT)
    print(f"[NSE] {gossip_addr}:{gossip_port} <<< GOSSIP_ANNOUNCE | NSE_BOOTSTRAP_REQUEST")
    boot_writer.write(buf)

    async with serv:
        await asyncio.gather(
            serv.serve_forever(), nse_round_coro(goss_reader, goss_writer),
            read_gossip_notification(goss_reader, goss_writer), read_gossip_notification(boot_reader, boot_writer)
        )


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n[NSE] Received SIGINT, shutting down...")
        sys.exit(0)
