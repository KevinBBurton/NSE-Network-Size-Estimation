#!/usr/bin/python3
import argparse
import asyncio
import configparser
import random
import socket
import struct
import time
import hexdump
import sys
import multiprocessing

import nse_util
import matplotlib.pyplot as pyplot
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


async def handle_early_message(buf, reader, writer):
    raddr, rport = writer.get_extra_info('socket').getpeername()
    print(f"[Test] {raddr}:{rport} >>> EARLY_MESSAGE")

    body = buf[4:]
    packed_data = body[:12]
    signature = body[12:524]
    pub_key = RSA.import_key(body[524:1323])

    verif_code = nse_util.verify_messages(packed_data, pub_key, signature, W, CURRENT_ROUND_KEY,
                                          dtype=NSE_EARLY_MESSAGE)
    n = 1
    if verif_code == -1:
        print(f"[Test] {raddr}:{rport} >>> Signature verification failed")
        return
    elif verif_code == -2:
        print(f"[Test] {raddr}:{rport} >>> Proof of work verification failed")
        return
    elif verif_code == -3:
        if nse_util.verify_messages(packed_data, pub_key, signature, W, LAST_ROUND_KEY,
                                    dtype=NSE_EARLY_MESSAGE) < 0:
            print(f"[Test] {raddr}:{rport} >>> Round key verification failed, discarding message")
            return
        else:
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
    print(f"[Test] {raddr}:{rport} >>> NSE_BOOTSTRAP_RESPONSE")

    body = buf[4:]
    packed_data = body[:12]
    signature = body[12:524]
    pub_key = RSA.import_key(body[524:1323])

    verif_code = nse_util.verify_messages(packed_data, pub_key, signature, W, round_key=None,
                                          dtype=NSE_BOOTSTRAP_RESPONSE)
    if verif_code == -1:
        print(f"[Test] {raddr}:{rport} >>> Signature verification failed during bootstrapping")
        return
    elif verif_code == -2:
        print(f"[Test] {raddr}:{rport} >>> Proof of work verification failed during bootstrapping")
        return

    estimate = struct.unpack(">QI", packed_data)[1]

    print(f"[Test] Bootstrap response with estimate {estimate} received")


async def handle_nse_bootstrap_request(buf, reader, writer):
    raddr, rport = writer.get_extra_info('socket').getpeername()
    print(f"[Test] {raddr}:{rport} >>> GOSSIP_NOTIFICATION | NSE_BOOTSTRAP_REQUEST")

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

    header = struct.pack(">HH", 4 + 4 + 8 + 512 + 799, NSE_BOOTSTRAP_RESPONSE)
    data, hashed_data = nse_util.proof_of_work(struct.pack(">I", estimate), IDENTIFIER, W)

    signature = pss.new(HOSTKEY).sign(hashed_data)
    header += data
    header += signature
    header += HOSTKEY.public_key().export_key(format='PEM')
    print(f"[Test] {ip}:{port} <<< NSE_BOOTSTRAP_RESPONSE")

    reader, writer = await asyncio.open_connection(host=ip, port=port)
    writer.write(header)
    await writer.drain()
    writer.close()


async def handle_nse_proximity(buf, reader, writer):
    raddr, rport = writer.get_extra_info('socket').getpeername()
    print(f"[Test] {raddr}:{rport} >>> GOSSIP_NOTIFICATION | NSE_PROXIMITY")

    header = struct.unpack(">HHHH", buf[:8])
    mid = header[2]  # message id

    body = buf[8:]
    packed_data = body[:20]
    signature = body[20:532]
    pub_key = RSA.import_key(body[532:1331])

    try:
        verif_code = nse_util.verify_messages(packed_data, pub_key, signature, W, CURRENT_ROUND_KEY, dtype=NSE_PROXIMITY)
        n = 1
        if verif_code < 0:
            if verif_code == -1:
                print(f"[Test] {raddr}:{rport} >>> Signature verification failed")

            elif verif_code == -2:
                print(f"[Test] {raddr}:{rport} >>> Proof of work verification failed")

            elif verif_code == -3:
                if nse_util.verify_messages(packed_data, pub_key, signature, W, LAST_ROUND_KEY,
                                            dtype=NSE_EARLY_MESSAGE) < 0:
                    print(f"[Test] {raddr}:{rport} >>> Round key verification failed, discarding message")
                else:
                    n = 2

            if n != 2:
                answer = struct.pack(">HHHH", 8, GOSSIP_VALIDATION, mid, 0)
                async with WRITER_LOCK:
                    writer.write(answer)
                    await writer.drain()
                    return

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

    if last_estimate is None or estimate > last_estimate:
        async with HISTORY_LOCK:
            NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - n] = estimate

        header = struct.pack(">HHBBH", 8 + 20 + 512 + 799, GOSSIP_ANNOUNCE, 0, 0, NSE_PROXIMITY)
        buf = header + body

        gossip_addr, gossip_port = writer.get_extra_info('socket').getpeername()
        print(f"[Test] {gossip_addr}:{gossip_port} <<< GOSSIP_ANNOUNCE | NSE_PROXIMITY")

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
        print(f"[Test] {peer_ip}:{peer_port} <<< NSE_EARLY_MESSAGE")

        reader, writer = await asyncio.open_connection(host=peer_ip, port=peer_port)
        writer.write(buf)
        await writer.drain()
        writer.close()


async def read_nse_estimate(reader, writer):
    """
    Does the same thing as read_gossip_notification but because a new reader/writer pair is generated for every new
    nse query no infinite loop is needed
    """
    msizebuf = await reader.read(2)
    buflen = struct.unpack(">H", msizebuf)[0]
    buf = msizebuf + await reader.read(buflen)

    raddr, rport = writer.get_extra_info('socket').getpeername()

    header = struct.unpack(">HH", buf[:4])
    mtype = header[1]

    if mtype == NSE_ESTIMATE:
        print(f"[Test] {raddr}:{rport} >>> NSE_ESTIMATE")

        body = struct.unpack(">II", buf[4:])
        estimate = body[0]
        std_deviation = body[1]

        ESTIMATE_LIST.append(estimate)
    else:
        print(f"[Test] {raddr}:{rport} >>> Unknown data type when nse estimate was expected")
        hexdump.hexdump(buf)


async def read_gossip_notification(reader, writer):
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
            print(f"[Test] {raddr}:{rport} >>> Unknown data type when gossip notification as expected")
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
    if mtype == NSE_EARLY_MESSAGE:
        asyncio.create_task(handle_early_message(buf, reader, writer))
    elif mtype == NSE_BOOTSTRAP_RESPONSE:
        asyncio.create_task(handle_nse_bootstrap_response(buf, reader, writer))


async def testing_round_coro(nse_addr, nse_port, goss_reader, goss_writer, boot_reader, boot_writer, peer_keys):
    global TEST_PEERS
    global CURRENT_ROUND_KEY
    CURRENT_ROUND_KEY = None
    global LAST_ROUND_KEY

    # wait until the NSE is online
    while True:
        try:
            nse_reader, nse_writer = await asyncio.open_connection(host=nse_addr, port=nse_port)
            print("[Test] NSE online, beginning with test")
            break
        except socket.error:
            await asyncio.sleep(1)
            pass

    # append the starting number of peers to the list that is later used to visualize estimates in a graph
    PEER_LIST.append(TEST_PEERS)

    # instead of the infinite loop in the nse module we loop for the specified number of rounds
    for current_round in range(TEST_ROUNDS):
        # simulating churn using a gaussian distribution with the last round's peers as a mean
        if TEST_CHURN:
            TEST_PEERS = int(random.gauss(TEST_PEERS, 4))

        # append the amount of actual peers to the dict for later comparison with the estimate at the start of each round
        PEER_LIST.append(TEST_PEERS)

        current_time = int(time.time())
        next_round_key = SHA256.new(bytes(current_time + (NSE_FREQ - current_time % NSE_FREQ)))

        # find out how many peers joined or left the network due to churn, if new ones joined, keys have to be
        # generated for them
        cores = multiprocessing.cpu_count()
        new_peers = TEST_PEERS - len(peer_keys)
        if new_peers > 0:
            peer_keys += [None for i in range(new_peers)]
            with multiprocessing.Pool(cores, initializer=worker_init(
                    lambda x: RSA.generate(4096).export_key('PEM') if x is None else x)) as pool:
                mapped = pool.map_async(worker, peer_keys)
                mapped.wait()
                peer_keys = mapped.get()
                pool.close()
                pool.join()
        else:
            # in case some left, the list has to be truncated
            del peer_keys[TEST_PEERS:]

        # calculate the proximities of the peers in the network
        with multiprocessing.Pool(cores,
                                  initializer=worker_init(lambda x: (x,
                                                                     nse_util.calc_proximity(
                                                                         SHA256.new(
                                                                             RSA.import_key(x).public_key().export_key(
                                                                                 format='PEM')),
                                                                         next_round_key)))) as pool:
            mapped = pool.map_async(worker, peer_keys)
            mapped.wait()
            key_estimate_list = mapped.get()
            pool.close()
            pool.join()

        max_proximity = 0
        max_key = None
        for key, prox in key_estimate_list:
            if prox >= max_proximity:
                max_proximity = prox
                max_key = RSA.import_key(key)

        max_pubkey = max_key.public_key().export_key(format='PEM')
        max_identifier = SHA256.new(max_pubkey)

        estimate = nse_util.calc_estimate(max_proximity)

        message = struct.pack(">4sHHI", socket.inet_aton(NSE_TEST_ADDR), 0, NSE_TEST_PORT, estimate)
        data, hashed_data = nse_util.proof_of_work(message, max_identifier, W)
        signature = pss.new(max_key).sign(hashed_data)

        buf = struct.pack(">HHBBH", 8 + 20 + 512 + 799, GOSSIP_ANNOUNCE, 0, 0, NSE_PROXIMITY)
        buf += data  # 20B of data: 8B Nonce, 4B IP, 2B Port, 2B reserved, 4B Proximity
        buf += signature  # 512B
        buf += max_pubkey  # 799B

        async with HISTORY_LOCK:
            last_estimate = NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 1]
            if last_estimate is None:
                last_estimate = NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 2]

        time_to_round = NSE_FREQ - time.time() % NSE_FREQ
        print(f"[Test] Time to next round: {int(time_to_round)} seconds")

        await asyncio.sleep(time_to_round)

        try:
            await task
        except Exception:
            pass

        async with HISTORY_LOCK:
            last_estimate = NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 1]
            time_to_gossip = nse_util.calc_time_to_gossip(NSE_FREQ, estimate, last_estimate)

            print(f"\n[Test] Starting round {current_round + 1} of {TEST_ROUNDS} with {TEST_PEERS} peers")
            print(f"[Test] Estimate for round {current_round + 1}: {estimate}")
            NSE_HISTORY_QUEUE.append(None)

        try:
            LAST_ROUND_KEY = CURRENT_ROUND_KEY
        except Exception:
            pass
        CURRENT_ROUND_KEY = next_round_key

        task = asyncio.create_task(wait_and_gossip(time_to_gossip, estimate, goss_reader, goss_writer, buf))

        # querying the estimate from the nse module
        print(f"[Test] {nse_addr}:{nse_port} <<< NSE_QUERY")
        nse_writer.write(struct.pack(">HH", 4, NSE_QUERY))
        await read_nse_estimate(nse_reader, nse_writer)
        await nse_writer.drain()
        nse_writer.close()
        # a new reader/writer pair has to be created each time, otherwise the handler of the nse won't receive the message
        nse_reader, nse_writer = await asyncio.open_connection(host=nse_addr, port=nse_port)

    # wait for the last round to finish so that the final rounds estimate can be checked against a received bootstrap estimate
    await task
    time_to_round = NSE_FREQ - time.time() % NSE_FREQ
    await asyncio.sleep(time_to_round)

    # get the final rounds estimate
    print(f"[Test] {nse_addr}:{nse_port} <<< NSE_QUERY")
    nse_writer.write(struct.pack(">HH", 4, NSE_QUERY))
    await read_nse_estimate(nse_reader, nse_writer)
    await nse_writer.drain()
    nse_writer.close()

    # sending a bootstrap request to test if the nse responds correctly
    print(f"\n[Test] Announcing testing bootstrap request")
    buf = struct.pack(">HHBBH4sHH", 16, GOSSIP_ANNOUNCE, 0, 0, NSE_BOOTSTRAP_REQUEST, socket.inet_aton(NSE_TEST_ADDR),
                      0,
                      NSE_TEST_PORT)
    boot_writer.write(buf)
    await boot_writer.drain()

    await asyncio.sleep(5)

    pyplot.plot(range(1, len(ESTIMATE_LIST) + 1), ESTIMATE_LIST, label="Estimates")
    pyplot.plot(range(1, len(PEER_LIST) + 1), PEER_LIST, label="Actual Peers")
    pyplot.xlabel("Rounds")
    pyplot.legend()
    pyplot.savefig("chart.png")

    print(
        f"[Test] Testing protocol finished, estimations compared to the actual values can be seen in chart.png, hit CTRL-C to terminate")


async def wait_and_gossip(time_to_gossip, estimate, goss_reader, goss_writer, buf):
    passed_time = time.time() % NSE_FREQ
    await asyncio.sleep(time_to_gossip - passed_time)

    async with HISTORY_LOCK, WRITER_LOCK:
        current_estimate = NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 1]
        if current_estimate is None or estimate > current_estimate:
            NSE_HISTORY_QUEUE[len(NSE_HISTORY_QUEUE) - 1] = estimate
            gossip_addr, gossip_port = goss_writer.get_extra_info('socket').getpeername()
            print(f"[Test] {gossip_addr}:{gossip_port} <<< GOSSIP_ANNOUNCE | NSE_PROXIMITY")
            goss_writer.write(buf)
            await goss_writer.drain()


async def main() -> int:
    global NSE_FREQ
    global NSE_HISTORY_QUEUE, HISTORY_LOCK
    global W
    global HOSTKEY
    global IDENTIFIER

    global NSE_TEST_ADDR
    global NSE_TEST_PORT
    global TEST_PEERS
    global TEST_CHURN
    global TEST_ROUNDS

    # queues for plotting an output graph
    global PEER_LIST, ESTIMATE_LIST

    cmd = argparse.ArgumentParser()
    parser = configparser.ConfigParser()
    cmd.add_argument("-c", "--config",
                     help="Path to a valid .ini configuration file")

    args = cmd.parse_args()

    if args.config is not None:
        parser.read(args.config)
    else:
        parser.read("default.ini")
    try:
        nse_addr, nse_port = parser.get('nse', 'api_address').split(':')
        nse_port = int(nse_port)
        NSE_FREQ = parser.getint('nse', 'frequency')
        nse_history_size = parser.getint('nse', 'history_size')
        W = parser.getint('nse', 'w')

        NSE_TEST_ADDR, NSE_TEST_PORT = parser.get('nse', 'test_address').split(':')
        NSE_TEST_PORT = int(NSE_TEST_PORT)
        TEST_PEERS = parser.getint('nse', 'test_peers')
        TEST_CHURN = parser.getboolean('nse', 'test_churn')
        TEST_ROUNDS = parser.getint('nse', 'test_rounds')

        gossip_addr, gossip_port = parser.get('gossip', 'api_address').split(':')
        gossip_port = int(gossip_port)

        HOSTKEY = RSA.generate(4096)
        file_out = open("test_hostkey.pem", "wb")
        file_out.write(HOSTKEY.export_key(format='PEM'))
        file_out.close()

    except Exception as e:
        print(f"[Test] Couldn't parse .ini config file: {e}")
        return 0

    # initializing the queues to store the estimates and actual values to later create a graph
    # length is the rounds + 1 to account for bootstrap estimate
    PEER_LIST = deque(maxlen=TEST_ROUNDS + 1)
    ESTIMATE_LIST = deque(maxlen=TEST_ROUNDS + 1)

    # the identifier for the testing module is only used whenever an estimate is sent out outside the rounds where
    # peers are simulated, since simulated peers have their own pub key and identifier
    IDENTIFIER = SHA256.new(HOSTKEY.public_key().export_key(format='PEM'))
    NSE_HISTORY_QUEUE = deque(maxlen=nse_history_size)
    HISTORY_LOCK = asyncio.Lock()

    # bootstrapping

    boot_reader, boot_writer = await asyncio.open_connection(host=gossip_addr, port=gossip_port)
    buf = struct.pack(">HHHH", 8, GOSSIP_NOTIFY, 0, NSE_BOOTSTRAP_REQUEST)
    boot_writer.write(buf)
    await boot_writer.drain()

    # subscribe to NSE_PROXIMITY notifications
    global WRITER_LOCK
    WRITER_LOCK = asyncio.Lock()
    goss_reader, goss_writer = await asyncio.open_connection(host=gossip_addr, port=gossip_port)
    buf = struct.pack(">HHHH", 8, GOSSIP_NOTIFY, 0, NSE_PROXIMITY)
    goss_writer.write(buf)
    await goss_writer.drain()

    print(
        f"[Test] Communicating with Gossip on {boot_writer.get_extra_info('socket').getsockname()} and {goss_writer.get_extra_info('socket').getsockname()}")

    # we know the actual number of peers
    NSE_HISTORY_QUEUE.append(TEST_PEERS + 1)

    serv = await asyncio.start_server(handler,
                                      host=NSE_TEST_ADDR, port=NSE_TEST_PORT,
                                      family=socket.AddressFamily.AF_INET,
                                      reuse_address=True,
                                      reuse_port=True)
    print(f"[Test] Listening on {NSE_TEST_ADDR}:{NSE_TEST_PORT}")

    # generate the keys for the peers in advance
    print(f"[Test] Generating keys for {TEST_PEERS} peers, stand by...")
    peer_keys = [None for i in range(TEST_PEERS)]
    with multiprocessing.Pool(multiprocessing.cpu_count(),
                              initializer=worker_init(lambda x: RSA.generate(4096).export_key(format='PEM'))) as pool:
        mapped = pool.map_async(worker, peer_keys)
        mapped.wait()
        peer_keys = mapped.get()
        pool.close()
        pool.join()

    print("[Test] Finished key generation, waiting for NSE...")

    async with serv:
        await asyncio.gather(
            serv.serve_forever(), testing_round_coro(nse_addr, nse_port, goss_reader, goss_writer, boot_reader, boot_writer, peer_keys),
            read_gossip_notification(goss_reader, goss_writer), read_gossip_notification(boot_reader, boot_writer)
        )


# credit to https://medium.com/@yasufumy/python-multiprocessing-c6d54107dd55 , allows the usage of lambdas for multiprocessing
_func = None


def worker_init(func):
    global _func
    _func = func


def worker(x):
    return _func(x)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n[Test] Received SIGINT, shutting down...")
        sys.exit(0)
