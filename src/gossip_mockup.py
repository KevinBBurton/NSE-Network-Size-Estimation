#!/usr/bin/python3

import argparse
import asyncio
import hexdump
import random
import socket
import struct

from gossip_util import bad_packet, read_message, handle_client

GOSSIP_ADDR = 'localhost'
GOSSIP_PORT = 7001

GOSSIP_ANNOUNCE = 500
GOSSIP_NOTIFY = 501
GOSSIP_NOTIFICATION = 502
GOSSIP_VALIDATION = 503

# This map maps a (reader,writer) pair to the state in which the client resides.
# So conn_state_map := {(reader,writer) : state}
# State s is defined as a dictionary of existing subscriptions to message types,
# mapping to their validity:  {mtype:valid} where valid is of type BOOL
conn_state_map = {}
state_map_lock = None

# This map maps a (reader,writer) pair to a state-dict of open notification
# request message IDs, the connection has to reply to in the future.
# So conn_state_map := {(reader,writer) : MIDstate}
# MIDState s is defined a dictionary of open MIDs to message types:  {MID:dtype}
conn_mid_map = {}
mid_map_lock = None

async def add_mid(conn, mid, dtype):
    global conn_mid_map, mid_map_lock
    async with mid_map_lock:
        try:
            state = conn_mid_map[conn]

            if mid in state.keys():
                return

            state[mid] = dtype

        except KeyError:
            state = {mid:dtype}
            conn_mid_map[conn] = state

async def add_subscription(conn, dtype):
    global conn_state_map, state_map_lock
    async with state_map_lock:
        try:
            state = conn_state_map[conn]

            if dtype in state.keys():
                return

            state[dtype] = False

        except KeyError:
            state = {dtype:False}
            conn_state_map[conn] = state

async def clear_state(conn):
    global conn_state_map, state_map_lock, conn_mid_map, mid_map_lock
    async with state_map_lock:
        try:
            conn_state_map.pop(conn)
        except KeyError:
            pass
    async with mid_map_lock:
        try:
            conn_mid_map.pop(conn)
        except KeyError:
            pass

async def is_subscribed(conn, dtype):
    global conn_state_map, state_map_lock
    async with state_map_lock:
        try:
            state = conn_state_map[conn]
            if dtype in state.keys():
                return True

        except KeyError:
            pass

        return False

async def get_subscribers_of(dtype):
    global conn_state_map, state_map_lock
    subscribers = []

    async with state_map_lock:
        for conn in conn_state_map:
            state = conn_state_map[conn]

            if dtype in state.keys():
                subscribers.append(conn)

    return subscribers

async def update_validation_state(conn, mid, valid):
    global conn_state_map, state_map_lock, conn_mid_map, mid_map_lock
    async with mid_map_lock:
        try:
            state = conn_mid_map[conn]
        except KeyError:
            return False

        if mid not in state.keys():
            return False

        dtype = state.pop(mid)

    async with state_map_lock:
        try:
            state = conn_state_map[conn]

            if dtype in state.keys():
                state[dtype] = valid
                return True

        except KeyError:
            pass

    return False

async def send_gossip_notification(conn, dtype, data):
    reader, writer = conn
    raddr, rport = writer.get_extra_info('socket').getpeername()

    mid = random.randint(0, 65535)
    msize = 8 + len(data)
    msg = struct.pack(">HHHH",
                      msize,
                      GOSSIP_NOTIFICATION,
                      mid,
                      dtype)
    msg += data

    await writer.drain()
    if not writer.is_closing():
        writer.write(msg)
        await writer.drain()
        print(f"[Gossip] {raddr}:{rport} <<< GOSSIP_NOTIFICATION("
              + f"{mid}, {dtype})")
        await add_mid(conn, mid, dtype)
    else:
        await bad_packet(reader, writer, cleanup_func=clear_state)

async def gossip_to_subscribers(dtype, data, originator):
    subs = await get_subscribers_of(dtype)
    for sub in subs:
        if sub != originator:
            await send_gossip_notification(sub, dtype, data)

async def handle_gossip_announce(buf, reader, writer):
    raddr, rport = writer.get_extra_info('socket').getpeername()
    header = buf[:4]
    body = buf[4:]

    msize = struct.unpack(">HH", header)[0]

    if msize <= 8 or len(buf) != msize:
        await bad_packet(reader, writer,
                         reason='GOSSIP_ANNOUNCE with datasize = 0 received',
                         data=buf,
                         cleanup_func=clear_state)
        return False

    ttl, mres, dtype = struct.unpack(">BBH", body[:4])
    mdata = body[4:]


    if not await is_subscribed((reader, writer), dtype):
        await bad_packet(reader, writer,
                         reason=f"GOSSIP_ANNOUNCE for unregistered type {dtype}",
                         data=buf,
                         cleanup_func=clear_state)
        return False

    print(f"[Gossip] {raddr}:{rport} >>> GOSSIP_ANNOUNCE: ({dtype})")

    await gossip_to_subscribers(dtype, mdata, (reader,writer))
    return True

async def handle_gossip_notify(buf, reader, writer):
    raddr, rport = writer.get_extra_info('socket').getpeername()
    header = buf[:4]
    body = buf[4:]

    msize = struct.unpack(">HH", header)[0]

    if msize != 8 or msize != len(buf):
        await bad_packet(reader, writer,
                         reason="Invalid size for GOSSIP_NOTIFY",
                         data=buf,
                         cleanup_func=clear_state)
        return False

    res, dtype = struct.unpack(">HH", body)
    await add_subscription((reader,writer), dtype)

    print(f"[Gossip] {raddr}:{rport} >>> GOSSIP_NOTIFY registered: ({dtype})")
    return True

async def handle_gossip_validation(buf, reader, writer):
    raddr, rport = writer.get_extra_info('socket').getpeername()
    header = buf[:4]
    body = buf[4:]

    msize = struct.unpack(">HH", header)[0]

    if msize != 8 or msize != len(buf):
        await bad_packet(reader, writer,
                         reason="Invalid size for GOSSIP_VALIDATION",
                         data=buf,
                         cleanup_func=clear_state)
        return False

    mid, res, valid = struct.unpack(">HBB", body)
    valid = True if valid > 0 else False

    print(f"[Gossip] {raddr}:{rport} >>> GOSSIP_VALIDATION: ({mid}:{valid})")

    if not await update_validation_state((reader,writer), mid, valid):
        await bad_packet(reader, writer,
                         reason="GOSSIP_VALIDATION for nonexisting subscription",
                         data=buf,
                         cleanup_func=clear_state)
        return False

    return True

async def handle_message(buf, reader, writer):
    ret = False
    header = buf[:4]
    body = buf[4:]

    mtype = struct.unpack(">HH", header)[1]
    if mtype == GOSSIP_ANNOUNCE:
        ret = await handle_gossip_announce(buf, reader, writer)
    elif mtype == GOSSIP_NOTIFY:
        ret = await handle_gossip_notify(buf, reader, writer)
    elif mtype == GOSSIP_NOTIFICATION:
        await bad_packet(reader, writer,
                         f"Received illegal GOSSIP_NOTIFICATION from client.",
                         header)
    elif mtype == GOSSIP_VALIDATION:
        ret = await handle_gossip_validation(buf, reader, writer)
    else:
        await bad_packet(reader, writer,
                         f"Unknown message type {mtype} received",
                         header)
    return ret

def main():
    host = GOSSIP_ADDR
    port = GOSSIP_PORT

    # parse commandline arguments
    usage_string = ("Run a GOSSIP module mockup with local info exchange.\n\n"
                   + "Multiple API clients can connect to this same instance.")
    cmd = argparse.ArgumentParser(description=usage_string)
    cmd.add_argument("-a", "--address",
                     help="Bind server to this address")
    cmd.add_argument("-p", "--port",
                     help="Bind server to this port")
    args = cmd.parse_args()

    if args.address is not None:
        host = args.address

    if args.port is not None:
        port = args.port

    # setup state locks
    global state_map_lock, mid_map_lock
    state_map_lock = asyncio.Lock()
    mid_map_lock = asyncio.Lock()

    # create asyncio server to listen for incoming API messages
    loop = asyncio.get_event_loop()
    handler = (lambda r,
                      w,
                      mhandler=handle_message,
                      cleanup=clear_state: handle_client(r,w,mhandler,cleanup))

    serv = asyncio.start_server(handler,
                                host=host, port=port,
                                family=socket.AddressFamily.AF_INET,
                                reuse_address=True,
                                reuse_port=True)
    loop.create_task(serv)
    print(f"[Gossip] GOSSIP mockup listening on {host}:{port}")

    try:
        loop.run_forever()
    except KeyboardInterrupt as e:
        print("[Gossip] Received SIGINT, shutting down...")
        loop.stop()

if __name__ == '__main__':
    main()
