import asyncio
import binascii
import logging
import scram_lib
import socket
import ssl
import sys
import time
import types

if sys.version_info > (3,):
    buffer = memoryview

def connect(host, port, loop):
    return loop.run_until_complete(_connect(host, port))

@asyncio.coroutine
def _connect(host, port, loop = None):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    connection = yield from asyncio.open_connection(host, port,
                                                    ssl=ctx, loop=loop)
    return connection

def disconnect(writer, loop):
    return loop.run_until_complete(_disconnect(writer))

@asyncio.coroutine
def _disconnect(writer):
    try:
        writer.close()
        return True
    except:
        logging.error('Writer cannot be closed, exception: {}'.format(sys.exc_info()[0]))
        raise

def authenticate(username, password, reader, writer, loop):
    return loop.run_until_complete(
            _authenticate(username, password, reader, writer))

@asyncio.coroutine
def _authenticate(username, password, reader, writer):
    logging.debug('Scram authenticate called...')
    state = {}

    state['username'] = scram_lib.nameprep(username)
    state['password'] = scram_lib.nameprep(password)

    state = scram_lib.clientFirstMessage(state)
    logging.debug('Client first message: {}'.format(state['client_first_msg']))
    buffer_ = state['client_first_msg']

    logging.debug('Sending client first message')
    status = yield from sendMessage(writer, bytes(buffer_, 'utf-8'))
    logging.debug('Sent client first message')

    logging.debug('Receiving server first message')
    received_data = yield from receiveMessage(reader)
    response = received_data.strip()
    logging.debug('Received server first message: {}'.format(response))
    state['server_first_msg'] = response

    state = scram_lib.parse(response, state)

    state = scram_lib.clientFinalMessage(state)
    logging.debug('Client final message: {}'.format(state['client_final_msg']))

    buffer_ = state['client_final_msg']
    logging.debug('Sending client final message')
    status = yield from sendMessage(writer, bytes(buffer_, 'ascii'))
    logging.debug('Sent client final message')

    logging.debug('Receiving server final message')
    received_data = yield from receiveMessage(reader)
    response = received_data.strip()
    logging.debug('Received server final message: {}'.format(response))

    state = scram_lib.parse(response, state)

    if scram_lib.verifyServerSignature(state):
        logging.debug('Authentication succeeded.')
        return True
    else:
        logging.error('Authentication failed.')
        return False

@asyncio.coroutine
def sendMessage(writer, msg):
    writer.write(msg)
    result = yield from writer.drain()
    return result

@asyncio.coroutine
def receiveMessage(reader, timeout = 0):
    total_data = []
    to = None
    #recv something
    while True:
        logging.debug('in while.. ')
        coro = asyncio.Task(reader.read(4096))
        try:

            data = yield from asyncio.wait_for(coro, timeout=to)
            logging.debug('in while after yield from.. ')
            if data:
                total_data.append(data)
                to = timeout
        except asyncio.TimeoutError:
            logging.debug('timeout after 0.. ')
            # Docs say: "When a timeout occurs, it cancels the task
            # and raises asyncio.TimeoutError."
            # But it doesn't cancel! So we cancel here.
            coro.cancel()
            break

    response = b''.join(total_data)
    logging.debug('recv data: {}'.format(response))
    return response

# For testing.
if __name__ == "__main__":
    scram_lib.setup_logging()
    host = '192.168.211.166'
    port = 8887
    username = password = 'admin'
    # test_scram(host, port, username, password)
    loop = asyncio.get_event_loop()
    (reader, writer)  = connect(host, port, loop = loop)
    authenticate(username, password, reader, writer, loop = loop)
    disconnect(writer, loop = loop)
    loop.close()
