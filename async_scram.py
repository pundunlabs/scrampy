# vim: set expandtab:
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

async def authenticate(username, password, reader, writer, loop, retries = 0):
    logging.debug('Scram authentication initiated, number of potential retries: {}'.format(retries))
    succeeded = False
    timeout = 0

    while retries >= 0 and (not succeeded):
        succeeded = await _authenticate(username, password, reader, writer, timeout = timeout)
        if succeeded:
            break

        retries -= 1
        if not timeout:
            timeout = 1
        else:
            timeout *= 2
        logging.debug('Scram authentication failed. Retrying, number of retries left: {}, timeout: {} second(s)'.format(retries, timeout))
    return succeeded

async def _authenticate(username, password, reader, writer, timeout = 0):
    logging.debug('Scram authenticate called...')
    state = {}

    state['username'] = scram_lib.nameprep(username)
    state['password'] = scram_lib.nameprep(password)

    state = scram_lib.clientFirstMessage(state)
    logging.debug('Client first message: {}'.format(state['client_first_msg']))
    buffer_ = state['client_first_msg']

    logging.debug('Sending client first message')
    status = await writer(bytes(buffer_, 'utf-8'))
    logging.debug('Sent client first message')

    logging.debug('Receiving server first message')
    response = await reader()
    logging.debug('Received server first message: {}'.format(response))
    state['server_first_msg'] = response

    state = scram_lib.parse(response, state)

    state = scram_lib.clientFinalMessage(state)
    logging.debug('Client final message: {}'.format(state['client_final_msg']))

    buffer_ = state['client_final_msg']
    logging.debug('Sending client final message')
    status = writer(bytes(buffer_, 'ascii'))
    logging.debug('Sent client final message')

    logging.debug('Receiving server final message')
    received_data = await reader(timeout = timeout)
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
    yield from writer.drain()
    return True

@asyncio.coroutine
def receiveMessage(reader, timeout = 0):
    total_data = []
    to = None
    #recv something
    while True:
        coro = asyncio.Task(reader.read(4096))
        try:
            data = yield from asyncio.wait_for(coro, timeout=to)
            if data:
                total_data.append(data)
                to = timeout
        except asyncio.TimeoutError:
            # Docs say: "When a timeout occurs, it cancels the task
            # and raises asyncio.TimeoutError."
            # But it doesn't cancel! So we cancel here.
            # coro.cancel()
            break

    response = b''.join(total_data)
    logging.debug('recv data: {}'.format(response))
    return response

# For testing.
if __name__ == "__main__":
    scram_lib.setup_logging()
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

def authenticate(username, password, reader, writer, loop, retries = 0):
    logging.debug('Scram authentication initiated, number of potential retries: {}'.format(retries))
    succeeded = False
    timeout = 0

    while retries >= 0 and (not succeeded):
        succeeded = _authenticate(username, password, reader, writer, timeout = timeout)
        if succeeded:
            break

        retries -= 1
        if not timeout:
            timeout = 1
        else:
            timeout *= 2
        logging.debug('Scram authentication failed. Retrying, number of retries left: {}, timeout: {} second(s)'.format(retries, timeout))
    return succeeded

async def _authenticate(username, password, reader, writer, timeout = 0):
    logging.debug('Scram authenticate called...')
    state = {}

    state['username'] = scram_lib.nameprep(username)
    state['password'] = scram_lib.nameprep(password)

    state = scram_lib.clientFirstMessage(state)
    logging.debug('Client first message: {}'.format(state['client_first_msg']))
    buffer_ = state['client_first_msg']

    logging.debug('Sending client first message')
    status = writer.write_data(bytes(buffer_, 'utf-8'))
    logging.debug('Sent client first message {}'.format(status))

    logging.debug('Receiving server first message')
    response = await reader.read_data()
    logging.debug('Received server first message: {}'.format(response))
    state['server_first_msg'] = response

    state = scram_lib.parse(response, state)

    state = scram_lib.clientFinalMessage(state)
    logging.debug('Client final message: {}'.format(state['client_final_msg']))

    buffer_ = state['client_final_msg']
    logging.debug('Sending client final message')
    status = writer.write_data(bytes(buffer_, 'ascii'))
    logging.debug('Sent client final message')

    logging.debug('Receiving server final message')
    response = await reader.read_data(timeout = timeout)
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
    yield from writer.drain()
    return True

@asyncio.coroutine
def receiveMessage(reader, timeout = 0):
    total_data = []
    to = None
    #recv something
    while True:
        coro = asyncio.Task(reader.read(4096))
        try:
            data = yield from asyncio.wait_for(coro, timeout=to)
            if data:
                total_data.append(data)
                to = timeout
        except asyncio.TimeoutError:
            # Docs say: "When a timeout occurs, it cancels the task
            # and raises asyncio.TimeoutError."
            # But it doesn't cancel! So we cancel here.
            # coro.cancel()
            break

    response = b''.join(total_data)
    logging.debug('recv data: {}'.format(response))
    return response

# For testing.
class TestConnection:
    def __init__(self, reader, writer, loop):
        self.reader = reader
        self.writer = writer
        self.loop = loop

    async def read_data(self, timeout = None):
        if timeout == 0:
            timeout = None
        try:
            numbytes = await asyncio.wait_for(self.reader.readexactly(4),
                                              timeout=timeout,loop=self.loop)
            lenght = int.from_bytes(numbytes, byteorder='big')
            data = await asyncio.wait_for(self.reader.readexactly(lenght),
                                          timeout=timeout, loop=self.loop)
            return data

        except CancelledError as e:
            raise e
        except asyncio.TimeoutError as e:
            raise e
        except Exception as e:
            err = sys.exc_info()
            raise e

    def write_data(self, msg, timeout=0):
        length = len(msg)
        num_bytes = length.to_bytes(4, byteorder='big')
        data = b''.join([num_bytes, msg])
        res = self.writer.write(data)
        return res

    def close(self):
        self.writer.close()

if __name__ == "__main__":
    scram_lib.setup_logging()
    host = 'localhost'
    port = 8887
    username = password = 'admin'

    loop = asyncio.get_event_loop()
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    connection = asyncio.open_connection(host,
                                         port,
                                         ssl=ctx, loop=loop)
    (reader, writer) = loop.run_until_complete(connection)
    test = TestConnection(reader, writer, loop)
    loop.run_until_complete(authenticate(username, password, test, test, loop = loop))
    test.close()
    loop.close()
