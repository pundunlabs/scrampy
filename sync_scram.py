# vim: set expandtab:
import asyncio
import binascii
import logging
import scram_lib
import socket
import ssl
import sys
import time

if sys.version_info > (3,):
    buffer = memoryview


def authenticate(username, password, connection, retries = 0):
    logging.debug('Scram authentication initiated, number of potential retries: {}'.format(retries))
    succeeded = False
    timeout = 0

    while retries >= 0 and (not succeeded):
        succeeded = authenticate_(username, password, connection, timeout = timeout)
        if succeeded:
            break

        retries -= 1
        if not timeout:
            timeout = 1
        else:
            timeout *= 2
        logging.debug('Scram authentication failed. Retrying, number of retries left: {}, timeout: {} second(s)'.format(retries, timeout))
    return succeeded

def authenticate_(username, password, connection, timeout = 0):
    logging.debug('Scram authenticate called...')
    state = {}

    state['username'] = scram_lib.nameprep(username)
    state['password'] = scram_lib.nameprep(password)

    state = scram_lib.clientFirstMessage(state)
    logging.debug('Client first message: {}'.format(state['client_first_msg']))
    buffer_ = state['client_first_msg']

    logging.debug('Sending client first message')
    status = connection.write_data(bytes(buffer_, 'utf-8'))
    logging.debug('Sent client first message')

    logging.debug('Receiving server first message')
    response = connection.read_data(timeout = timeout)
    logging.debug('type of {}'.format(type(response)))
    logging.debug('Received server first message: {}'.format(response))
    state['server_first_msg'] = response

    state = scram_lib.parse(response, state)

    state = scram_lib.clientFinalMessage(state)
    logging.debug('Client final message: {}'.format(state['client_final_msg']))

    buffer_ = state['client_final_msg']
    logging.debug('Sending client final message')
    status = connection.write_data(bytes(buffer_, 'ascii'))
    logging.debug('Sent client final message')

    logging.debug('Receiving server final message')
    response = connection.read_data(timeout = timeout)
    logging.debug('Received server final message: {}'.format(response))

    state = scram_lib.parse(response, state)

    if scram_lib.verifyServerSignature(state):
        logging.debug('Authentication succeeded.')
        return True
    else:
        logging.error('Authentication failed.')
        return False

def sendMessage(connection, msg):
    logging.debug('Sending data {}'.format(msg))
    return connection.send(msg)

def receiveMessage(connection, timeout = 0):
    #total data partwise in an array
    total_data = []

    while True:
        #recv something
        try:
            data = connection.recv(4096, timeout)
            logging.debug('recv data: {}'.format(data))
            if data:
                connection.settimeout(timeout)
                total_data.append(data)
        except ssl.SSLWantReadError:
            logging.debug('No more data to recv')
            break
        except ssl.timeout:
            logging.debug('SSL Timout, try increasing timeout')
            break
        except:
            logging.error(sys.exc_info()[0])
            break

    connection.setblocking(1)
    #join all parts to make final string
    response = b''.join(total_data)
    return response

def clientFirstMessage(state):
    buffer_ = gs2Header()

    state = clientFirstMessageBare(state)

    buffer_ += state['client_first_msg_bare']

    state['client_first_msg'] = buffer_

    return state

def clientFirstMessageBare(state):
    buffer_ = 'n='
    buffer_ += state['username']
    buffer_ += ',r='

    nonce_ = nonce()
    state['nonce'] = nonce_
    buffer_ += nonce_
    state['client_first_msg_bare'] = buffer_

    return state

def clientFinalMessage(state):
    iterationCount = int(state['i'])
    salt = base64.standard_b64decode(state['s'])
    # password = bytes(state['password'], 'utf8')
    password = bytes(state['password'], 'utf8')
    saltedPassword = hi(password, salt, iterationCount)

    clientFinalMessageWoProof_ = clientFinalMessageWoProof(state['r'])

    authMsg = state['client_first_msg_bare']
    authMsg += ','
    authMsg += state['server_first_msg'].decode('utf-8')
    authMsg += ','
    authMsg += clientFinalMessageWoProof_

    clientProof_ = clientProof(saltedPassword, authMsg)
    state['salted_password'] = saltedPassword
    state['auth_msg'] = authMsg

    clientProof_encoded = base64.standard_b64encode(clientProof_)
    clientFinalMsg = clientFinalMessageWoProof_
    clientFinalMsg += ',p='
    clientFinalMsg += clientProof_encoded.decode('utf-8')

    state['client_final_msg'] = clientFinalMsg

    return state

class TestConnection:
    def __init__(self, connection=None):
        self.connection = connection

    def recvall(self, count, timeout=0):
        buf = b''
        while count:
            newbuf = self.connection.recv(count)
            if not newbuf:
                break
            buf = b''.join([buf, newbuf])
            count -= len(newbuf)

        return buf

    def read_data(self, timeout=0):
        if timeout != 0 and timeout != None:
            self.connection.settimeout(timeout)
        numbytes = self.recvall(4)
        length = int.from_bytes(numbytes, byteorder='big')
        data = self.recvall(length)
        return data

    def write_data(self, msg, timeout=0):
        length = len(msg)
        num_bytes = length.to_bytes(4, byteorder='big')
        data = b''.join([num_bytes, msg])
        res = self.connection.sendall(data)
        return res

    def connect(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1)

        try:
            connection.connect((host,port))
        except:
            logging.error('Unexpected error:', sys.exc_info()[0])
            raise

        logging.debug('Connection established')
        self.connection = connection

    def disconnect(self):
        try:
            self.connection.close()
        except:
            logging.error('Writer cannot be closed, exception {}'.format(sys.exc_info()[0]))
            raise


# For testing.
if __name__ == "__main__":
    scram_lib.setup_logging()
    host = 'localhost'
    port = 8887
    username = password = 'admin'
    connection = TestConnection()
    connection.connect(host, port)
    authenticate(username, password, connection)
    connection.disconnect()
