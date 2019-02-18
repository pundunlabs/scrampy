# -*- coding: utf-8 -*-
import base64
import hashlib
import hmac
import os
import random
import socket
import stringprep
import ssl
import sys
import time
import struct
import unicodedata

# Could be used to initialize a socket.
def initialize(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    connection = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1)

    try:
        connection.connect((host, port))
    except socket.error:
        print('socket.error connecting host: {} at port: {}'.format(host, port))
        sys.exit()
    except:
        print('Unknown error connecting host: {} at port: {}'.format(host, port))
        sys.exit()

    print('Connection established')

    return connection

def disconnect(connection):
    try:
        connection.close()
    except:
        print('Connection cannot be closed')
        return False

    print('Connection closed')
    return True

def authenticate(connection, username, password):
    print('Scram authenticate called..')

    try:
        version = connection.ssl_version
    except:
        print('Cannot verify ssl version of the connection')
        sys.exit()
    if version != 3:
        print('Use ssl_version=ssl.PROTOCOL_TLSv1, not compatible otherwise.')
        sys.exit()

    # Initialize empty state.
    state = {}

    # Normalize username and password.
    prep_username = nameprep(username)
    prep_password = nameprep(password)

    state['username'] = prep_username
    state['password'] = prep_password

    state = clientFirstMessage(state)

    buffer_ = state['client_first_msg']

    status = sendMessage(connection, buffer_)

    response = receiveMessage(connection).strip()
    state['server_first_msg'] = response

    state = parse(response, state)

    state = clientFinalMessage(state)

    buffer_ = state['client_final_msg']
    status = sendMessage(connection, buffer_)

    response = receiveMessage(connection).strip()

    state = parse(response, state)

    if verifyServerSignature(state):
        print('Authentication succeeded')
        return True
    else:
        print('Authentication failed')
        return False

def sendMessage(connection, msg):
    return connection.send(msg)

# Sends client first message through the socket.
def clientFirstMessage(state):
    # Initialize the buffer with the gs2 header.
    buffer_ = gs2Header()

    state = clientFirstMessageBare(state)

    # Append client first msg bare to the header.
    buffer_ += state['client_first_msg_bare']

    state['client_first_msg'] = buffer_

    return state

def gs2Header():
    return 'n,,'

def clientFirstMessageBare(state):
    buffer_ = 'n='
    buffer_ += state['username']
    buffer_ += ',r='
    # Get nonce using the nonce function.
    nonce_ = nonce()
    state['nonce'] = nonce_
    buffer_ += nonce_

    state['client_first_msg_bare'] = buffer_
    # Return the updated state with nonce & client_first_msg_bare
    return state

# Receive message over the connection and return the response string.
def receiveMessage(connection, timeout=1.0):
    # Set timeout for the connection temporarily when receiving messages.
    connection.settimeout(timeout)
    # Initialize the response to empty string.
    response = ''
    cont = True
    while cont:
        # Handle timeout error.
        try:
            data = connection.recv(1024)
        except ssl.SSLError:
            cont = False
            continue

        if not data:
            cont = False
            break
        response += data

    # Remove the timeout for the connection.
    connection.settimeout(None)

    return response

def clientFinalMessage(state):
    iterationCount = int(state['i'])
    salt = base64.standard_b64decode(state['s'])

    saltedPassword = hi(state['password'], salt, iterationCount)

    clientFinalMessageWoProof_ = clientFinalMessageWoProof(state['r'])

    authMsg = state['client_first_msg_bare']
    authMsg += ','
    authMsg += state['server_first_msg']
    authMsg += ','
    authMsg += clientFinalMessageWoProof_

    clientProof_ = clientProof(saltedPassword, authMsg)

    state['salted_password'] = str(saltedPassword)
    state['auth_msg'] = str(authMsg)

    clientFinalMsg = clientFinalMessageWoProof_
    clientFinalMsg += ',p='
    clientFinalMsg += clientProof_

    state['client_final_msg'] = str(clientFinalMsg)

    return state

def clientFinalMessageWoProof(nonce):
    header = gs2Header()
    encoded = base64.standard_b64encode(header)
    buffer_ = 'c='
    buffer_ += encoded
    buffer_ += ',r='
    buffer_ += nonce

    return buffer_

def clientProof(saltedPassword, authMsg):
    mac = hmac.new(str(saltedPassword), digestmod=hashlib.sha1)
    mac.update('Client Key')
    clientKey = mac.digest()

    # Get SHA1 checksum of the clientKey
    sha1 = hashlib.sha1(clientKey)
    storedKey = sha1.digest()

    mac2 = hmac.new(storedKey[:], digestmod=hashlib.sha1)
    mac2.update(authMsg.strip())
    clientSignature = mac2.digest()

    clientProof = exor(clientKey, clientSignature)
    return base64.standard_b64encode(clientProof)

def verifyServerSignature(state):
    try:
        verifier = state['v']
    except KeyError:
        print('Invalid proof says the server')
        sys.exit()
    saltedPassword = state['salted_password']
    authMsg = state['auth_msg']

    mac = hmac.new(saltedPassword, digestmod=hashlib.sha1)
    mac.update('Server Key')
    serverKey = mac.digest()

    mac2 = hmac.new(serverKey, digestmod=hashlib.sha1)
    mac2.update(authMsg)
    serverSignature = mac2.digest()

    compare = base64.standard_b64encode(serverSignature)

    if compare == verifier:
        return True
    else:
        print('Server Signature not verified')
        sys.exit()

def nonce():
    # Set the size of the bufer to 10.
    size = 10
    # Initialize byte array full of 0 bytes with the given size.
    zeros = bytearray()
    for i in xrange(size):
        zeros.append(0x00)

    # Assign a random value for each byte in the buffer.
    for i in range(size):
        zeros[i] = random.randint(0, 255)

    # Get SHA1 checksum of the buffer.
    sha1 = hashlib.sha1(zeros)
    str_ = sha1.digest()

    count = 0
    hex_ = ''

    while count < 20:
        c = ord(str_[count/2])
        hex_ += hex(c/16)[2]
        hex_ += hex(c%16)[2]
        count += 2

    # Return the first 20 characters.
    return hex_[:20]

def parse(buffer_, state):
    # Split the buffer using the , character as the delimiter.
    tokens = buffer_.split(',')

    # Add each token to the state.
    for token in tokens:
        state[token[:1]] = token[2:]

    return state

def hi(password, salt, iterationCount):
    mac = hmac.new(str(password), salt + bytearray([0x00,0x00,0x00,0x01]), digestmod=hashlib.sha1)
    # mac.update(salt)
    # Corresponding to mac.Write([]byte{0, 0, 0, 1}) in the Go code.
    # mac.update(bytes([0x00, 0x00, 0x00, 0x01]))
    ui = mac.digest()
    if iterationCount == 1:
        return ui
    else:
        return hi_iter(password, ui, iterationCount - 1)

def hi_iter(password, ui, iterationCount):
    res = ui
    for i in xrange(iterationCount):
        mac = hmac.new(str(password), ui, digestmod=hashlib.sha1)
        mac_ = mac.digest()
        res = exor(res, mac_)
        ui = mac_
    return res

# XOR the two buffers byte by byte.
def exor(a, b):
    # Run as many times as the string whose length is smaller.
    length = min(len(a), len(b))

    buffer_ = bytearray()
    for i in range(length):
        buffer_.append(0x00)

    for i in range(length):
        # In some cases, the current element returns an integer instead of a string.
        # Wrap in try/except to avoid error
        try:
            cur_a = ord(a[i])
        except TypeError:
            cur_a = a[i]
        try:
            cur_b = ord(b[i])
        except TypeError:
            cur_b = b[i]

        buffer_[i] = cur_a ^ cur_b

    return buffer_

def nameprep(label):
    label = u''.join(label)

    newlabel = []
    for c in label:
        if stringprep.in_table_b1(c):
            continue
        newlabel.append(stringprep.map_table_b2(c))
    label = u''.join(newlabel)

    label = unicodedata.normalize('NFKC', label)
    for c in label:
        if stringprep.in_table_c12(c) or \
           stringprep.in_table_c22(c) or \
           stringprep.in_table_c3(c) or \
           stringprep.in_table_c4(c) or \
           stringprep.in_table_c5(c) or \
           stringprep.in_table_c6(c) or \
           stringprep.in_table_c7(c) or \
           stringprep.in_table_c8(c) or \
           stringprep.in_table_c9(c):
            raise UnicodeError('Invalid character %r' % c)

    RandAL = map(stringprep.in_table_d1, label)
    for c in RandAL:
        if c:
            if filter(stringprep.in_table_d2, label):
                raise UnicodeError('Violation of BIDI requirement 2')
            if not RandAL[0] or not RandAL[-1]:
                raise UnicodeError('Violation of BIDI requirement 3')
    return label

conn = initialize('192.168.211.166', 8887)
authenticate(conn, 'admin', 'admin')
disconnect(conn)
