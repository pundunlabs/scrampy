import base64
import hashlib
import hmac
import logging
import random
import stringprep
import unicodedata

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

def clientFinalMessageWoProof(nonce):
    header = gs2Header()
    encoded = base64.standard_b64encode(bytes(header, 'utf-8'))
    buffer_ = 'c='
    buffer_ += encoded.decode('utf-8')
    buffer_ += ',r='
    buffer_ += nonce

    return buffer_

def clientProof(saltedPassword, authMsg):
    mac = hmac.new(saltedPassword, digestmod=hashlib.sha1)
    mac.update(bytes('Client Key', 'ascii'))
    clientKey = mac.digest()

    # Get SHA1 checksum of the clientKey
    sha1 = hashlib.sha1(clientKey)
    storedKey = sha1.digest()

    mac2 = hmac.new(storedKey[:], digestmod=hashlib.sha1)
    mac2.update(authMsg.strip().encode('utf8'))
    clientSignature = mac2.digest()
    clientProof = exor(clientKey, clientSignature)

    return clientProof

def gs2Header():
    return 'n,,'

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

def nonce():
    # Set the size of the bufer to 10.
    size = 10
    # Initialize byte array full of 0 bytes with the given size.
    zeros = bytearray()
    for i in range(size):
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
        c = str_[count//2]
        hex_ += hex(c//16)[2]
        hex_ += hex(c%16)[2]
        count += 2

    # Return the first 20 characters.
    return hex_[:20]

def parse(buffer_, state):
    # Split the buffer using the , character as the delimiter.
    tokens = (buffer_.decode('utf-8')).split(',')

    # Add each token to the state.
    for token in tokens:
        state[token[:1]] = token[2:]

    return state

def hi(password, salt, iterationCount):
    mac = hmac.new(password, salt + bytearray([0x00,0x00,0x00,0x01]), digestmod=hashlib.sha1)
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
    for i in range(iterationCount):
        mac = hmac.new(password, ui, digestmod=hashlib.sha1)
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

def verifyServerSignature(state):
    try:
        verifier = state['v']
    except :
        logging.error('Invalid proof says the server')
        raise

    saltedPassword = state['salted_password']
    authMsg = state['auth_msg']

    mac = hmac.new(saltedPassword, digestmod=hashlib.sha1)
    mac.update('Server Key'.encode('ascii'))

    serverKey = mac.digest()

    mac2 = hmac.new(serverKey, digestmod=hashlib.sha1)
    mac2.update(authMsg.encode('ascii'))
    serverSignature = mac2.digest()

    compare = base64.standard_b64encode(serverSignature).decode('utf8')

    if compare == verifier:
        return True
    else:
        logging.error('Server Signature not verified')
        return False

def setup_logging(level = logging.WARNING):
    date_fmt = '%Y-%m-%d %H:%M:%S'
    log_fmt=('%(asctime)s.%(msecs)03d [%(filename)s:%(lineno)d] '
             '%(levelname)s %(message)s'
            )
    logging.basicConfig(format=log_fmt, level=level, datefmt=date_fmt)
