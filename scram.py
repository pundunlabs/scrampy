import asyncio
import async_scram
import logging
import scram_lib
import sync_scram
import unittest

def connect(host, port, loop=None):
    if loop:
        return async_scram.connect(host, port, loop=loop)
    else:
        return sync_scram.connect(host, port)

def disconnect(connection = None, streamwriter = None, loop = None):
    if streamwriter and loop:
        return async_scram.disconnect(streamwriter, loop)
    elif connection:
        return sync_scram.disconnect(connection)

def authenticate(username, password,
                 connection = None,
                 streamreader = None, streamwriter = None,
                 loop = None):
    if streamreader and streamwriter and loop:
        return async_scram.authenticate(username, password,
                                        streamreader, streamwriter,
                                        loop)
    elif connection:
        return sync_scram.authenticate(username, password, connection)

class TestMethods(unittest.TestCase):

    def test_async(self):
        logging.debug('testing async scram')
        host = '192.168.211.166'
        port = 8887
        username = password = 'admin'
        loop = asyncio.get_event_loop()
        (reader, writer) = connect(host, port, loop = loop)
        self.assertTrue(authenticate(username, password,
                                     streamreader = reader,
                                     streamwriter = writer,
                                     loop = loop))
        self.assertTrue(disconnect(streamwriter = writer,
                                   loop = loop))
        loop.close()
        logging.debug('async scram done\n')

    def test_sync(self):
        logging.debug('testing sync scram')
        host = '192.168.211.166'
        port = 8887
        username = password = 'admin'
        conn = connect(host, port)
        self.assertTrue(authenticate(username, password, connection = conn))
        self.assertTrue(disconnect(connection = conn))
        logging.debug('sync scram done.')

# For testing.
if __name__ == "__main__":
    scram_lib.setup_logging(logging.DEBUG)
    unittest.main()
