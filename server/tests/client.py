from websocket import create_connection, WebSocketConnectionClosedException
from threading import Thread, Semaphore
import time
import requests as r
from event_constants import *

# dev
target = 'localhost:6969'
ssl = False

# some events have slightly different endpoint names to follow http best practices
EVENT_ENDPOINT_MAP = {
        EVENT_NEXT: 'next-slide',
        EVENT_PREV: 'prev-slide',
}


class SocketErrorEvent(Exception):
    def __init__(self, error_msg: str):
        self.error_msg = error_msg
        super().__init__('Server sent an error event: ' + error_msg)


class Presenter(object):
    def __init__(self):
        self.ssl = ssl
        self.target = target
        self.ws = None
        self.uuid = None

    @property
    def socket_url(self):
        if self.ssl:
            return 'wss://%s/api/v1/ws' % self.target
        return 'ws://%s/api/v1/ws' % self.target

    def _init_connect(self):
        if self.is_connected():
            print('socket is still open! closing first')
            self.disconnect()
        self.ws = create_connection(self.socket_url)

    def new_session(self):
        print('opening new session')
        try:
            self._init_connect()

            self.ws.send('v1')
            self.ws.send('new')

            result = self.ws.recv()
            if result.startswith('uuid: '):
                self.uuid = result[6:]
                print('got session:', self.uuid)
            elif result.startswith('ERR: '):
                err = result[5:]
                print('failed, error:', err)
                raise SocketErrorEvent(err)
            else:
                print('unexpected message from socket:', result)
                raise Exception('unexpected message from socket')
        except Exception as e:
            print('failed to connect:', e)
            raise e

    def resume_session(self, uuid=None):
        if self.uuid is None:
            if uuid is None:
                raise Exception('no uuid to resume')
            self.uuid = uuid
        print('resuming session')

        try:
            self._init_connect()

            self.ws.send('v1')
            self.ws.send('resume: ' + self.uuid)

            result = self.ws.recv()
            if result == 'resumed':
                print('resumed session:', self.uuid)
            elif result.startswith('ERR: '):
                err = result[5:]
                print('failed, error:', err)
                raise SocketErrorEvent(err)
            else:
                print('unexpected message from socket:', result)
                raise Exception('unexpected message from socket')
        except Exception as e:
            print('failed to connect:', e)
            raise e

    def is_connected(self) -> bool:
        if self.ws is None:
            return False
        if not self.ws.connected:
            return False

        # forceful disconnections still report as connected, for some reason
        try:
            self.ws.ping()
            return True
        except (OSError, WebSocketConnectionClosedException):
            return False

    def end_session(self, disconnect: bool = True):
        print(self.uuid, 'ending session')
        self.ws.send(EVENT_END)

        if disconnect:
            self.disconnect()

    def disconnect(self):
        print(self.uuid, 'disconnecting socket')
        try:
            self.ws.abort()  # don't be gentle
        except OSError as e:
            print('already disconnected:', e)


def click(p: Presenter, event):
    event = EVENT_ENDPOINT_MAP.get(event, event)

    if p.ssl:
        url = 'https://%s/api/v1/session/%s' % (p.target, event)
    else:
        url = 'http://%s/api/v1/session/%s' % (p.target, event)

    try:
        print(p.uuid, 'click!')
        s = time.time()
        result = r.get(url, headers={'Authorization': p.uuid})
        print(p.uuid, event, result.status_code)

        f = time.time()
        print(p.uuid, 'click took', f - s, 'seconds!')

        return result.status_code
    except Exception as e:
        print('click failure!', e)
        raise e


class SocketListener(object):
    def __init__(self, p: Presenter):
        self.uuid = p.uuid
        self.ws = p.ws
        self.die = False
        self.t = None
        self.capsem = Semaphore(0)
        self.captured = []

    def start(self):
        if self.t is not None:
            raise Exception('thread already started')

        print('spinning up socket listener')
        self.die = False
        self.t = Thread(target=self.socket_loop)
        self.t.start()

    def stop(self, block: bool = True):
        if self.t is None:
            return
        print('killing socket listener')
        self.die = True
        if block:
            self.await_death()

    def await_death(self):
        t = self.t
        if t is not None:
            t.join()

    def socket_loop(self):
        try:
            while not self.die:
                func = self.ws.recv()
                # the python websocket sends an empty message when it loses connection
                if func == '' and not self.ws.connected:
                    raise OSError('connection lost')

                self.captured.append(func)
                self.capsem.release()
                print(self.uuid, 'GOT', func)
        except Exception as e:
            print('Socket listener death!!!!', e)
        finally:
            self.t = None

    def pop(self, timeout: float | int | None = 0.1) -> str | None:
        if self.capsem.acquire(timeout=timeout):
            return self.captured.pop(0)
        return None

    def peek_all(self) -> [str]:
        return self.captured
