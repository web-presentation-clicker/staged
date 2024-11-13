import math
from websocket import create_connection
from threading import Thread, Semaphore
import time
import requests as r
import random


# dev
target = 'localhost:6969'
ssl = False

EVENT_HELLO = 'hello'
EVENT_NEXT = 'next_slide'
EVENT_PREV = 'prev_slide'
EVENT_END = 'end'
EVENT_PING = 'A'

CLICK_EVENTS = [EVENT_HELLO, EVENT_NEXT, EVENT_PREV]

# some events have slightly different endpoint names to follow http best practices
EVENT_ENDPOINT_MAP = {
        EVENT_NEXT: 'next-slide',
        EVENT_PREV: 'prev-slide',
}


class Presenter(object):
    def __init__(self):
        self.ssl = ssl
        self.target = target
        self.ws = None
        self.uuid = None

    def new_session(self):
        print('opening new session')
        try:
            if self.ssl:
                url = 'wss://%s/api/v1/ws' % self.target
            else:
                url = 'ws://%s/api/v1/ws' % self.target
            self.ws = create_connection(url)

            self.ws.send('v1')
            self.ws.send('new')

            result = self.ws.recv()
            if result.startswith('uuid: '):
                self.uuid = result[6:]
                print('got session:', self.uuid)
            elif result.startswith('ERR: '):
                err = result[5:]
                print('failed, error:', err)
                raise Exception(err)
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
        except OSError:
            return False

    def end_session(self, disconnect: bool = True):
        print(self.uuid, 'ending session')
        self.ws.send(EVENT_END)

        if disconnect:
            self.disconnect()

    def disconnect(self):
        print(self.uuid, 'disconnecting socket')
        self.ws.abort()  # don't be gentle


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

    def stop(self):
        if self.t is None:
            return
        print('killing socket listener')
        self.die = True
        self.t.join()
        self.t = None

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


class SingleSessionTest(object):
    def __init__(self):
        self.p = Presenter()
        self.loop = None

    def reset(self):
        print('resetting')
        if self.p is not None and self.p.is_connected():
            print('Unclosed socket!!!')
            self.p.disconnect()
        self.p = Presenter()

        if self.loop is not None:
            self.loop.stop()
        self.loop = None

    def new_session(self):
        self.p.new_session()

    def init_sock_loop(self):
        self.loop = SocketListener(self.p)
        self.loop.start()

    def n_synchronous_clicks(self, n=500, expect=200):
        print('sending', n, 'events synchronously')
        for i in range(n):
            print()
            assert self.loop.pop(0) is None
            ev = random.choice(CLICK_EVENTS)
            assert click(self.p, ev) == expect
            assert self.loop.pop(0.1) == ev
            assert self.loop.pop(0) is None

        print('\nPASS\n')

    def n_async_clicks(self, n=2000, n_threads=4, expect=200):
        print('sending', n, 'events asynchronously across', n_threads, 'threads')
        expected_events = [random.choice(CLICK_EVENTS) for _ in range(n)]
        events = expected_events.copy()

        def loop():
            try:
                while True:
                    assert click(self.p, events.pop()) == expect
            except IndexError:
                print('hit end of event list')
                return

        threads = [Thread(target=loop) for _ in range(n_threads)]

        assert self.loop.pop(0) is None
        print('spinning up threads')
        [t.start() for t in threads]

        # do busy work
        expected_counts = {}
        actual_counts = {}
        for ev in CLICK_EVENTS:
            expected_counts[ev] = expected_events.count(ev)
            actual_counts[ev] = 0

        # wait for threads
        [t.join() for t in threads]

        print('validating')
        ev = self.loop.pop(0.1)
        while ev is not None:
            assert ev in CLICK_EVENTS
            actual_counts[ev] += 1
            ev = self.loop.pop(0.1)

        print('expected:', expected_counts, '\nactual:', actual_counts)
        assert expected_counts == actual_counts

        print('\nPASS\n')

    def end_session_no_disconnect(self, timeout=30, interval=1):
        self.p.end_session(False)

        self.wait_for_clicker_expire(timeout, interval)

        print('asserting that the socket has been forcibly closed')
        assert not self.p.is_connected()

        print('\nPASS\n')

    def end_session(self, timeout=30, interval=1):
        self.p.end_session()
        self.wait_for_clicker_expire(timeout, interval)

        print('\nPASS\n')

    def wait_for_presenter_disconnect(self, timeout=30):
        deadline = time.time() + timeout
        print('waiting for presenter disconnect...')
        s = time.time()
        while self.p.is_connected() and time.time() < deadline:
            time.sleep(0.1)
        assert not self.p.is_connected()
        f = time.time()
        duration = f - s
        print('took', duration, 'seconds for disconnect')
        print('\nPASS\n')

    def wait_for_presenter_expire(self, timeout=30):
        print('waiting for presenter expire...')
        s = time.time()
        assert self.loop.pop(timeout) == 'ERR: session expired'
        f = time.time()
        duration = f - s
        print('took', duration, 'seconds for session to expire')
        print('\nPASS\n')

    def wait_for_clicker_expire(self, timeout=30, interval=1):
        print('waiting for clicker expire...')
        assert self.clicker_ping_interval(interval, math.ceil(timeout / interval), 406, 401)

    def clicker_ping_interval(self, interval=1, loops=20, expect=200, until=None):
        if until is not None:
            print('pinging every %i second(s) for %i seconds until status %i' % (interval, interval * loops, until))
        else:
            print('pinging every %i second(s) for %i seconds' % (interval, interval * loops))

        for i in range(loops):
            ev = random.choice(CLICK_EVENTS)
            assert self.loop.pop(0) is None
            result = click(self.p, ev)
            if result == 200:
                assert self.loop.pop(0.1) == ev
            if result == until:
                return True
            assert result == expect
            time.sleep(interval)
        return until is None

    def test_end(self):
        # the server should close the connection when the extension explicitly ends the session
        print('testing end with no disconnect')
        self.new_session()
        self.init_sock_loop()
        self.n_synchronous_clicks(3)
        self.end_session_no_disconnect()

        print('\nPASS\n')
        self.reset()

        # the server also shouldn't break if the client ends the connection
        print('testing end with disconnect')
        self.new_session()
        self.init_sock_loop()
        self.n_synchronous_clicks(3)
        self.end_session()

        print('\nPASS\n')
        self.reset()

    def test_socket_ping(self):
        # the socket ping should be ignored by the server
        print('testing socket ping')
        self.new_session()
        self.init_sock_loop()
        self.n_synchronous_clicks(3)
        self.p.ws.send(EVENT_PING)
        assert self.loop.pop(0.5) is None
        self.n_synchronous_clicks(3)
        self.end_session()

        print('\nPASS\n')
        self.reset()

    def test_many_clicks(self):
        # the server should be able to handle clicks very well. that's its whole job anyway.
        print('testing clicks')
        self.new_session()
        self.init_sock_loop()
        self.n_synchronous_clicks(1000)             # many clicks
        self.n_async_clicks(4000, 8)    # many clicks very fast
        self.end_session()

        print('\nPASS\n')
        self.reset()

    def test_expire(self, max_expire=30):
        # session should expire if the clicker never connects before the timeout
        print('testing no clicker expire')
        self.new_session()
        self.init_sock_loop()
        self.wait_for_presenter_expire(max_expire)
        self.wait_for_presenter_disconnect()

        print('\nPASS\n')
        self.reset()

        # session should expire with no clicker activity
        print('testing clicker stop expire')
        self.new_session()
        self.init_sock_loop()
        self.clicker_ping_interval(1, math.ceil(max_expire*2), 200)
        self.wait_for_presenter_expire(max_expire)
        self.wait_for_presenter_disconnect()

        print('\nPASS\n')
        self.reset()

        # session should expire if the presenting device disconnects, even if the clicker still pings
        print('testing presenter death expire')
        self.new_session()
        self.init_sock_loop()
        self.clicker_ping_interval(1, math.ceil(max_expire*2), 200)
        self.p.disconnect()
        self.wait_for_clicker_expire(max_expire)

        print('\nPASS\n')
        self.reset()

        # session should expire even if the presenting device disconnects and the clicker never connected
        print('testing no presenter expire')
        self.new_session()
        self.init_sock_loop()
        self.p.disconnect()
        print('waiting for maximum expiration time')
        time.sleep(max_expire)
        print('session should be expired now')
        assert click(self.p, EVENT_HELLO) == 401

        print('\nPASS\n')
        self.reset()


test = SingleSessionTest()

test.test_end()

test.test_socket_ping()

test.test_many_clicks()

# it is recommended to set your config values low so this test doesn't take forever
# max_expire_time = session_timeout + maintenance_interval + tolerance
max_expire_time = 8
test.test_expire(max_expire_time)


print('nothing blew up - PASS')
