import math
from threading import Thread, Semaphore
import time
import random
import traceback
from client import Presenter, SocketErrorEvent, SockClicker
from event_constants import *


class SingleSessionTest(object):
    def __init__(self):
        self.p = Presenter()
        self.c = SockClicker()

    def reset(self):
        print('resetting\n')
        if self.p is not None and self.p.is_connected():
            print('Unclosed socket!!!')
            self.p.disconnect()
        self.p = Presenter()

        if self.c is not None and self.c.is_connected():
            print('Unclosed socket!!!')
            self.c.disconnect()
        self.c = SockClicker()

    def new_session(self):
        if self.p is None:
            self.p = Presenter()
        self.p.new_session()

    def connect_clicker(self, pop_ping=True):
        if self.c is None:
            self.c = SockClicker()
        self.c.connect(self.p.uuid)

        if pop_ping:
            assert self.p.pop(0.1) == EVENT_HELLO

    def resume_session(self, uuid=None):
        if self.p is None:
            self.p = Presenter()
        self.p.resume_session(uuid)

    def n_synchronous_clicks(self, n=500):
        print('sending', n, 'events synchronously')
        for i in range(n):
            print()
            assert self.p.pop(0) is None
            ev = random.choice(CLICK_EVENTS)
            assert self.c.click_blocking(ev) == EVENT_OK
            self.c.assert_eoq()
            assert self.p.pop(0.1) == ev
            assert self.p.pop(0) is None

        print('\nPASS\n')

    def n_async_clicks(self, n=2000, n_threads=4):
        # note: this test fails with high thread counts.
        # the high thread counts overflow the websocket buffer, dropping the events.
        # this is intended functionality, and this test isn't very scientific anyway.
        print('sending', n, 'events asynchronously across', n_threads, 'threads')
        expected_events = [random.choice(CLICK_EVENTS) for _ in range(n)]
        events = expected_events.copy()
        errors = []

        def loop():
            try:
                while True:
                    result = self.c.click_blocking(events.pop(), 5)
                    if result != EVENT_OK:
                        raise AssertionError(str(result) + ' is not ' + EVENT_OK)
            except IndexError:
                print('hit end of event list')
                return
            except BaseException as e:
                print('error in async click loop:', e)
                errors.append(e)
                raise e

        threads = [Thread(target=loop) for _ in range(n_threads)]

        assert self.p.pop(0) is None
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

        self.c.assert_eoq()

        # if there were errors, this is a failure
        if len(errors) != 0:
            print('there were errors:')
            for e in errors:
                traceback.print_exception(e)
            assert False

        print('validating')
        ev = self.p.pop(0.1)
        while ev is not None:
            assert ev in CLICK_EVENTS
            actual_counts[ev] += 1
            ev = self.p.pop(0.1)

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
        assert self.p.pop(timeout) == 'ERR: session expired.'
        f = time.time()
        duration = f - s
        print('took', duration, 'seconds for session to expire')
        print('\nPASS\n')

    def wait_for_clicker_expire(self, timeout=30, interval=1):
        print('waiting for clicker expire...')

        for i in range(math.ceil(timeout / interval)):
            try:
                ev = random.choice(CLICK_EVENTS)
                assert self.p.pop(0) is None
                self.c.click_blocking(ev)
                assert False
            except SocketErrorEvent as e:
                if not e.session_valid and e.error_msg == 'session expired':
                    break

                assert e.session_valid
                assert e.error_msg == 'peer unavailable'
            time.sleep(interval)

    def assert_unreachable(self):
        try:
            self.c.click_blocking(EVENT_HELLO)
            assert False
        except SocketErrorEvent as e:
            assert e.session_valid
            assert e.error_msg == 'peer unavailable'

    def clicker_ping_interval(self, interval=1, loops=20, expect=EVENT_OK):
        print('pinging every %i second(s) for %i seconds' % (interval, interval * loops))

        for i in range(loops):
            ev = random.choice(CLICK_EVENTS)
            assert self.p.pop(0) is None
            result = self.c.click_blocking(ev)
            if result == EVENT_OK:
                assert self.p.pop(0.1) == ev
            assert result == expect
            time.sleep(interval)

    def test_end(self):
        # the server should close the connection when the extension explicitly ends the session
        print('testing end with no disconnect')
        self.new_session()
        self.connect_clicker()
        self.n_synchronous_clicks(3)
        self.end_session_no_disconnect()

        print('\nPASS\n')
        self.reset()

        # the server also shouldn't break if the client ends the connection
        print('testing end with disconnect')
        self.new_session()
        self.connect_clicker()
        self.n_synchronous_clicks(3)
        self.end_session()

        print('\nPASS\n')
        self.reset()

    def test_socket_ping(self):
        # the socket ping should be ignored by the server
        print('testing socket ping')
        self.new_session()
        self.connect_clicker()
        self.n_synchronous_clicks(3)
        self.p.ws.send(EVENT_PING)
        assert self.p.pop(0.5) is None
        self.n_synchronous_clicks(3)
        self.end_session()

        print('\nPASS\n')
        self.reset()

    def test_many_clicks(self, threads=4):
        # the server should be able to handle clicks very well. that's its whole job anyway.
        print('testing clicks')
        self.new_session()
        self.connect_clicker()
        self.n_synchronous_clicks(1000)             # many clicks
        # todo: async test broken because it's fundamentally pointless
        # self.n_async_clicks(4000, threads)       # many clicks very fast
        self.end_session()

        print('\nPASS\n')
        self.reset()

    def test_resume(self):

        # server should reject invalid uuid
        print('testing invalid uuid')
        try:
            self.resume_session('not-a-real-uuid')
            print('server did not reject connection!!!')
            assert False
        except TimeoutError as e:
            assert str(e) == 'did not get confirmation in time'
            assert not self.p.is_connected()
            # success

        print('\nPASS\n')
        self.reset()

        # server should refuse for uuids that don't exist
        print('testing non-existent uuid')
        try:
            self.resume_session('deadbeef-dead-beef-dead-beefdeadbeef')
            print('server did not reject connection!!!')
            assert False
        except SocketErrorEvent as e:
            assert e.error_msg == 'session expired'
            assert not e.session_valid
            self.wait_for_presenter_disconnect(2)

        print('\nPASS\n')
        self.reset()

        # server should allow resuming after connection is lost
        print('testing resume after connection loss')
        self.new_session()
        self.connect_clicker()
        self.n_synchronous_clicks(3)
        for i in range(10):
            print('testing resumptions (%i/10)' % (i+1))
            self.p.disconnect()
            self.assert_unreachable()
            self.resume_session()
            self.n_synchronous_clicks(3)
        self.end_session()

        print('\nPASS\n')
        self.reset()

        # server should disconnect old socket without an error when resuming
        print('testing old socket termination on resume')
        self.new_session()
        self.connect_clicker()
        self.n_synchronous_clicks(3)
        for i in range(10):
            print('testing resumptions (%i/10)' % (i+1))

            # swap out presenter
            old_presenter = self.p
            self.p = None

            # reconnect with new connection
            self.resume_session(old_presenter.uuid)
            self.n_synchronous_clicks(3)

            # verify that old connection "cleanly" disconnected
            assert not old_presenter.is_connected()
            assert old_presenter.pop(0) is None
        self.end_session()

        print('\nPASS\n')
        self.reset()

    def test_rapid_resume(self, n_threads=16, duration=30):
        # check for race conditions in session resume code
        print('testing rapid session resumption')

        self.new_session()
        self.connect_clicker()
        self.n_synchronous_clicks(3)

        die = False
        error = []

        # make it interesting
        events_dropped = 0
        events_clicked = {}
        events_got = {}
        events_got_unsorted = []
        for ev in CLICK_EVENTS:
            events_clicked[ev] = 0
            events_got[ev] = 0

        running_sem = Semaphore(n_threads)

        def resume_loop():
            with running_sem:
                try:
                    # each loop has its own client running in parallel
                    rtest = SingleSessionTest()
                    while not die:
                        rtest.resume_session(self.p.uuid)

                        # test both server and client side termination
                        if random.randint(0, 1):
                            rtest.wait_for_presenter_disconnect(5)
                        else:
                            rtest.p.disconnect()

                        # dump all the events to process later
                        rtest.p.loop.await_death()
                        events_got_unsorted.extend(rtest.p.peek_all())

                except BaseException as ex:
                    print('resume loop threw!!!', ex)
                    error.append(ex)

        threads = [Thread(target=resume_loop) for _ in range(n_threads)]
        self.p.disconnect()

        print('starting rapid resumption across', n_threads, 'threads')
        [t.start() for t in threads]

        stop_at = time.time() + duration

        # send a bunch of events to contribute to the chaos
        try:
            while time.time() < stop_at:
                ev = random.choice(CLICK_EVENTS)
                try:
                    events_clicked[ev] += 1
                    assert self.c.click_blocking(ev) == EVENT_OK
                except SocketErrorEvent as e:
                    assert e.session_valid
                    events_dropped += 1
        except BaseException as e:
            # catch if main loop dies
            error.append(e)
            traceback.print_exception(e)

        print('stopping resume loop')
        die = True
        # one connection should win
        for _ in range(n_threads - 1):
            assert running_sem.acquire(timeout=1)

        print('resuming session back to main thread')
        self.resume_session()
        self.n_synchronous_clicks(3)

        assert running_sem.acquire(timeout=1)

        print('waiting for all resume loops to terminate')
        [t.join() for t in threads]

        # if there were errors, this is a failure
        if len(error) != 0:
            print('there were errors:')
            for e in error:
                traceback.print_exception(e)
            assert False

        # count events
        for event in events_got_unsorted:
            assert event in CLICK_EVENTS
            events_got[event] += 1

        # lost events are unavoidable without additional delivery confirmation, but they should be rare.
        # as such this is mostly informational, but an arbitrary 20% maximum for lost events is required
        total_sent = sum(events_clicked.values())
        total_got = len(events_got_unsorted)
        lost = total_sent - total_got - events_dropped
        lost_percent = lost / total_sent * 100
        print('=================================================================')
        print('sent', total_sent, 'events. received', total_got, 'events. failed to send', events_dropped, 'events.', 'there are', lost, 'events unaccounted for.')
        print()
        print('clicked:', events_clicked)
        print('got:', events_got)
        print('dropped:', events_dropped)
        print('lost:', '%.2f%%' % lost_percent)
        print('=================================================================')

        assert lost_percent <= 20.0

        self.n_synchronous_clicks(3)
        self.p.disconnect()

        print('\nPASS\n')
        self.reset()

    def test_expire(self, max_expire=30):
        # session should expire if the clicker never connects before the timeout
        print('testing no clicker expire')
        self.new_session()
        self.connect_clicker()
        self.wait_for_presenter_expire(max_expire)
        self.wait_for_presenter_disconnect()

        print('\nPASS\n')
        self.reset()

        # the above should also work after a resume
        print('testing no clicker expire after resume')
        self.new_session()
        self.connect_clicker()
        self.p.disconnect()
        self.resume_session()
        self.wait_for_presenter_expire(max_expire)
        self.wait_for_presenter_disconnect()

        print('\nPASS\n')
        self.reset()

        # session should expire with no clicker activity
        print('testing clicker stop expire')
        self.new_session()
        self.connect_clicker()
        self.clicker_ping_interval(1, math.ceil(max_expire * 2))
        self.wait_for_presenter_expire(max_expire)
        self.wait_for_presenter_disconnect()

        print('\nPASS\n')
        self.reset()

        # the above should also work after a resume
        print('testing clicker stop expire after resume')
        self.new_session()
        self.connect_clicker()
        self.clicker_ping_interval(1, math.ceil(max_expire * 2))
        self.p.disconnect()
        self.assert_unreachable()
        self.resume_session()
        self.clicker_ping_interval(1, math.ceil(max_expire * 2))
        self.wait_for_presenter_expire(max_expire)
        self.wait_for_presenter_disconnect()

        print('\nPASS\n')
        self.reset()

        # session should expire if the presenting device disconnects, even if the clicker still pings
        print('testing presenter death expire')
        self.new_session()
        self.connect_clicker()
        self.clicker_ping_interval(1, math.ceil(max_expire * 2))
        self.p.disconnect()
        self.wait_for_clicker_expire(max_expire)

        print('\nPASS\n')
        self.reset()

        # the above should also work after a resume
        print('testing presenter death expire after resume')
        self.new_session()
        self.connect_clicker()
        self.clicker_ping_interval(1, math.ceil(max_expire * 2))
        self.p.disconnect()
        self.assert_unreachable()
        self.resume_session()
        self.clicker_ping_interval(1, math.ceil(max_expire * 2))
        self.p.disconnect()
        self.wait_for_clicker_expire(max_expire)

        print('\nPASS\n')
        self.reset()

        # session should expire even if the presenting device disconnects and the clicker never connected
        print('testing no presenter expire')
        self.new_session()
        self.p.disconnect()
        print('waiting for maximum expiration time')
        time.sleep(max_expire)
        print('session should be expired now')
        self.wait_for_clicker_expire(0)

        print('\nPASS\n')
        self.reset()

        # the above should work even after resume
        print('testing no presenter expire after resume')
        self.new_session()
        self.p.disconnect()
        self.resume_session()
        self.p.disconnect()
        print('waiting for maximum expiration time')
        time.sleep(max_expire)
        print('session should be expired now')
        self.wait_for_clicker_expire(0)

        print('\nPASS\n')
        self.reset()


if __name__ == '__main__':
    test = SingleSessionTest()

    test.test_end()

    test.test_socket_ping()

    test.test_many_clicks(4)

    test.test_resume()

    test.test_rapid_resume(32, 60)

    # it is recommended to set your config values low so this test doesn't take forever
    # max_expire_time = session_timeout + maintenance_interval + tolerance
    max_expire_time = 8
    test.test_expire(max_expire_time)

    print('nothing blew up - PASS')
