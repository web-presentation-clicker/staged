import select
from socket import AF_UNIX
from socketserver import UnixStreamServer, ThreadingMixIn, BaseRequestHandler
from threading import Thread, Lock
from uuid import uuid4, UUID
from common.log import Log, concurrent_logging, ansi_logging, log_level
from common.constants import *
from common.config import read_config
from common.pool_queue import Queue, QueueItem
from common.exceptions import *
from time import time, sleep
from ipaddress import IPv6Address, IPv4Address

# fuck it, magic monkeys
#from gevent import monkey
#monkey.patch_all()  # this is really what it comes down to
#from gevent import spawn, sleep
# the magic monkeys were slower. go figure


# key: uuid, value: session
session_table = {}
listener_table = {}
listener_insert_lock = Lock()


class PrometheusStub(object):
    def __init__(self):
        pass

    def start(self):
        pass

    def inc(self, key, amount: int = 1, labels=None):
        pass

    def dec(self, key, amount: int = 1, labels=None):
        pass

    def set(self, key, value, labels=None):
        pass


SOCKETS_OPENED = 'sock_opened'
SOCKETS_CLOSED = 'sock_closed'
# revise
#SESSIONS_ACTIVE = 'sess_active'
SESSIONS_OPENED = 'sess_opened'
SESSIONS_CLOSED = 'sess_closed'
SESSIONS_EXPIRED = 'sess_expired'
SESSIONS_ENDED = 'sess_ended'
SESSIONS_RECONNECTED = 'sess_recon'
QUEUE_DROPPED = 'queue_dropped'
MAINTENANCE_TIME = 'maintenance_time'
MAINTENANCE_LOOPS = 'maintenance_loops'
MAINTENANCE_LAST_TS = 'maintenance_last_ts'
MAINTENANCE_FAILS = 'maintenance_fail'
# add
#MAINTENANCE_TIME_LAST
# delete these
CLICKS_SUCC = 'events_suc'
CLICKS_FAIL = 'events_fail'
CLICKS_PENDING = 'events_pending'
# add
#EVENTS_QUEUED
#EVENTS_SENT
#EVENTS_FAILED
#EVENT_QUEUE_REJECTIONS
#EVENTS_EXPIRED


class PrometheusHelper(PrometheusStub):
    def __init__(self, addr, port):
        super().__init__()
        self._addr = addr
        self._port = port
        self._metrics = {}
        self._pfx = 'staged_sessionsrv_'

    def start(self):
        Log.i('starting prometheus metrics server on %s:%i' % (self._addr, self._port))
        start_http_server(self._port, self._addr)
        self._metrics[SOCKETS_OPENED] = Counter(self._pfx + 'sockets_opened', 'total number of opened sockets')
        self._metrics[SOCKETS_CLOSED] = Counter(self._pfx + 'sockets_closed', 'total number of closed sockets')
        # self._metrics[SESSIONS_ACTIVE] = Gauge(self._pfx + 'sessions_active', 'currently active sessions')
        self._metrics[SESSIONS_OPENED] = Counter(self._pfx + 'sessions_opened', 'total number of opened sessions')
        self._metrics[SESSIONS_CLOSED] = Counter(self._pfx + 'sessions_closed', 'total number of closed sessions')
        self._metrics[SESSIONS_EXPIRED] = Counter(self._pfx + 'sessions_expired', 'total number of expired sessions')
        self._metrics[SESSIONS_ENDED] = Counter(self._pfx + 'sessions_ended', 'total number of explicitly ended sessions')
        self._metrics[SESSIONS_RECONNECTED] = Counter(self._pfx + 'sessions_reconnected', 'total number of session reconnections')
        self._metrics[QUEUE_DROPPED] = Counter(self._pfx + 'queue_dropped', 'total number of dropped events in the send queue, indicative of server overload')
        self._metrics[MAINTENANCE_TIME] = Counter(self._pfx + 'maintenance_time', 'total time spent in seconds doing maintenance jobs')
        self._metrics[MAINTENANCE_LOOPS] = Counter(self._pfx + 'maintenance_loops', 'total number of maintenance jobs run')
        self._metrics[MAINTENANCE_LAST_TS] = Gauge(self._pfx + 'maintenance_last_timestamp', 'timestamp of the last successful maintenance job\'s completion')
        self._metrics[MAINTENANCE_FAILS] = Counter(self._pfx + 'maintenance_failures', 'total number of failed maintenance jobs')
        self._metrics[CLICKS_SUCC] = Counter(self._pfx + 'events_succeeded', 'total number of successful events', ['type'])
        self._metrics[CLICKS_FAIL] = Counter(self._pfx + 'events_failed', 'total number of failed events', ['type'])
        self._metrics[CLICKS_PENDING] = Gauge(self._pfx + 'events_pending', 'total number of events that are still sending', ['type'])

    def inc(self, key, amount: int = 1, labels=None):
        if labels is not None:
            self._metrics.get(key).labels(labels).inc(amount)
            return
        self._metrics.get(key).inc(amount)

    def dec(self, key, amount: int = 1, labels=None):
        if labels is not None:
            self._metrics.get(key).labels(labels).dec(amount)
            return
        self._metrics.get(key).dec(amount)
    
    def set(self, key, value, labels = None):
        if labels is not None:
            self._metrics.get(key).labels(labels).set(value)
            return
        self._metrics.get(key).set(value)


class Session(object):
    def __init__(self, last_contact: int, worker_id):
        self.last_contact = last_contact
        self.worker_id = worker_id

    def alive(self):
        self.last_contact = int(time())


class ClickEvent(QueueItem):
    def __init__(self, event_type, uuid_b, ttl):
        self.event_type = event_type
        self.uuid_b = uuid_b
        super().__init__(ttl)

    def g_tag(self):
        return 'click_event', self.created


def submit_event(worker_id, event_type, uuid_b, ttl):
    queue = listener_table.get(worker_id)
    if queue is None:
        # generally, this shouldn't happen
        raise KeyError('no listeners connected for destination worker')
    item = queue.submit(ClickEvent(event_type, uuid_b, ttl))
    if item is None:
        prom.inc(QUEUE_DROPPED)
    return item


class IPAddr(object):
    # ram-efficient storage for ip addresses
    def __init__(self, b: int, v6):
        self.b = b
        self.v6 = v6

    def __str__(self):
        if self.v6:
            return str(IPv6Address(self.b))
        else:
            # return '.'.join(str((self.b >> o*8) & 0xFF) for o in range(4))
            return str(IPv4Address(self.b))


def close_session(tag, ident: bytes) -> Session | None:
    # pop the session
    session = session_table.pop(ident, None)
    if session is not None:
        assert isinstance(session, Session)
        prom.inc(SESSIONS_CLOSED)
        # yeet an event at the worker. it doesn't really matter if this succeeds
        if submit_event(session.worker_id, V1_FUNC_EXPIRED, ident, session_queue_ttl) is None:
            Log.w(tag, 'can\'t send expiration event - event queue full!!! is the server overloaded?')
    return session


class RequestHandler(BaseRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tag = tuple()
        self.worker_id = None

    def handle(self):
        self.tag = tuple()
        prom.inc(SOCKETS_OPENED)
        try:
            self.request.settimeout(socket_timeout)
            init = self.request.recv(2)

            if init == V1_INIT_LISTENER:
                self.init_listener()
            elif init == V1_INIT_SENDER:
                self.init_sender()
            else:
                # unsupported version/init
                self.tag = ('?',)
                self.request.sendall(V1_GEN_FAIL)

        except Exception as e:
            Log.e(self.tag, 'uncaught exception in request handler', e)
            raise e
        finally:
            prom.inc(SOCKETS_CLOSED)

    def read_null_terminated(self):
        # this was used for worker id initially but is now unused
        # todo: delete this
        result = bytes()
        b = self.request.recv(1)
        while b != NULL:
            result += b
            b = self.request.recv(1)
        return result
    
    def read_len_first(self):
        n = int.from_bytes(self.request.recv(1))
        return self.request.recv(n)

    def read_uuid(self) -> bytes:
        return self.request.recv(16)

    def init_sender(self):
        self.tag = ('sender',)

        # read uwsgi worker id
        self.worker_id = self.read_len_first()
        self.tag += (self.worker_id.hex(),)

        # confirm
        Log.i(self.tag, 'connection up')
        self.request.sendall(V1_OK)

        # start loop
        try:
            self.sender_loop()
        except BrokenPipeError as e:
            Log.e(self.tag, 'connection died:', str(e))
        except TimeoutError as e:
            Log.e(self.tag, 'timeout during connection loop:', str(e))
        except BaseException as e:
            Log.wtf(self.tag, 'connection loop threw unexpected error', e)

    def sender_loop(self):
        poll = select.poll()
        poll.register(self.request, POLL_CHECK_FLAGS)
        while True:
            # wait for command
            ev = poll.poll(int(poll_time * 1000))
            if len(ev) == 0:
                # timeout
                continue
            if ev[0][1] & POLL_DEATH_FLAGS:
                # socket died
                raise BrokenPipeError('sender connection died according to poll')

            # execute command
            self.command_v1(self.tag)

    def init_listener(self):
        self.tag = ('listener',)

        # read uwsgi worker id
        self.worker_id = self.read_len_first()
        self.tag += (self.worker_id.hex(),)

        # confirm
        Log.i(self.tag, 'connection up')
        self.request.sendall(V1_OK)

        # add a queue if not already present
        with listener_insert_lock:
            existing = listener_table.get(self.worker_id)
            if existing is None:
                listener_table[self.worker_id] = Queue(event_queue_size)

        try:
            self.listener_loop()
        except BrokenPipeError as e:
            Log.e(self.tag, 'connection died:', str(e))
        except TimeoutError as e:
            Log.e(self.tag, 'timeout during connection loop:', str(e))
        except BaseException as e:
            Log.wtf(self.tag, 'connection loop threw unexpected error', e)

    def listener_loop(self):
        poll = select.poll()
        poll.register(self.request, POLL_DEATH_FLAGS)
        queue = listener_table[self.worker_id]
        while True:
            # get an event from top of the queue
            event = queue.pop(timeout=poll_time)
            if event is None:
                # check connection state while idle
                p = poll.poll(0)
                if len(p) == 0 or not p[0][1] & POLL_DEATH_FLAGS:
                    continue  # not dead

                # socket died
                raise BrokenPipeError('sender connection died according to poll')

            # claim event
            if not event.claim():
                # expired, server may be overloaded. throw it out.
                Log.w(self.tag, 'Server may be overloaded!!! expired event pulled from queue, it is', time() - event.created, 'seconds old!!!')

            Log.d(self.tag, 'event claimed!')

            try:
                # forward to listening uwsgi worker
                self.request.sendall(event.event_type)
                self.request.sendall(event.uuid_b)

                result = self.request.recv(1)
                event.result = result
            except BaseException as e:
                # if there are any connection problems, the socket is in an inconsistent state and must restart
                event.error = True
                raise e
            finally:
                # always inform of finish, otherwise it will hang forever after claiming
                event.done()

    def command_v1(self, tag):
        # read function
        func = self.request.recv(1)

        if func == V1_FUNC_CREATE_SESSION:      # create session
            tag += ('new',)
            self.create_session_v1(tag)
        elif func in [V1_FUNC_NEXT, V1_FUNC_PREV, V1_FUNC_HELLO]:  # click
            tag += ('click',)
            self.click_v1(tag, func)
        elif func == V1_FUNC_RESUME:            # resume
            tag += ('resume',)
            self.resume_v1(tag)
        elif func == V1_FUNC_END:               # end
            tag += ('end',)
            self.end_v1(tag)
        else:
            tag += ('nofunc',)
            Log.w(tag, 'invalid func value')
            self.request.sendall(V1_GEN_FAIL)

    def create_session_v1(self, tag):
        # 8 bits for a boolean. wasteful, I know
        ip_ver = self.request.recv(1)

        # get ip address in correct format and use for rate-limiting
        if ip_ver == NULL:  # v4
            ip_addr = int.from_bytes(self.request.recv(4))
        else:               # v6
            ip_addr = int.from_bytes(self.request.recv(16))

        tag += (IPAddr(ip_addr, bool(ip_ver)),)

        Log.v(tag, 'request to make a session')
        # todo: actually do something with the ip address

        # generate id
        uuid_s = uuid4()
        ident = uuid_s.bytes
        while ident in session_table:
            Log.d(tag, 'buy a lottery ticket')
            uuid_s = uuid4()
            ident = uuid_s.bytes

        # insert session
        session_table[ident] = Session(int(time()), self.worker_id)
        tag += (uuid_s,)
        Log.i(tag, 'session created')
        prom.inc(SESSIONS_OPENED)

        # send session id back to client
        self.request.sendall(V1_OK)
        self.request.sendall(ident)

    def end_v1(self, tag):
        ident = self.read_uuid()
        uuid_s = UUID(bytes=ident)
        tag += (uuid_s,)

        Log.d(tag, 'request to end session')

        # close the session
        session = close_session(tag, ident)
        if session is not None:
            Log.v(tag, 'session did not exist in table, it may have already expired')
            self.request.sendall(V1_OK)  # this is still a success
            return

        Log.v(tag, 'ended session')
        prom.inc(SESSIONS_ENDED)
        self.request.sendall(V1_OK)

    def resume_v1(self, tag):
        ident = self.read_uuid()
        uuid_s = UUID(bytes=ident)
        tag += (uuid_s,)

        # get session
        session = session_table.get(ident)
        if session is None:
            # too late buck-o
            Log.v(tag, 'session does not exist in table, it may have expired')
            self.request.sendall(V1_NO_SESSION)
            return

        session.alive()

        # potential race condition as maintenance thread sweeps expired sessions
        if ident not in session_table:
            Log.v(tag, 'session stopped existing in table, user is unlucky')
            self.request.sendall(V1_NO_SESSION)
            return

        Log.d(tag, 'session resume, updating target worker')
        # todo: test rapid resumption, there might be issues with race conditions
        old_worker = session.worker_id
        session.worker_id = self.worker_id  # update session to be reachable at new worker id

        # send a "rerouted" event to the old worker. if this fails, it's fine because the client probably already closed the connection
        # only send this if the worker doesn't match, otherwise it will terminate the session that was just resumed
        if self.worker_id != old_worker and submit_event(old_worker, V1_FUNC_REROUTED, ident, session_queue_ttl) is None:
            Log.w(tag, 'can\'t send rerouted event - event queue full!!! is the server overloaded?')

        self.request.sendall(V1_OK)
        prom.inc(SESSIONS_RECONNECTED)

    def click_v1(self, tag, func):
        if func == V1_FUNC_HELLO:
            labels = 'hello'
            tag += ('hello',)
        elif func == V1_FUNC_NEXT:
            labels = 'next_slide'
            tag += ('next_slide',)
        elif func == V1_FUNC_PREV:
            labels = 'prev_slide'
            tag += ('prev_slide',)
        else:
            # likely that the socket is out of sync
            raise Panic('invalid function for click_v1')

        # get/validate uuid
        ident = self.read_uuid()
        uuid_s = UUID(bytes=ident)
        tag += (uuid_s,)

        # retrieve session
        session = session_table.get(ident)
        if session is None:
            self.request.sendall(V1_NO_SESSION)
            return

        # forward event to relevant queue
        Log.v(tag, 'forwarding event')
        prom.inc(CLICKS_PENDING, labels=labels)
        try:
            event = submit_event(session.worker_id, func, ident, click_queue_ttl)
            if event is None:
                Log.w(tag, 'event queue full!!! server overloaded?')
                self.request.sendall(V1_GEN_FAIL)
                prom.inc(CLICKS_FAIL, labels=labels)
                return

            event.wait_for_result()

            if event.result == V1_OK:
                prom.inc(CLICKS_SUCC, labels=labels)
                session.alive()
            else:
                prom.inc(CLICKS_FAIL, labels=labels)
        except KeyError as e:
            # generally this should not happen, but it's not the socket's fault
            Log.wtf(tag, 'is the uwsgi app down?', e)
            prom.inc(CLICKS_FAIL, labels=labels)
            self.request.sendall(V1_GEN_FAIL)
            return
        except BaseException as e:
            # unexpected error, things may be broken
            prom.inc(CLICKS_FAIL, labels=labels)
            self.request.sendall(V1_GEN_FAIL)
            raise e
        finally:
            prom.dec(CLICKS_PENDING, labels=labels)

        # send result
        Log.d(tag, 'event result arrived, forwarding')
        self.request.sendall(event.result)


class SessionServer(ThreadingMixIn, UnixStreamServer):
    pass


def maintain():
    global die
    tag = ('maintenance thread',)
    while not die:
        start = time()

        Log.d(tag, 'session count:', len(session_table))
        try:
            frozen = session_table.copy()
            for ident in frozen:
                session = session_table.get(ident)
                if session is None:
                    continue
                elif time() - session.last_contact > session_timeout:
                    session = close_session(tag, ident)
                    if session is not None:
                        Log.i(tag, 'expired session:', UUID(bytes=ident))
                        prom.inc(SESSIONS_EXPIRED)

        except BaseException as e:
            Log.wtf('maintenance thread threw exception!!', e)
            prom.inc(MAINTENANCE_FAILS)
        finally:
            dur = time() - start
            prom.inc(MAINTENANCE_LOOPS)
            prom.inc(MAINTENANCE_TIME, dur)
            prom.set(MAINTENANCE_LAST_TS, time() * 1000)
        sleep(maintenance_interval)


def load_config():
    global maintenance_interval
    global session_timeout
    global socket_timeout
    global socket_addr
    global prom
    global event_queue_size
    global click_queue_ttl
    global session_queue_ttl
    global poll_time

    config = read_config()
    if config is None:
        Log.w(('load_config',), 'empty config, defaults will be used')
        config = {}

    ansi_logging(config.get('ansi_logging', DEFAULT_ANSI_LOGGING))
    log_level(config.get('log_level', DEFAULT_LOG_LEVEL))
    maintenance_interval = config.get('maintenance_interval', DEFAULT_MAINTENANCE_INTERVAL)
    session_timeout = config.get('session_timeout', DEFAULT_SESSION_TIMEOUT)
    socket_timeout = config.get('session_server_timeout', DEFAULT_SESSION_SERVER_TIMEOUT)
    socket_addr = config.get('session_server_socket', DEFAULT_SESSION_SERVER_SOCKET)
    event_queue_size = config.get('event_queue_size', DEFAULT_EVENT_QUEUE_SIZE)
    poll_time = config.get('poll_time', DEFAULT_POLL_TIME)
    click_queue_ttl = config.get('click_queue_ttl', DEFAULT_CLICK_QUEUE_TTL)
    session_queue_ttl = config.get('session_queue_ttl', DEFAULT_SESSION_QUEUE_TTL)
    if isinstance(prom, PrometheusStub):
        p = config.get('prometheus', {})
        if p.get('export', False):
            addr = p.get('addr', 'localhost')
            port = p.get('port', 8888)
            prom = PrometheusHelper(addr, port)
        else:
            prom = PrometheusStub()


global maintenance_interval
global session_timeout
global socket_timeout
global socket_addr
global event_queue_size
global click_queue_ttl
global session_queue_ttl
global poll_time
prom = PrometheusStub()

if __name__ == '__main__':
    die = False
    tag = ('main',)
    Log.d(tag, 'loading config')

    load_config()

    if isinstance(prom, PrometheusHelper):
        from prometheus_client import start_http_server, Gauge, Counter
        prom.start()

    # this is multithreaded enough to cause issues with regular logging
    concurrent_logging(True)

    # check compatibility
    try:
        AF_UNIX
    except NameError:
        Log.e(tag, 'Sorry! Only unix is supported at the moment.')
        exit(1)

    server = SessionServer(socket_addr, RequestHandler)
    server.allow_reuse_address = True

    maintenance_t = Thread(target=maintain)
    maintenance_t.start()

    with server:
        Log.i(tag, 'starting server at unix domain socket:', socket_addr)
        #spawn(server.serve_forever).join()
        server.serve_forever()
        die = True
        maintenance_t.join()
        server.shutdown()
