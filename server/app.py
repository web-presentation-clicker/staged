import uwsgi
import uuid
import base64
import binascii
import math
from uwsgidecorators import postfork
from gevent.select import poll as ge_poll
from select import poll as std_poll  # do not use this in a blocking way
from gevent.lock import BoundedSemaphore
from gevent import sleep, spawn, socket
from time import time

from common.config import read_config
from common.log import Log, ansi_logging, log_level
from common.constants import *
from common.exceptions import *
from common.pool_queue import Queue, QueueItem, use_gevent
from ipaddress import IPv6Address, IPv4Address

DEFAULT_HEADERS = [('Server', 'on stage click router')]
CONTENT_PLAIN_TEXT = ('Content-Type', 'text/plain')


# see common.pool_queue.use_gevent()
use_gevent()


def ipv6_addr_bytes(ip_addr_s: str) -> bytes:
    return IPv6Address(ip_addr_s).packed


def ipv4_addr_bytes(ip_addr_s: str) -> bytes:
    # ip_addr_spl = ip_addr_s.split('.')
    # if len(ip_addr_spl) != 4:
    #     raise Exception('expected v4 address with 4 segments, not ' + str(len(ip_addr_spl)))
    # ip_addr = 0
    # for i in range(4):
    #     ip_addr = (ip_addr << 8) + int(ip_addr_spl.pop())
    #
    # return ip_addr.to_bytes(4)
    return IPv4Address(ip_addr_s).packed


def ws_send(msg: bytes):
    uwsgi.websocket_send(msg)


def ws_send_err(msg: bytes, can_retry: bool = False, nonce: bytes | None = None):
    event = V1_EVENT_ERR_PFX + msg
    if not can_retry:
        event += V1_EVENT_ERR_NO_SESSION_SFX
    if nonce is not None:
        event = nonce + event

    ws_send(event)


def parse_uuid_from_client(tag, action: bytes, pfx, nonce = None) -> None | uuid.UUID:
    if len(action) > len(pfx) + 40:
        Log.w(tag, 'uuid too long')
        return None  # no

    uuid_r = action[len(pfx):].decode('ascii')

    if len(uuid_r) == 0:
        ws_send_err(V1_EVENT_ERR_CLIENT, False, nonce)
        return

    try:
        return uuid.UUID(uuid_r)
    except ValueError:
        Log.i(tag, 'got badly formed uuid from client, aborting')
        return None


def do_socket_loop_v1(tag, ident: bytes):
    # make callback
    with callback_table_lock:
        # check for old callback; i.e. if this listener was just previously connected to this worker
        old_loop = callback_table.pop(ident, None)
        if old_loop is not None:
            assert isinstance(old_loop, WebSocketCallback)
            old_loop.submit(WebSocketEvent(V1_FUNC_REROUTED, session_queue_ttl))  # disregard result (it doesn't matter)

        # add new callback
        cb = WebSocketCallback()
        callback_table[ident] = cb

    try:
        while True:
            # wait for event
            event = cb.pop(timeout=ws_poll_time)

            try:
                # ensure socket alive
                ws_cmd = uwsgi.websocket_recv_nb()

                # handle websocket cmd
                if ws_cmd == V1_EVENT_END:
                    Log.d(tag, 'session ending')
                    # yeet this at the session server and don't check for a result, it doesn't matter
                    if submit_command(V1_FUNC_END + ident, 0, session_queue_ttl) is None:
                        Log.w(tag, 'failed to send session end to session server. queue full! is the server overloaded???')

                    # don't forget to respond to the event
                    if event is not None:
                        event.result = V1_COMM_FAIL
                    return

                # event?
                if event is None:
                    continue  # nothing to do

                # event valid?
                if not event.claim():
                    Log.w(tag, 'got expired event. server overloaded???')
                    continue

                # execute event
                Log.d(tag, 'session server command')

                click_ev = {
                    V1_FUNC_HELLO: V1_EVENT_HELLO,
                    V1_FUNC_NEXT: V1_EVENT_NEXT,
                    V1_FUNC_PREV: V1_EVENT_PREV,
                }.get(event.event_type)

                if click_ev is not None:
                    ws_send(click_ev)
                    event.result = V1_OK
                elif event.event_type == V1_FUNC_REROUTED:
                    Log.d(tag, 'rerouted!')
                    event.result = V1_OK
                    return
                elif event.event_type == V1_FUNC_EXPIRED:
                    Log.d(tag, 'expired!')
                    ws_send_err(V1_EVENT_ERR_EXPIRED, False)
                    event.result = V1_OK
                    return
                else:
                    # this should never happen
                    raise_panic(tag, 'unknown func from session server')

            except OSError as e:
                Log.v(tag, 'web socket died:', str(e))
                if event is not None:
                    event.result = V1_COMM_FAIL
                return
            except BaseException as e:
                if event is not None:
                    event.error = True
                raise e
            finally:
                if event is not None:
                    # set comm error if no result
                    if event.result is None and not event.error:
                        event.result = V1_COMM_FAIL
                    event.done()
    finally:
        # remove from table
        cb.gone = True
        with callback_table_lock:
            if callback_table.get(ident) == cb:
                callback_table.pop(ident)

        # flush remaining events
        ev = cb.pop(0)
        while ev is not None:
            ev.claim()
            ev.result = V1_COMM_FAIL
            ev.done()
            ev = cb.pop(0)


def do_clicker_loop_v1(tag, ident, poll):
    nonce_buffer = b''
    for _ in range(clicker_nonce_buff_size):   # fill with nulls, the client shouldn't send nulls anyway
        nonce_buffer += b'\x00'
    while True:
        # get next event
        p_ev = poll.poll(clicker_inactivity_timeout)

        if len(p_ev) == 0:  # timeout
            Log.v(tag, 'disconnecting inactive clicker')
            return

        # get func
        recv = uwsgi.websocket_recv_nb()
        if len(recv) == 0:
            continue

        # first byte is nonce
        nonce = recv[:1]
        command = recv[1:]

        # check nonce
        if nonce_buffer.find(nonce) != -1:
            continue  # duplicate event, discard

        # rotate nonce buffer
        nonce_buffer = nonce + nonce_buffer[:-1]

        func = {
            V1_EVENT_HELLO: V1_FUNC_HELLO,
            V1_EVENT_NEXT: V1_FUNC_NEXT,
            V1_EVENT_PREV: V1_FUNC_PREV,
        }.get(command)
        if func is None:
            # don't do anything, it could be an unsupported feature
            Log.d(tag, 'clicker sent unknown command')
            continue

        # send command
        cmd = submit_command(func + ident, 0, click_queue_ttl)
        if cmd is None:  # queue full
            Log.w(tag, 'command queue full!!! server overloaded?')
            ws_send_err(V1_EVENT_ERR_OVERLOADED, True, nonce)
            continue

        cmd.wait_for_result()
        result = cmd.result_code

        if result == V1_OK:
            ws_send(nonce + V1_EVENT_OK)
        elif result == V1_NO_SESSION:
            ws_send_err(V1_EVENT_ERR_EXPIRED, False, nonce)
            return
        elif result == V1_COMM_FAIL:
            ws_send_err(V1_EVENT_ERR_UNREACHABLE, True, nonce)
        elif result == V1_GEN_FAIL:
            ws_send_err(V1_EVENT_ERR_UNKNOWN, True, nonce)
            return
        else:
            raise_panic(tag, 'unexpected click result from session server')


def do_create_init_v1(tag, env):
    # serialize ip address
    addr = env['REMOTE_ADDR']
    if ':' in addr:
        addr_flag = 0x1.to_bytes()
        ip_addr_b = ipv6_addr_bytes(addr)
    else:
        addr_flag = 0x0.to_bytes()
        ip_addr_b = ipv4_addr_bytes(addr)

    # compile payload
    payload = (V1_FUNC_CREATE_SESSION
               + addr_flag
               + ip_addr_b)

    # make session
    cmd = submit_command(payload, 16, session_queue_ttl)
    if cmd is None:  # queue full
        Log.w(tag, 'command queue full!!! server overloaded?')
        ws_send_err(V1_EVENT_ERR_OVERLOADED)
        return
    cmd.wait_for_result()

    # errors
    if cmd.result_code == V1_NO_SESSION:
        Log.i(tag, 'session server refused, likely rate limited')
        ws_send_err(V1_EVENT_ERR_OVERLOADED)
        return
    elif cmd.result_code == V1_GEN_FAIL:
        Log.e(tag, 'session server encountered general failure')
        return
    elif cmd.result_code != V1_OK:
        raise_panic(tag, 'unexpected new session result')

    ident = cmd.result  # session uuid
    uuid_s = uuid.UUID(bytes=ident)
    tag += (uuid_s,)

    Log.i(tag, 'new session')
    ws_send(('uuid: %s' % uuid_s).encode('ascii'))

    # loop
    do_socket_loop_v1(tag, ident)


def do_resume_init_v1(tag, ident):
    Log.i(tag, 'session resuming')

    # compile payload
    payload = (V1_FUNC_RESUME + ident)

    # resume session
    cmd = submit_command(payload, 0, session_queue_ttl)
    if cmd is None:  # queue full
        Log.w(tag, 'command queue full!!! server overloaded?')
        ws_send_err(V1_EVENT_ERR_OVERLOADED, True)
        return
    cmd.wait_for_result()

    result = cmd.result_code
    if result == V1_NO_SESSION:
        ws_send_err(V1_EVENT_ERR_EXPIRED, False)
        return
    elif result == V1_GEN_FAIL:
        ws_send_err(V1_EVENT_ERR_UNKNOWN, True)
        return
    elif result != V1_OK:
        raise_panic(tag, 'unexpected session resume result')

    Log.v(tag, 'session resume')
    ws_send(V1_EVENT_RESUMED)

    # loop
    do_socket_loop_v1(tag, ident)


def do_clicker_init_v1(tag, ident, poll):
    Log.i(tag, 'clicker connecting')
    cmd = submit_command(V1_FUNC_HELLO + ident, 0, click_queue_ttl)

    if cmd is None:  # queue full
        Log.w(tag, 'command queue full!!! server overloaded?')
        ws_send_err(V1_EVENT_ERR_OVERLOADED, True, NULL)
        return

    cmd.wait_for_result()
    result = cmd.result_code

    if result == V1_NO_SESSION:
        ws_send_err(V1_EVENT_ERR_EXPIRED, False, NULL)
        return
    elif result == V1_COMM_FAIL:
        ws_send_err(V1_EVENT_ERR_UNREACHABLE, True, NULL)
        return
    elif result == V1_GEN_FAIL:
        ws_send_err(V1_EVENT_ERR_UNKNOWN, True, NULL)
        return
    elif result != V1_OK:
        raise_panic(tag, 'unexpected click result from session server')

    ws_send(NULL + V1_EVENT_OK)
    ws_send(NULL + V1_EVENT_NONCE_BUFFER_SIZE_PFX + str(clicker_nonce_buff_size).encode('ascii'))

    do_clicker_loop_v1(tag, ident, poll)


def do_socket_v1(tag, env, poll):
    action = uwsgi.websocket_recv_nb()
    if len(action) == 0:
        events = poll.poll(500)     # these should be sent in rapid succession
        if len(events) > 0:
            if events[0][1] & POLLIN:
                # this maybe could possibly block until the socket closes, but I can't do anything about that
                # issue: https://github.com/unbit/uwsgi/issues/1716
                Log.d(tag, 'using websocket_recv due to uwsgi bug')
                action = uwsgi.websocket_recv()
            else:
                Log.w(tag, 'client sent no action within 500 ms')

    if action == V1_EVENT_NEW:
        tag += ('new',)
        do_create_init_v1(tag, env)

    elif action.startswith(V1_EVENT_RESUME_PFX):
        tag += ('resume',)
        uuid_s = parse_uuid_from_client(tag, action, V1_EVENT_RESUME_PFX)
        if uuid_s is None:
            return
        tag += (uuid_s,)
        ident = uuid_s.bytes

        do_resume_init_v1(tag, ident)

    elif action.startswith(V1_EVENT_CLICKER_PFX):
        tag += ('clicker',)
        uuid_s = parse_uuid_from_client(tag, action, V1_EVENT_CLICKER_PFX, NULL)
        if uuid_s is None:
            return
        tag += (uuid_s,)
        ident = uuid_s.bytes

        do_clicker_init_v1(tag, ident, poll)

    else:
        # no
        Log.d(tag, 'unknown action sent by client:', action)


def do_socket(tag, env):
    try:
        # honestly 4 seconds might be too graceful
        poll = ge_poll()
        poll.register(uwsgi.connection_fd(), POLL_CHECK_FLAGS)
        events = poll.poll(4000)

        if len(events) == 0:
            Log.w(tag, 'received nothing within 4 seconds, closing connection')
            return

        ver = uwsgi.websocket_recv_nb()

        if ver == V1_WS_VERSION:
            tag += ('v1',)
            do_socket_v1(tag, env, poll)
        else:
            tag += ('v?',)
            ws_send_err(V1_EVENT_ERR_UNSUPPORTED, True)

    except OSError as e:
        if str(e) == 'unable to receive websocket message':
            Log.v(tag, 'web socket died, according to exception')
            return
        ws_send_err(V1_EVENT_ERR_UNKNOWN, True)
        raise e
    except BaseException as e:
        Log.e(tag, 'uncaught error in socket:', e)
        ws_send_err(V1_EVENT_ERR_UNKNOWN, True)
        raise e


def rest_v1(tag, env: dict, sr, headers, path: str, uuid_s: uuid.UUID):
    if path == '/hello':
        tag += ('hello',)
        func = V1_FUNC_HELLO
    elif path == '/next-slide':
        tag += ('next-slide',)
        func = V1_FUNC_NEXT
    elif path == '/prev-slide':
        tag += ('prev-slide',)
        func = V1_FUNC_PREV
    else:
        tag += ('unknown',)
        sr('404 Not Found', headers)
        return '404 Not Found'.encode('utf-8')

    cmd = submit_command(func + uuid_s.bytes, 0, click_queue_ttl)
    if cmd is None:  # queue full
        Log.w(tag, 'command queue full!!! server overloaded?')
        sr('500 Problem', headers)
        return 'try again'.encode('utf-8')
    cmd.wait_for_result()
    result = cmd.result_code

    # errors
    if result == V1_NO_SESSION:
        sr('401 Unauthorized', headers)
        return 'session expired'.encode('utf-8')
    elif result == V1_COMM_FAIL:
        sr('406 Not Acceptable', headers)
        return 'peer unavailable'.encode('utf-8')
    elif result == V1_GEN_FAIL:
        sr('500 Problem', headers)
        return 'internal error'.encode('utf-8')
    elif result != V1_OK:
        raise_panic(tag, 'unexpected click result')

    sr('200 OK', headers)
    return 'sent'.encode('utf-8')


def application(env, sr):
    headers = DEFAULT_HEADERS.copy()
    tag = ('app',)
    addr = env['REMOTE_ADDR']
    tag += (addr,)
    try:
        path = env['PATH_INFO']

        if path == '/':
            # hello world
            tag += ('/',)
            headers.append(CONTENT_PLAIN_TEXT)
            sr('418 I\'m a teapot', headers)
            yield "The server is running!".encode('utf-8')
        elif path.startswith('/api/v1/session'):
            tag += ('/api/v1/session',)
            headers.append(CONTENT_PLAIN_TEXT)

            if len(cors_origin_header_value) > 0:
                headers.append(('Access-Control-Allow-Origin', cors_origin_header_value))

            headers.append(('Access-Control-Allow-Headers', 'Authorization'))

            method = env.get('REQUEST_METHOD')
            if method == 'OPTIONS':
                sr('200 perhaps', headers)
                return
            elif method != 'GET':
                sr('405 Method Not Allowed', headers)
                yield '405 Method Not Allowed'.encode('utf-8')
                return
            
            tag += ('GET',)
            
            try:
                auth = env.get('HTTP_AUTHORIZATION')
                uuid_s = uuid.UUID(str(auth))
            except ValueError:
                sr('401 Unauthorized', headers)
                yield '401 Unauthorized'.encode('utf-8')
                return

            tag += ('auth valid',)

            yield rest_v1(tag, env, sr, headers, path[15:], uuid_s)
        elif path == '/api/v1/ws':
            tag += ('/api/v1/ws',)
            try:
                # ensure socket
                if 'HTTP_SEC_WEBSOCKET_KEY' not in env:
                    headers.append(CONTENT_PLAIN_TEXT)
                    headers.append(('Upgrade', 'websocket'))
                    sr('426 Upgrade Required', headers)
                    # not a socket
                    yield '426 Upgrade Required'.encode('utf-8')
                    return

                tag += ('ws',)
                
                # handshake
                uwsgi.websocket_handshake(env['HTTP_SEC_WEBSOCKET_KEY'], env.get('HTTP_ORIGIN', ''))
                tag += ('hs',)
                do_socket(tag, env)
            except OSError as e:
                if str(e) == 'unable to receive websocket message':
                    # eos
                    Log.v(tag, 'socket die')
                    return
                # other error
                Log.e(tag, 'error during websocket connection', e)
                raise e

        elif len(path) == 23:
            tag += ('b64',)
            headers.append(CONTENT_PLAIN_TEXT)
            try:
                uuid_b = base64.urlsafe_b64decode(path[1:] + '==')
            except binascii.Error:
                # invalid b64
                sr('404 Not Found', headers)
                # a static page would go here
                yield '404 Not Found'.encode('utf-8')
                return

            tag += ('valid encoding',)

            uuid_s = uuid.UUID(bytes=uuid_b)
            tag += (uuid_s,)
            headers.append(('Location', '/clicker?s=' + str(uuid_s)))
            sr('302 This way', headers)
            yield 'redirecting'.encode('utf-8')
        else:
            # simply doesn't exist
            tag += ('404',)
            headers.append(CONTENT_PLAIN_TEXT)
            sr('404 Not Found', headers)
            yield '404 Not Found'.encode('utf-8')
    except Exception as e:
        # catch-all
        Log.e(tag, 'uncaught exception', e)
        headers.append(CONTENT_PLAIN_TEXT)
        sr('500 Oops', headers)
        yield '500 Internal Server Error'.encode('utf-8')
        raise e


@postfork
def load_config():
    global session_server_timeout
    global session_server_socket
    global num_senders
    global num_listeners
    global cmd_queue_size
    global ws_queue_size
    global click_queue_ttl
    global session_queue_ttl
    global poll_time
    global ws_poll_time
    global cors_origin_header_value
    global clicker_nonce_buff_size
    global clicker_inactivity_timeout

    config = read_config()
    if config is None:
        Log.w(('load_config',), 'empty config, defaults will be used')
        config = {}

    ansi_logging(config.get('ansi_logging', DEFAULT_ANSI_LOGGING))
    log_level(config.get('log_level', DEFAULT_LOG_LEVEL))
    session_server_timeout = config.get('session_server_timeout', DEFAULT_SESSION_SERVER_TIMEOUT)
    session_server_socket = config.get('session_server_socket', DEFAULT_SESSION_SERVER_SOCKET)
    num_senders = config.get('sender_threads', DEFAULT_SENDER_THREADS)
    num_listeners = config.get('listener_threads', DEFAULT_LISTENER_THREADS)
    cmd_queue_size = config.get('cmd_queue_size', DEFAULT_LISTENER_THREADS)
    ws_queue_size = config.get('websocket_queue_size', DEFAULT_LISTENER_THREADS)

    click_queue_ttl = config.get('click_queue_ttl', DEFAULT_CLICK_QUEUE_TTL)
    session_queue_ttl = config.get('session_queue_ttl', DEFAULT_SESSION_QUEUE_TTL)

    poll_time = config.get('poll_time', DEFAULT_POLL_TIME)
    ws_poll_time = config.get('ws_poll_time', DEFAULT_WS_POLL_TIME)

    cors_origin_header_value = config.get('cors_origin_header_value', DEFAULT_CORS_ORIGIN_HEADER_VALUE)

    clicker_nonce_buff_size = config.get('clicker_nonce_buffer_size', DEFAULT_CLICKER_NONCE_BUFFER_SIZE)
    if clicker_nonce_buff_size > 254:
        Log.wtf(('load_config()',), 'clicker_nonce_buff_size SHOULD NOT BE GREATER THAN 254!!! You will drop events. This is your warning, fix your config!')

    clicker_inactivity_timeout = config.get('clicker_inactivity_timeout', DEFAULT_CLICKER_INACTIVITY_TIMEOUT)


# config vars
global session_server_timeout
global session_server_socket
global num_senders
global num_listeners
global cmd_queue_size
global ws_queue_size
global click_queue_ttl
global session_queue_ttl
global poll_time
global ws_poll_time
global cors_origin_header_value
global clicker_nonce_buff_size
global clicker_inactivity_timeout
listener_threads = []
sender_threads = []

send_queue = None
callback_table = {}
callback_table_lock = BoundedSemaphore(1)


class WebSocketCallback(Queue):
    def __init__(self):
        super().__init__(ws_queue_size)
        self.gone = False


class WebSocketEvent(QueueItem):
    def __init__(self, event_type, ttl):
        self.event_type = event_type
        super().__init__(ttl)

    def g_tag(self):
        return 'ws_event', self.created


class SessionSrvCommand(QueueItem):
    def __init__(self, payload, result_len, ttl):
        self.payload = payload
        self.result_len = result_len
        self.result_code = None
        super().__init__(ttl)

    def g_tag(self):
        return 'ss_cmd', self.created


def submit_command(payload, result_len, ttl):
    return send_queue.submit(SessionSrvCommand(payload, result_len, ttl))


def sessionsrv_send_loop(tag, sock):
    poll = std_poll()
    poll.register(sock, POLL_DEATH_FLAGS)
    while True:
        # get a command from top of the queue
        cmd = send_queue.pop(timeout=poll_time)
        if cmd is None:
            # check connection state while idle
            # gevent poll doesn't detect errors for some reason, but that's fine because this doesn't need to block
            p = poll.poll(0)
            if len(p) == 0 or not p[0][1] & POLL_DEATH_FLAGS:
                continue  # not dead

            # socket died
            raise BrokenPipeError('sender connection died according to poll')

        if not cmd.claim():
            # expired, server may be overloaded. throw it out.
            Log.w(tag, 'Server may be overloaded!!! expired cmd pulled from queue, it is', time() - cmd.created, 'seconds old!!!')
            continue

        Log.d(tag, 'command claimed!')

        try:
            # send it
            sock.sendall(cmd.payload)

            # get success/fail
            cmd.result_code = sock.recv(1)
            if cmd.result_code == V1_OK and cmd.result_len > 0:
                cmd.result = sock.recv(cmd.result_len)
        except BaseException as e:
            # if there are any connection problems, the socket is in an inconsistent state and must restart
            cmd.error = True
            raise e
        finally:
            # always inform of finish, otherwise it will hang forever after claiming
            cmd.done()


def sessionsrv_listen_loop(tag, sock: socket.socket):
    poll = ge_poll()
    poll.register(sock, POLL_CHECK_FLAGS)
    while True:
        # wait for event
        ev = poll.poll(int(poll_time * 1000))
        if len(ev) == 0:
            # timeout
            continue
        if ev[0][1] & POLL_DEATH_FLAGS:
            # socket died
            raise BrokenPipeError('sender connection died according to poll')

        event_type = sock.recv(1)
        uuid_b = sock.recv(16)

        # get callback
        cb = callback_table.get(uuid_b)
        if cb is None or cb.gone:
            sock.sendall(V1_COMM_FAIL)
            continue

        event = cb.submit(WebSocketEvent(event_type, click_queue_ttl))
        if event is None:  # queue full
            Log.w(tag, 'queue for session', uuid.UUID(bytes=uuid_b), 'full')
            sock.sendall(V1_GEN_FAIL)
            continue

        try:
            event.wait_for_result()
        except TimeoutError as e:
            Log.e(tag, 'timed out', str(e))
            sock.sendall(V1_GEN_FAIL)
            continue
        except OSError as e:
            Log.e(tag, 'failed to forward event:', str(e))
            sock.sendall(V1_GEN_FAIL)
            continue

        # send result
        sock.sendall(event.result)


def sessionsrv_loop(tag, listener: bool):
    while True:
        try:
            w_id = worker_identifier()
            w_id_len = len(w_id).to_bytes()  # max 1 byte

            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(session_server_timeout)
                sock.connect(session_server_socket)

                if listener:
                    sock.sendall(V1_INIT_LISTENER)
                else:
                    sock.sendall(V1_INIT_SENDER)

                sock.sendall(w_id_len)
                sock.sendall(w_id)
                Log.i(tag, 'connection up')
                if sock.recv(1) != V1_OK:
                    raise Panic('unexpected handshake result')

                if listener:
                    sessionsrv_listen_loop(tag, sock)
                else:
                    sessionsrv_send_loop(tag, sock)

        except ConnectionRefusedError as e:
            Log.e(tag, 'connection refused during connection loop! is the session server up?', str(e))
        except BrokenPipeError as e:
            Log.e(tag, 'connection died:', str(e))
        except TimeoutError as e:
            Log.e(tag, 'timeout during connection loop:', str(e))
        except BaseException as e:
            Log.wtf(tag, 'connection loop threw unexpected error', e)
        sleep(3)


def worker_identifier():
    # todo: config prefix for clusters with many uwsgi servers
    w_id = uwsgi.worker_id()
    w_id_b = w_id.to_bytes(math.ceil(math.ceil(math.log2(w_id+1))/8))
    if len(w_id_b) > 255:
        raise Panic('the worker id is too long!')  # the worker id is simply too long and the admin must be stopped

    return w_id_b


@postfork
def start_connection_pool():
    global send_queue
    if send_queue is None:
        send_queue = Queue(cmd_queue_size)
    else:
        Log.wtf('send queue already initialized‽')
        raise Panic('send queue already initialized')

    tag = ('sessionsrv_conn_pool', uwsgi.worker_id())
    Log.i(tag, 'starting session server connection pool')

    if len(listener_threads) + len(sender_threads) > 0:
        Log.wtf(tag, 'there are already threads running, abort!')
        raise Panic('cannot start connection pool, there already is a connection pool!!!!')

    # start senders
    tagg = tag + ('sender',)
    for i in range(num_senders):
        Log.d(tag, 'spawning sender', i)
        sender_threads.append(
                spawn(sessionsrv_loop, tagg + (i,), False))

    # start listeners
    tagg = tag + ('listener',)
    for i in range(num_listeners):
        Log.d(tag, 'spawning listener', i)
        listener_threads.append(
                spawn(sessionsrv_loop, tagg + (i,), True))

