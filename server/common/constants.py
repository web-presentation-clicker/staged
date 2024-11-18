from select import POLLIN, POLLERR, POLLHUP, POLLRDHUP, POLLNVAL

# init sequence
V1_INIT = 0xF1.to_bytes()
V1_INIT_LISTENER = V1_INIT + 0x01.to_bytes()
V1_INIT_SENDER = V1_INIT + 0x02.to_bytes()

# functions
V1_FUNC_CREATE_SESSION = 0x91.to_bytes()
V1_FUNC_RESUME = 0x92.to_bytes()
V1_FUNC_NEXT = 0x81.to_bytes()
V1_FUNC_PREV = 0x82.to_bytes()
V1_FUNC_HELLO = 0x83.to_bytes()
V1_FUNC_END = 0x84.to_bytes()
V1_FUNC_EXPIRED = 0x85.to_bytes()
V1_FUNC_REROUTED = 0x86.to_bytes()

V1_FUNC_NAME_MAP = {
    V1_FUNC_CREATE_SESSION: 'create session',
    V1_FUNC_RESUME: 'resume',
    V1_FUNC_NEXT: 'next slide',
    V1_FUNC_PREV: 'prev slide',
    V1_FUNC_HELLO: 'hello',
    V1_FUNC_END: 'end',
    V1_FUNC_EXPIRED: 'expired',
    V1_FUNC_REROUTED: 'rerouted',
}
V1_CLICK_FUNCS = {V1_FUNC_HELLO, V1_FUNC_NEXT, V1_FUNC_PREV}


# responses
V1_OK = 0x11.to_bytes()
# error responses
V1_NO_SESSION = 0X01.to_bytes()
V1_COMM_FAIL = 0x02.to_bytes()
V1_GEN_FAIL = 0x03.to_bytes()

# misc
V1_PING = 0X12.to_bytes()
NULL = 0x00.to_bytes()

# websocket events
V1_WS_VERSION = b'v1'
V1_EVENT_NEW = b'new'
V1_EVENT_RESUME_PFX = b'resume: '
V1_EVENT_RESUMED = b'resumed'
V1_EVENT_CLICKER_PFX = b'click: '
V1_EVENT_HELLO = b'hello'
V1_EVENT_NEXT = b'next_slide'
V1_EVENT_PREV = b'prev_slide'
V1_EVENT_END = b'end'
V1_EVENT_OK = b'ok'

V1_EVENT_ERR_PFX = b'ERR: '
V1_EVENT_ERR_EXPIRED = b'session expired'
V1_EVENT_ERR_CLIENT = b'client error'
V1_EVENT_ERR_UNREACHABLE = b'peer unavailable'
V1_EVENT_ERR_OVERLOADED = b'try again'  # vague error message
V1_EVENT_ERR_UNSUPPORTED = b'unsupported client'
V1_EVENT_ERR_UNKNOWN = b'internal error'
V1_EVENT_ERR_NO_SESSION_SFX = b'.'

# poll flags
POLL_DEATH_FLAGS = POLLHUP | POLLRDHUP | POLLNVAL | POLLERR
POLL_CHECK_FLAGS = POLLIN | POLL_DEATH_FLAGS


# config defaults
DEFAULT_ANSI_LOGGING = False
DEFAULT_LOG_LEVEL = 3
DEFAULT_SESSION_SERVER_TIMEOUT = 5
DEFAULT_SESSION_SERVER_SOCKET = '/run/staged/session.socket'

DEFAULT_SENDER_THREADS = 4
DEFAULT_LISTENER_THREADS = 4

DEFAULT_CMD_QUEUE_SIZE = 20
DEFAULT_WS_QUEUE_SIZE = 4

DEFAULT_EVENT_QUEUE_SIZE = 20

DEFAULT_CLICK_QUEUE_TTL = 5
DEFAULT_SESSION_QUEUE_TTL = 7

DEFAULT_POLL_TIME = 10
DEFAULT_WS_POLL_TIME = 5

DEFAULT_MAINTENANCE_INTERVAL = 60
DEFAULT_SESSION_TIMEOUT = 500

DEFAULT_CORS_ORIGIN_HEADER_VALUE = ''

