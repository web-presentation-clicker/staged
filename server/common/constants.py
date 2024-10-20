from select import POLLIN, POLLERR, POLLHUP, POLLRDHUP, POLLNVAL

# init sequence
V1_INIT = 0xF1.to_bytes()
V1_INIT_LISTENER = V1_INIT + 0x01.to_bytes()
V1_INIT_SENDER = V1_INIT + 0x02.to_bytes()

# functions
V1_FUNC_CREATE_SESSION = 0x91.to_bytes()
V1_FUNC_RESUME = 0x92.to_bytes()
V1_FUNC_DISOWN = 0x93.to_bytes()
V1_FUNC_NEXT = 0x81.to_bytes()
V1_FUNC_PREV = 0x82.to_bytes()
V1_FUNC_HELLO = 0x83.to_bytes()


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
V1_EVENT_NEW = 'new'
V1_EVENT_RESUME_PFX = 'resume: '
V1_EVENT_HELLO = 'hello'
V1_EVENT_NEXT = 'next_slide'
V1_EVENT_PREV = 'prev_slide'

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
DEFAULT_CREATE_QUEUE_TTL = 5
DEFAULT_RESUME_QUEUE_TTL = 7

DEFAULT_POLL_TIME = 10
DEFAULT_WS_POLL_TIME = 5

DEFAULT_MAINTENANCE_INTERVAL = 60
DEFAULT_SESSION_TIMEOUT = 500

