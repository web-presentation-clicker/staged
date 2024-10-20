import traceback
import time
from threading import Lock, Thread, Semaphore, Condition


_ANSI_RESET = '\u001b[0m'

_ANSI_B = '\u001b[1m'
_ANSI_RESET_B = '\u001b[0;1m'
_ANSI_RED_B = '\u001b[31;1m'
_ANSI_GREEN_B = '\u001b[32;1m'
_ANSI_YELLOW_B = '\u001b[33;1m'
_ANSI_BLUE_B = '\u001b[34;1m'
_ANSI_MAGENTA_B = '\u001b[35;1m'

_ANSI_GRAY = '\u001b[2m'
_ANSI_CYAN = '\u001b[36m'

_print_queue_max = 10
_PRINT_SEMAPHORE = Semaphore(_print_queue_max)
_PRINT_CONDITION = Condition(Lock())
_print_thread = None
_print_queue = []


def _log_ansi(pfx, ansi, *args, **kwargs):
    t = _ANSI_CYAN + time.strftime(_time_format) + _ANSI_RESET_B
    tag = ''
    if len(args) > 1:
        if isinstance(args[0], tuple):
            tag = _ANSI_GRAY + '(' + ', '.join([str(tg) for tg in args[0]]) + ')' + _ANSI_RESET_B
            args = args[1:]

        end = _ANSI_RESET + kwargs.get('end', '\n')
        if isinstance(args[-1], BaseException):
            end = '\n' + ''.join(traceback.format_exception(args[-1])) + end
            args = args[:-1]
        kwargs['end'] = end
    pfx = ansi + pfx + _ANSI_RESET_B
    args = ('%s[%s][%s]%s:%s' % (_ANSI_B, t, pfx, tag, ansi),) + args
    _printer(*args, **kwargs)


def _log_plain(pfx, _, *args, **kwargs):
    t = time.strftime(_time_format)
    tag = ''
    if len(args) > 1:
        if isinstance(args[0], tuple):
            tag = '(' + ', '.join([str(tg) for tg in args[0]]) + ')'
            args = args[1:]

        end = kwargs.get('end', '\n')
        if isinstance(args[-1], BaseException):
            end = '\n' + ''.join(traceback.format_exception(args[-1])) + end
            args = args[:-1]
        kwargs['end'] = end
    args = ('[%s][%s]%s:' % (t, pfx, tag),) + args
    _printer(*args, **kwargs)


def _print_loop():
    while True:
        if len(_print_queue) > 0:
            if len(_print_queue) >= _print_queue_max:
                print('Warning: print queue full!!!')
            args, kwargs = _print_queue.pop(0)
            print(*args, **kwargs)
            _PRINT_SEMAPHORE.release()
        else:
            with _PRINT_CONDITION:
                while len(_print_queue) == 0:
                    _PRINT_CONDITION.wait()


def _concurrent_printer(*args, **kwargs):
    _PRINT_SEMAPHORE.acquire()
    with _PRINT_CONDITION:
        _print_queue.append((args, kwargs))
        _PRINT_CONDITION.notify()


# aosp-style logger because it works well enough
# in addition, when the first arg is a tuple it's used as a tag, but it can contain detailed state information too
# also, if the last arg is an exception, a stack trace is printed
class Log:
    def wtf(*args, **kwargs):
        if _log_level < 0:
            return
        _log('WTF‽', _ANSI_RED_B, *args, **kwargs)

    def e(*args, **kwargs):
        if _log_level < 1:
            return
        _log('ERR!', _ANSI_RED_B, *args, **kwargs)

    def w(*args, **kwargs):
        if _log_level < 2:
            return
        _log('WARN', _ANSI_YELLOW_B, *args, **kwargs)

    def i(*args, **kwargs):
        if _log_level < 3:
            return
        _log('INFO', _ANSI_BLUE_B, *args, **kwargs)

    def v(*args, **kwargs):
        if _log_level < 4:
            return
        _log('VERB', _ANSI_GREEN_B, *args, **kwargs)

    def d(*args, **kwargs):
        if _log_level < 5:
            return
        _log('DEBG', _ANSI_MAGENTA_B, *args, **kwargs)


# configurations
_log = _log_plain
_printer = print
_block_logging_set = False

_log_level = 5
_time_format = '%D %T'


def ansi_logging(enable: bool):
    global _log
    if enable:
        _log = _log_ansi
    else:
        _log = _log_plain


def concurrent_logging(enable: bool):
    global _block_logging_set
    global _printer
    global _print_thread

    if _block_logging_set:
        raise Exception('block_logging() can only be set once')
    _block_logging_set = True

    if enable:
        _printer = _concurrent_printer
        _print_thread = Thread(target=_print_loop)
        _print_thread.start()
        # todo: the print thread also needs to be killed when the application is shut down
    else:
        _printer = print


def log_level(level):
    global _log_level
    _log_level = level


def time_format(f):
    global _time_format
    _time_format = f

