# aka "pool que" because... ok I admit it's not that clever.
from time import time
from common.exceptions import *
from threading import Semaphore as std_Semaphore
from gevent.lock import Semaphore as g_Semaphore

Semaphore = std_Semaphore


# switch to using gevent locks for uwsgi
# todo: test again and make a final decision if gevent is faster or slower for sessionsrv
def use_gevent():
    global Semaphore
    Semaphore = g_Semaphore


# a generic async event queue used for funnelling events through a small number of sockets.
# this is because the uwsgi app is better for holding lots of connections,
# but the session server is better for keeping a central place for storing things.
class Queue(object):
    def __init__(self, max):
        self._queue = []
        self._queue_lock = Semaphore(0)
        self._queue_max_lock = Semaphore(max)

    def submit(self, item):
        if not self._queue_max_lock.acquire(blocking=False):
            return None  # max capacity

        self._queue.append(item)
        self._queue_lock.release()
        return item

    def pop(self, timeout=5):
        # get a command from top of the queue
        if not self._queue_lock.acquire(timeout=timeout):
            return None
        self._queue_max_lock.release()
        return self._queue.pop(0)


class QueueItem(object):
    def __init__(self, ttl):
        self.created = time()
        self.ttl = ttl
        self.happening = False
        self.sema = Semaphore(0)
        self.result = None
        self.error = False

    def check_validity(self):
        # it is important to expire these, too much delay is unacceptable
        # the user simply cannot cope with a 20 second delay to the next slide, that would be ridiculous
        return self.happening or time() - self.created <= self.ttl

    def claim(self):
        if self.happening:
            raise Panic('invalid state, already claimed! race condition‽‽')

        # order matters to avoid race conditions for time-based expiration.
        # this way it doesn't need to block
        self.happening = True  # could be happening
        if time() - self.created <= self.ttl:  # check if expired
            return True
        self.happening = False  # jk not happening
        return False

    # generate a log tag
    def g_tag(self):
        return 'queue_item', self.created

    def done(self):
        self.sema.release()

    def wait_for_result(self):
        # acquire the 0 semaphore, the connection loop will release when it's finished
        while self.check_validity():
            timeout = max((self.ttl - time() + self.created), 0.1)
            if self.sema.acquire(timeout=timeout):
                # should be done
                if self.error:
                    # there was some kind of error with communications
                    raise OSError('failure during communications')

                return

        raise TimeoutError('queue item expired before it could run. server may be overloaded!!!')


