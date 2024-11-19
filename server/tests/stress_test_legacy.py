from threading import Thread
import time
import traceback
from client import click
from event_constants import *
from basic_legacy_test import SingleSessionTest


ping_interval = 20

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


def loop(s_test):
    try:
        while not die:
            status = click(s_test.p, EVENT_HELLO)
            if status != 200:
                raise Exception('expected 200 for hello, got: %s' % str(status))
            event = s_test.p.pop(5)
            if event != EVENT_HELLO:
                raise Exception('expected hello event within 5 seconds, got: %s' % str(event))
            time.sleep(ping_interval)
    except BaseException as ex:
        print('loop threw!!!', ex)
        error.append(ex)
    finally:
        s_test.p.disconnect()
        s_test.p.loop.stop()


threads = []
main_thread_crashed = False

print('starting many sessions stress test')
try:
    while True:
        test = SingleSessionTest()
        test.new_session()

        t = Thread(target=loop, args=(test,))
        t.start()
        threads.append(t)

        if len(error) > 0:
            print('thread crashed! test is over')
            break
except BaseException as e:
    error.insert(0, e)
    print('main thread crashed! test is over')
    main_thread_crashed = True
finally:
    die = True

print('waiting for threads to die')
for thread in threads:
    thread.join()

time.sleep(3)

print()
print()
print()

print('main thread crash:', main_thread_crashed)
if main_thread_crashed:
    print('stack trace:')
    traceback.print_exception(error.pop(0))

print()
print()
print()

print('session thread errors:')
for e in error:
    traceback.print_exception(e)

print()
print()
print()


print('reached a maximum of', len(threads), 'concurrent clients')


