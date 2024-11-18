from common.log import Log


class Panic(BaseException):
    pass    # for things that are not supposed to happen


def raise_panic(tag, msg):
    e = Panic(msg)
    Log.wtf(tag, msg, e)
    raise e
