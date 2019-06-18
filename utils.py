#!/usr/bin/python3
"""Misc utilities that did not fit anywhere nicely.

These are intended for internal use only: The API is subject to
change.

"""
import functools

def debug(func):
    """A function decorator that will print function calls and their results"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        print("calling {0}(args={1}, kwargs={2})", func, args, kwargs)
        res = func(*args, **kwargs)
        print("{f}(args={a}, kwargs={kw}) => {res}".format(f=func.__name__,
                                                           a=args,
                                                           kw=kwargs,
                                                           res=res))
        return res
    return wrapper
