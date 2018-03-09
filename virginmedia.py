#!/usr/bin/python

import requests
import base64
import random
import time
import json
from types import MethodType

class LoginFailed(IOError):
    def __init__(self, msg):
        IOError.__init__(self, msg)

class AccessDenied(IOError):
    def __init__(self, msg):
        IOError.__init__(self, msg)

def params(dict = None):
    result = {
        "_": int(round(time.time() * 1000)),
        "_n": "%05d" % random.randint(1,32768)
        }
    if dict:
        result.update(dict)
    return result

class Hub:

    def __init__(self, hostname='192.168.0.1', **kwargs):

        self._credential = None
        self._url = 'http://' + hostname
        self._hostname = hostname
        self._username = None
        self._password = None
        if kwargs:
            self.login(**kwargs)

    def _get(self, url, **kwargs):
        """Shorthand for requests.get"""
        if self._credential:
            r = requests.get(self._url + '/' + url, cookies={"credential": self._credential}, timeout=10, **kwargs)
        else:
            r = requests.get(self._url + '/' + url, timeout=10, **kwargs)
        r.raise_for_status()
        if r.status_code == 401:
            raise AccessDenied(url)
        return r

    def login(self, username=None, password="admin"):
        """Log into the router.

        This will capture the credentials to be used in subsequent requests.

        If no username is given, it will query the router for the
        default username first.
        """
        if not username:
            username = self.authUserName

        r = self._get('login', params = params( { "arg": base64.b64encode(username + ':' + password) } ) )

        if not r.content:
            raise LoginFailed("Unknown reason. Sorry. Headers were {h}".format(h=r.headers))

        try:
            attrs = json.loads(base64.b64decode(r.content))
            print attrs
        except Exception:
            raise LoginFailed(r.content)

        if attrs.get("gwWan") == "f" and attrs.get("conType") == "LAN":
            if attrs.get("muti") == "GW_WAN":
                raise LoginFailed("Remote user has already logged in, please wait...")
            elif attrs.get("muti") == "LAN":
                raise LoginFailed("Other local user has already logged in, please wait...")
        elif attrs.get("gwWan") == "t":
            if attrs.get("muti") == "LAN":
                raise LoginFailed("Local user has already logged in, please wait...")
            elif attrs.get("muti") == "GW_WAN":
                raise LoginFailed("Other remote user has already logged in, please wait...")

        self._credential = r.content
        self._username = username
        self._password = password

    def logout(self):
        if self._credential:
            try:
                self._get('logout', params= params() )
            finally:
                self._credential = None
                self._username = None
                self._password = None

    def __enter__(self):
        """Context manager support: Called on the way in"""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Context manager support: Called on the way out"""
        self.logout()
        return False

    def snmpGet(self, oid):
        r = self._get("snmpGet", params = { "oid": oid })
        c = r.content
        try:
            r = json.loads(c)
        except ValueError as e:
            print 'Response content:', c
            raise
        return r[oid]

    def __str__(self):
        return "Hub(hostname=%s, username=%s)" % (self._hostname, self._username)

    def __nonzero__(self):
        return (self._credential != None)

    def __del__(self):
        self.logout()

    def _walk(self, oid):
        r = self._get('walk', params={ "oids": oid })
        return json.loads(r.content)

    @property
    def connectionType(self):
        r = json.loads(self._get('checkConnType').content)
        return r["conType"]


_snmpAttributes = [
    ("docsisBaseCapability",                "1.3.6.1.2.1.10.127.1.1.5"),
    ("docsBpi2CmPrivacyEnable",             "1.3.6.1.2.1.126.1.1.1.1.1"),
    ("configFile",                          "1.3.6.1.2.1.69.1.4.5"),
    ("wanIPProvMode",                       "1.3.6.1.4.1.4115.1.20.1.1.1.17.0"),
    ("DSLiteWanEnable",                     "1.3.6.1.4.1.4115.1.20.1.1.1.18.1.0"),
    ("customID",                            "1.3.6.1.4.1.4115.1.20.1.1.5.14.0"),
    ("authUserName",                        "1.3.6.1.4.1.4115.1.20.1.1.5.16.1.2.1"),  # The admin user name to log in as
    ("authAccountEnabled",                  "1.3.6.1.4.1.4115.1.20.1.1.5.16.1.6.2"),
    ("language",                            "1.3.6.1.4.1.4115.1.20.1.1.5.6.0"),
    ("firstInstallWizardCompletionStatus",  "1.3.6.1.4.1.4115.1.20.1.1.5.62.0"),
    ("esafeErouterInitModeCtrl",            "1.3.6.1.4.1.4491.2.1.14.1.5.4.0"),
]

for name,oid in _snmpAttributes:
    def newGetter(name, oid):
        def getter(self):
            return self.snmpGet(oid)
        return property(MethodType(getter, None, Hub), None, None, name)
    setattr(Hub, name, newGetter(name, oid))

# Some properties cannot be snmpGet()'ed - they have to be snmpWalk()'ed instead??
_snmpWalks = [
    ("webAccessTable", "1.3.6.1.4.1.4115.1.20.1.1.6.7")
]

for name, oid in _snmpWalks:
    def newGetter(name, oid):
        def getter(self):
            return self._walk(oid)
        return property(MethodType(getter, None, Hub), None, None, name)
    setattr(Hub, name, newGetter(name, oid))

def _demo():
    global _snmpAttributes
    with Hub(hostname = '192.168.0.1') as hub:
        print "Got", hub

        hub.login(password='dssD04vy0z4t')
        for name,oid in _snmpAttributes + _snmpWalks:
            print '%s:' % name, '"%s"' % getattr(hub, name)

        print "Connection type", hub.connectionType

def _describe_oids():
    with open('oid-list') as fp, Hub() as hub:
        hub.login(password='dssD04vy0z4t')
        for oid in fp:
            oid = oid.rstrip('\n')
            try:
                r = hub.snmpGet(oid)
                print oid, '=', hub.snmpGet(oid)
            except Exception as e:
                print oid, ':', e

if __name__ == '__main__':
    #    _describe_oids()
    _demo()


# Local Variables:
# compile-command: "./virginmedia.py"
# End:
