import requests
import base64
import random
import time
import json

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
            r = requests.get(self._url + '/' + url, cookies={"credential": self._credential}, **kwargs)
        else:
            r = requests.get(self._url + '/' + url, **kwargs)
        r.raise_for_status()
        if r.status_code == 401:
            raise AccessDenied(url)
        return r

    def login(self, username="admin", password="admin"):
        """Log into the router.

        This will capture the credentials to be used in subsequent requests
        """
        r = self._get('login', params = params( { "arg": base64.b64encode(username + ':' + password) } ) )

        if not r.content:
            raise LoginFailed("Unknown reason. Sorry. Headers were {h}".format(h=r.headers))

        try:
            result = json.loads(base64.b64decode(r.content))
            print result
        except Exception:
            raise LoginFailed(r.content)

        self._credential = r.content
        self._username = username
        self._password = password

    def logout(self):
        if self._credential:
            self._credential = None
            self._username = None
            self._password = None
            self._get('/logout', params= params() )

    def __enter__(self):
        """Context manager support: Called on the way in"""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Context manager support: Called on the way out"""
        self.logout()
        return False

    def snmpGet(self, oid):
        r = json.loads(self._get("snmpGet", params = { "oids": oid }).content)
        return r[oid]

    def __str__(self):
        return "Hub(hostname=%s, username=%s)" % (self._hostname, self._username)

    def __nonzero__(self):
        return (self._credential != None)

    def __del__(self):
        self.logout()

    @property
    def connectionType(self):
        r = json.loads(self._get('checkConnType').content)
        return r["conType"]

    @property
    def language(self):
        return self.snmpGet("1.3.6.1.4.1.4115.1.20.1.1.5.6.0")

def __demo():
    with Hub(hostname = '192.168.0.1') as hub:
        print "Got", hub
        # print "foo", hub.snmpGet("1.3.6.1.4.1.4115.1.20.1.1.1.17.0")
        # print "bar", hub.snmpGet("1.3.6.1.4.1.4115.1.20.1.1.1.13")

#        hub.login(password='dssD04vy0z4t')
        print "Connection type", hub.connectionType
        print "Language:", hub.language
        for oid in [
                "1.3.6.1.4.1.4115.1.20.1.1.1.17.0",
                "1.3.6.1.4.1.4115.1.20.1.1.1.18.1.0",
                "1.3.6.1.4.1.4115.1.20.1.1.5.14.0",
                "1.3.6.1.4.1.4115.1.20.1.1.5.62.0",
                "1.3.6.1.4.1.4491.2.1.14.1.5.4.0"
                ]:
            print oid, hub.snmpGet(oid)

if __name__ == '__main__':
    __demo()
