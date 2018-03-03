import requests
import base64
import random
import time
import json

class LoginFailed(IOError):
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

class Session:

    def __init__(self, hostname):

        self._credential = None
        self._url = 'http://' + hostname
        self._hostname = hostname

    def _get(self, url, **kwargs):
        """Shorthand for requests.get"""
        if self._credential:
            return requests.get(self._url + '/' + url, cookies={"credential": self._credential}, **kwargs)
        else:
            return requests.get(self._url + '/' + url, **kwargs)

    def login(self, username="admin", password="admin"):
        """Log into the router.

        This will capture the credentials to be used in subsequent requests
        """
        r = self._get('login', params = params( { "arg": base64.b64encode(username + ':' + password) } ) )
        r.raise_for_status()

        if not r.content:
            raise LoginFailed("Unknown reason. Sorry. Headers were {h}".format(h=r.headers))

        try:
            result = json.loads(base64.b64decode(r.content))
            print result
        except Exception:
            raise LoginFailed(r.content)

        self._credential = r.content

    def logout(self):
        if self._credential:
            print "Logging out"
            self._credential = None
            r = requests.get('%s/logout' % self._url,
                                 params= params() )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.logout()
        return False

    def snmpGet(self, oid):
        r = requests.get("%s/snmpGet" % self._url, params = params( { "oids": oid }  ))
        print "Response", r
        print "Headers", r.headers
        print "Content", r.content

    def __str__(self):
        return "Session(hostname=%s)" % self._hostname

    def __nonzero__(self):
        return (self._credential != None)

    def __del__(self):
        self.logout()

def __demo():
    with Session(hostname = '192.168.0.1') as s:
        print "Got", s
        # print "foo", s.snmpGet("1.3.6.1.4.1.4115.1.20.1.1.1.17.0")
        # print "bar", s.snmpGet("1.3.6.1.4.1.4115.1.20.1.1.1.13")

        s.login(password='dssD04vy0z4t')
        print "serial number", s.snmpGet("1.3.6.1.4.1.4115.1.20.1.1.5.8");
        print "Would do stuff with", s

if __name__ == '__main__':
    __demo()
