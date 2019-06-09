#!/usr/bin/python

import requests
import base64
import random
import time
import json
import datetime
from types import MethodType
import sys

class LoginFailed(IOError):
    def __init__(self, msg):
        IOError.__init__(self, msg)

class AccessDenied(IOError):
    def __init__(self, msg):
        IOError.__init__(self, msg)

def _extract_ip(ip):
    """Extract an IP address to a sensible format.

    The router encodes IPv4 addresses in hex, prefixed by a dollar
    sign, e.g. "$c2a80464" => 192.168.4.100
    """
    return (       str(int(ip[1:3],base=16))
           + '.' + str(int(ip[3:5],base=16))
           + '.' + str(int(ip[5:7],base=16))
           + '.' + str(int(ip[7:9],base=16)) )

def _extract_ipv6(ip):
    """Extract an IPv6 address to a sensible format

    The router encodes IPv6 address in hex, prefixed by a dollar sign
    """
    if ip == "$00000000000000000000000000000000":
        return None
    res = ip[1:5]
    for x in range(5, 30, 4):
        res += ':' + ip[x:x+4]
    return res

def _extract_mac(mac):
    res = mac[1:3]
    for x in range(3,13,2):
        res += ':' + mac[x:x+2]
    return res

def _extract_date(vmdate):
    # Dates (such as the DHCP lease expiry time) are encoded somewhat stranger
    # than even IP addresses:
    #
    # E.g. "$07e2030e10071100" is:
    #      0x07e2 : year = 2018
    #          0x03 : month = March
    #            0x0e : day-of-month = 14
    #              0x10 : hour = 16 (seems to at least use 24hr clock!)
    #                0x07 : minute = 07
    #                  0x11 : second = 17
    #                    0x00 : junk
    year = int(vmdate[1:5], base=16)
    month = int(vmdate[5:7], base=16)
    dom = int(vmdate[7:9], base=16)
    hour = int(vmdate[9:11], base=16)
    minute = int(vmdate[11:13], base=16)
    second = int(vmdate[13:15], base=16)
    return datetime.datetime(year, month, dom, hour, minute, second)

class Namespace(object):
    def __init__(self, keyvals):
        self._keyvals = keyvals
        for key in keyvals:
            setattr(self, key, keyvals[key])

    def __str__(self):
        return "NameSpace(" + str(self._keyvals) + ")"

    def prettyPrint(self, prefix=None):
        for key in sorted(self._keyvals):
            if prefix:
                print prefix, key, ':', getattr(self, key)
            else:
                print key, ':', getattr(self, key)


_demo_properties = set()

def cache_result(function):
    """A function decorator to cache function results.

    This will only work for instance methods"""
    def wrapper(*args, **kwargs):
        self = args[0]
        if not hasattr(self, '__result_cache'):
            setattr(self, '__result_cache', {})
        if function.__name__ in self.__result_cache:
            return self.__result_cache[function.__name__]

        result = self.__result_cache[function.__name__] = function(*args, **kwargs)
        return result
    return wrapper


class Hub(object):
    """A Virgin Media Hub3.

    This class provides a pythonic interface to the Virgin Media Hub3.

    """
    def __init__(self, hostname='192.168.0.1', **kwargs):

        self._credential = None
        self._url = 'http://' + hostname
        self._hostname = hostname
        self._username = None
        self._password = None
        self._nonce = {
            "_": int(round(time.time() * 1000)),
            "_n": "%05d" % random.randint(10000,99999)
            }
        self._nonce_str = "_n=%s&_=%s" % (self._nonce["_n"], self._nonce["_"])
        self.counters = { }
        if kwargs:
            self.login(**kwargs)

    def _bump_counter(self, name, by=1):
        """Increase a counter by (usually) 1.

        If the counter does not exist yet, it will be created"""
        if name in self.counters:
            self.counters[name] += by
        else:
            self.counters[name] = by

    def _collect_stats(function):
        """A function decorator to count how many calls are done to the function.

        it also collects timing information
        """
        def wrapper(*args, **kwargs):
            self = args[0]
            self._bump_counter(function.__name__ + ':calls')
            start = time.time()
            result = function(*args, **kwargs)
            self._bump_counter(function.__name__ + ':secs', by=time.time()-start)
            return result
        return wrapper

    @_collect_stats
    def _get(self, url, retry401=5, retry500=3, **kwargs):
        """Shorthand for requests.get.

        If the request fails with HTTP 500, it will be retried after a
        short wait with exponential back-off.

        This also tries to work around bugs in the Virgin Media Hub3
        firmware: Requests can (randomly?) fail with HTTP status 401
        (Unauthorized) for no apparent reason.  Logging in again before
        retrying usually solves that.
        """
        sleep = 1
        while True:
            if self._credential:
                r = requests.get(self._url + '/' + url, cookies={"credential": self._credential}, timeout=10, **kwargs)
            else:
                r = requests.get(self._url + '/' + url, timeout=10, **kwargs)
            self._bump_counter('received_http_' + str(r.status_code))
            if r.status_code == 401:
                retry401 -= 1
                if retry401 > 0 and self.is_loggedin:
                    print "Got http status %s - Retrying after logging in again" % (r.status_code)
                    self.login(username=self._username, password=self._password)
                    self._bump_counter('_get_retries_401')
                    continue
            if r.status_code == 500:
                retry500 -= 1
                if retry500 > 0:
                    print "Got http status %s - retrying after %s seconds" % (r.status_code, sleep)
                    time.sleep(sleep)
                    sleep *= 2
                    self._bump_counter('_get_retries_500')
                    self._bump_counter('_get_retries_500_sleep_secs', by=sleep)
                    continue
            break
        r.raise_for_status()
        if r.status_code == 401:
            raise AccessDenied(url)
        return r

    @_collect_stats
    def _params(self, keyvalues):
        res = { }
        res.update(self._nonce)
        res.update(keyvalues)
        return res

    @_collect_stats
    def login(self, username=None, password="admin"):
        """Log into the router.

        This will capture the credentials to be used in subsequent requests.

        If no username is given, it will query the router for the
        default username first.
        """
        if not username:
            username = self.authUserName

        r = self._get('login', retry401=0, params = self._params( { "arg": base64.b64encode(username + ':' + password) } ) )

        if not r.content:
            raise LoginFailed("Unknown reason. Sorry. Headers were {h}".format(h=r.headers))

        try:
            attrs = json.loads(base64.b64decode(r.content))
        except Exception:
            raise LoginFailed(r.content)

        if attrs.get("gwWan") == "f" and attrs.get("conType") == "LAN":
            if attrs.get("muti") == "GW_WAN":
                print "Warning: Remote user has already logged in: Some things may fail with HTTP 401..."
            elif attrs.get("muti") == "LAN":
                print "Warning: Other local user has already logged in: Some things may fail with HTTP 401..."
        elif attrs.get("gwWan") == "t":
            if attrs.get("muti") == "LAN":
                print "Warning: Local user has already logged in: Some things may fail with HTTP 401..."
            elif attrs.get("muti") == "GW_WAN":
                print "Warning: Other remote user has already logged in: Some things may fail with HTTP 401..."

        self._credential = r.content
        self._username = username
        self._password = password

    @property
    def is_loggedin(self):
        return self._credential != None

    @_collect_stats
    def logout(self):
        if self.is_loggedin:
            try:
                self._get('logout', retry401=0, retry500=0, params= self._nonce )
            finally:
                self._credential = None
                self._username = None
                self._password = None

    @_collect_stats
    def __enter__(self):
        """Context manager support: Called on the way in"""
        return self

    @_collect_stats
    def __exit__(self, exc_type, exc_value, traceback):
        """Context manager support: Called on the way out"""
        try:
            self.logout()
        except requests.exceptions.HTTPError as err:
            # Avoid raising exceptions on the way out if our app had a problem
            if not exc_type:
                raise
        return False

    @_collect_stats
    def snmpGet(self, oid):
        r = self.snmpGets(oids = [ oid ])
        return r[oid]

    @_collect_stats
    def snmpGets(self, oids):
        r = self._get("snmpGet?oids=" + ';'.join(oids) + ';&' + self._nonce_str )
        c = r.content
        try:
            r = json.loads(c)
        except ValueError as e:
            print 'Response content:', c
            raise
        return r

    def __str__(self):
        return "Hub(hostname=%s, username=%s)" % (self._hostname, self._username)

    def __nonzero__(self):
        return (self._credential != None)

    @_collect_stats
    def __del__(self):
        self.logout()

    @_collect_stats
    def snmpWalk(self, oid):
        jsondata = self._get('walk?oids=%s;%s' % (oid, self._nonce_str)).content

        # The hub has an ANNOYING bug: Sometimes the json result include the single line
        #
        #    "Error in OID formatting!"
        #
        # which really messes up the JSON decoding (!). Since the IOD
        # is obviously correct, and the hub happily returns other
        # data, our only recourse is to remove such lines before
        # attempting to interpret it as JSON... (sigh).
        #
        jsondata = "\n".join(filter(lambda x:x != "Error in OID formatting!", jsondata.split("\n")))

        # print "snmpWalk of %s:" % oid
        # print jsondata
        result = json.loads(jsondata)
        # Strip off the final ANNOYING "1" entry!
        if result.get("1") == "Finish":
            del result["1"]
        return result

    def _listed_property(func):
        """A function decorator which adds the function to the list of known attributes"""
        _demo_properties.add(func.__name__)
        return func

    @property
    @_listed_property
    def connectionType(self):
        r = json.loads(self._get('checkConnType').content)
        return r["conType"]

    @property
    @_listed_property
    def lanIPAddress(self):
        r = json.loads(self._get('getPreLoginData').content)
        return r["gwaddr"]

    @property
    @_listed_property
    def configFile(self):
        r = json.loads(self._get('getRouterStatus').content)
        return r["1.3.6.1.2.1.69.1.4.5.0"]

    def _snmpProperty(oid):
        """A function decorator to present an MIB value as an attribute.

        The function will receive an extra parameter: "snmpValue" in
        which it gets passed the value of the oid as retrieved from
        the hub.
        """
        def real_wrapper(function):
            def wrapper(*args, **kwargs):
                self = args[0]
                kwargs["snmpValue"] = self.snmpGet(oid)
                return function(*args, **kwargs)
            _demo_properties.add(function.__name__)
            return property(wrapper)
        return real_wrapper

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.5.14.0")
    def customerID(self, snmpValue):
        "The value 8 appears to indicate Virgin Media"
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.3.1")
    def wanIPv4Address(self, snmpValue):
        """The current external IP address of the hub"""
        x = _extract_ip(snmpValue)
        if x == "0.0.0.0": return None
        else: return x

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.11.2.1.3.1")
    def dns_servers(self, snmpValue):
        """DNS servers used by the hub.

        This will probably also be the DNS servers the hub hands out
        in DHCP responses.

        For the virgin media Hub3 this always appears to be SINGLE dns
        server IP address, except when disconnected from the internet,
        in which case it may be None.
        """
        if snmpValue:
            return [ _extract_ip(snmpValue) ]
        else:
            return None

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.6.1")
    def wanIPv4Gateway(self, snmpValue):
        """Default gateway of the hub"""
        x = _extract_ip(snmpValue)
        if x == "0.0.0.0": return None
        else: return x

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.5.10.0")
    def hardwareVersion(self, snmpValue):
        "Hardware version of the hub"
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.5.8.0")
    def serialNo(self, snmpValue):
        "Serial number of the hub"
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.5.11.0")
    def softwareVersion(self, snmpValue):
        """Software version of the hub."""
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.13.0")
    def wanMACAddr(self, snmpValue):
        "WAN Mac address - i.e. the mac address facing Virgin Media"
        return _extract_mac(snmpValue)

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.4")
    def wanMTUSize(self, snmpValue):
        if snmpValue:
            return int(snmpValue)
        else:
            return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.17")
    def wanIPProvMode(self, snmpValue):
        if snmpValue == 1:
            return "Router"
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.11.2.1.2")
    def wanCurrentDNSIPAddrType(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.11.2.1.2")
    def wanCurrentDNSIPAddrType(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.11.2.1.3")
    def wanCurrentDNSIPAddr(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.12.3")
    def wanDHCPDuration(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.12.4")
    def wanDHCPExpire(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.12.7")
    def wanDHCPDurationV6(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.12.8")
    def wanDHCPExpireV6(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.3")
    def lanSubnetMask(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.5")
    def lanGatewayIp(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.7")
    def lanGatewayIp2(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.9")
    def lanUseDHCP(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.11")
    def lanStartDHCP(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.13")
    def lanEndDHCP(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.14")
    def lanLeaseTime(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.29")
    def lanPrefixLengthV6(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.31")
    def lanStartDHCPV6(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.33")
    def lanLeaseTimeV6(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.39")
    def lanParentalControlsEnable(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.3.3.1.1.1.3.1")
    def devMaxCpeAllowed(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.3.3.1.1.1.3.2")
    def devNetworkAccess(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.5.6.0")
    def language(self, snmpValue):
        return snmpValue

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.5.62.0")
    def firstInstallWizardCompleted(self, snmpValue):
        return snmpValue == "1"

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.12.4.0")
    def wanIPv4LeaseExpiryDate(self, snmpValue):
        if snmpValue == '$0000000000000000': return None
        else: return _extract_date(snmpValue)

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.12.3.0")
    def wanIPv4LeaseTimeSecsRemaining(self, snmpValue):
        "No of seconds remaining of the DHCP lease of the WAN IP address"
        return int(snmpValue)

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.3.2")
    def wanIPv6Addr(self, snmpValue):
        "Current external IPv6 address of hub"
        return  _extract_ipv6(snmpValue)

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.6.2")
    def wanIPv6Gateway(self, snmpValue):
        "Default IPv6 gateway"
        return  _extract_ipv6(snmpValue)

    @_snmpProperty("1.3.6.1.4.1.4115.1.3.4.1.3.8.0")
    def cmDoc30SetupPacketCableRegion(self, snmpValue):
        "TODO: Figure out what this is..."
        return int(snmpValue)

    @_snmpProperty("1.3.6.1.4.1.4491.2.1.14.1.5.4.0")
    def esafeErouterInitModeCtrl(self, snmpValue):
        "TODO: Figure out what this is..."
        return int(snmpValue)

    @_snmpProperty("1.3.6.1.4.1.4115.1.20.1.1.5.16.1.2.1")
    def authUserName(self, snmpValue):
        """The name of the admin user"""
        return snmpValue

    @_collect_stats
    def deviceList(self):
        """Iterator which retrieves devices known to the hub.

        This will return successive DeviceInfo instances, which can be
        queried for each device.
        """
        mac_prefix = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.4.200.1.4"
        for iod, mac in self.snmpWalk(mac_prefix).items():
            ip = iod[ len(mac_prefix)+1 : ]
            yield DeviceInfo(self, ip, _extract_mac(mac))

        raise StopIteration()

    def getDevice(self, ipv4_address):
        """Get information for the given device

        If the hub knows about a network device on the local lan (or
        wifi) with the given IP address, a DeviceInfo will be
        returned.

        If the device is not known to the hub, None will be returned.
        """
        mac = self.snmpGet("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.4.200.1.4.%s" % ipv4_address)
        if not mac:
            return None
        return DeviceInfo(self, ipv4_address, _extract_mac(mac))

snmpHelpers = [
    ("docsisBaseCapability",                "1.3.6.1.2.1.10.127.1.1.5"),
    ("docsBpi2CmPrivacyEnable",             "1.3.6.1.2.1.126.1.1.1.1.1"),
    ("wanIPProvMode",                       "1.3.6.1.4.1.4115.1.20.1.1.1.17.0"),
    ("DSLiteWanEnable",                     "1.3.6.1.4.1.4115.1.20.1.1.1.18.1.0"),
    ("authAccountEnabled",                  "1.3.6.1.4.1.4115.1.20.1.1.5.16.1.6.2"),
    ("esafeErouterInitModeCtrl",            "1.3.6.1.4.1.4491.2.1.14.1.5.4.0"),
]

for name,oid in snmpHelpers:
    def newGetter(name, oid):
        def getter(self):
            res = self.snmpGets(oids=[oid])
            return res[oid]

        return property(MethodType(getter, None, Hub), None, None, name)
    setattr(Hub, name, newGetter(name, oid))

# Some properties cannot be snmpGet()'ed - they have to be snmpWalk()'ed instead??
_snmpWalks = [
    ("webAccessTable", "1.3.6.1.4.1.4115.1.20.1.1.6.7")
]

for name, oid in _snmpWalks:
    def newGetter(name, oid):
        def getter(self):
            return self.snmpWalk(oid)
        return property(MethodType(getter, None, Hub), None, None, name)
    setattr(Hub, name, newGetter(name, oid))

class DeviceInfo(object):
    """Information about a device known to a hub

    This makes the information known about a device available as attributes.

    Generally, querying the Virgin Media hub is agonizingly slow, so
    attributes are not retrieved from the hub until necessary.
    """
    def __init__(self, hub, ipv4_address, mac_address):
        self._ipv4_address = ipv4_address
        self._mac_address = mac_address
        self._hub = hub

    @property
    def ipv4_address(self):
        """The IPv4 address of the device"""
        return self._ipv4_address

    @property
    @cache_result
    def connected(self):
        """Whether the device is currently connected to the hub.

        For some reason, the hub "remembers" recently connected
        devices - which is useful.
        """
        return self._hub.snmpGet("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.14.200.1.4.%s" % self._ipv4_address) == "1"

    @property
    @cache_result
    def name(self):
        """The name the device reports to the hub.

        This name most likely comes from the DHCP request issued by
        the device, or possibly the mDNS name broadcasted by
        it.  Nobody knows for sure, but the hub knows somehow!
        """
        n = self._hub.snmpGet("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.3.200.1.4.%s" % self._ipv4_address)
        if n == "unknown":
            n = None
        return n

    @property
    def mac_address(self):
        return self._mac_address

    def __str__(self):
        return "DeviceInfo(ipv4_address=%s, mac_address=%s, connected=%s, name=%s)" % (self.ipv4_address, self.mac_address, self.connected, self.name)

def _demo(hub):
    global snmpHelpers

    print 'Demo Properties:'
    for name in sorted(_demo_properties):
        try:
            v = getattr(hub, name)
            print '-', name, ":", v.__class__.__name__, ":", v
        except Exception as e:
            print "Problem with property", name
            raise

    print 'Old-style properties:'
    for name,oid in snmpHelpers + _snmpWalks:
        print '- %s:' % name,
        print '"%s"' % getattr(hub, name)

    print "Device List"
    for dev in filter(lambda x: x.connected, hub.deviceList()):
        print "-", dev

    print "Session counters:"
    for c in sorted(hub.counters):
        print '-', c, hub.counters[c]


def _describe_oids(hub):
    with open('oid-list') as fp:
        for oid in fp:
            oid = oid.rstrip('\n')
            try:
                r = hub.snmpGet(oid)
                print oid, '=', hub.snmpGet(oid)
            except Exception as e:
                print oid, ':', e

if __name__ == '__main__':
    with Hub() as hub:
        hub.login(password='dssD04vy0z4t')
        print "Got", hub
        #_describe_oids(hub)
        _demo(hub)

        # if len(sys.argv) > 1:
        #     print "value of", sys.argv[1]
        #     print hub.snmpGet(sys.argv[1])


# Local Variables:
# compile-command: "./virginmedia.py"
# End:
