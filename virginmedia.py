#!/usr/bin/python3
"""Python API for the Virgin Media Hub 3

The Virgin Media Hub 3 is a re-badged Arris router - this module may
work for other varieties too.

"""

import base64
import enum
import random
import time
import json
import datetime
import os
import functools
import itertools
import collections
import textwrap
import types
import warnings
import operator
import requests

class LoginFailed(IOError):
    """Exception that indicates that logging in failed.

    This usually indicates that traffic could not reach the router or
    the router is dead... Unfortunately, it is very easy to overload
    these routers...

    """
    def __init__(self, msg, resp):
        msg = "{m}\nHTTP Status code: {s}\nResponse Headers: {h}".format(
            m=msg,
            s=resp.status_code,
            h=resp.headers)
        IOError.__init__(self, msg)

class AccessDenied(IOError):
    """The router denied the login.

    Time to check username + password.

    """
    def __init__(self, msg):
        IOError.__init__(self, msg)

def extract_int(strvalue, zero_is_none=True):
    """Extract an integer from a string.

    This is almost like the int() function - except that this one
    knows how to handle input values of None or the empty string.

    For convenience, it can also convert zero-valued results into None
    """
    if strvalue is None or strvalue == "":
        return None
    ival = int(strvalue)
    if zero_is_none and ival == 0:
        return None
    return ival

def extract_ip(hexvalue, zero_is_none=True):
    """Extract an IP address to a sensible format.

    The router encodes IPv4 addresses in hex, prefixed by a dollar
    sign, e.g. "$c2a80464" => 192.168.4.100
    """
    ipaddr = (str(int(hexvalue[1:3], base=16))
              + '.' + str(int(hexvalue[3:5], base=16))
              + '.' + str(int(hexvalue[5:7], base=16))
              + '.' + str(int(hexvalue[7:9], base=16)))
    if ipaddr == "0.0.0.0" and zero_is_none:
        return None
    return ipaddr

def ipv4_to_dollar(address):
    """Translates an IP address to the router's representation.

    The router encodes IPv4 addresses in hex, prefixed by a dollar
    sign, e.g. "$c2a80464" => 192.168.4.100
    """
    def tohex(decimal):
        return "{0:0>2s}".format(hex(int(decimal))[2:].lower())
    return "$" + ''.join(map(tohex, address.split('.')))

def extract_ipv6(hexvalue, zero_is_none=True):
    """Extract an IPv6 address to a sensible format

    The router encodes IPv6 address in hex, prefixed by a dollar sign
    """
    if hexvalue == "$00000000000000000000000000000000" and zero_is_none:
        return None
    res = hexvalue[1:5]
    for chunk in range(5, 30, 4):
        res += ':' + hexvalue[chunk:chunk+4]
    return res

def extract_ip_generic(hexvalue, addrtype, zero_is_none=True):
    """Transform a hex value into an ip address.

    The address type controls the conversion made

    """
    if addrtype == IPVersion.IPV4:
        return extract_ip(hexvalue, zero_is_none)
    if addrtype == IPVersion.IPV6:
        return extract_ipv6(hexvalue, zero_is_none)

    return "Unknown:{hexvalue=%s, addrtype=%s}" % (hexvalue, addrtype)

def extract_mac(mac):
    """Extract a mac address from the hub response.

    The hub represents mac addresses as e.g. "$787b8a6413f5" - i.e. a
    dollar sign followed by 12 hex digits, which we need to transform
    to the traditional mac address representation.

    """
    res = mac[1:3]
    for idx in range(3, 13, 2):
        res += ':' + mac[idx:idx+2]
    return res

def extract_date(vmdate):
    """
    Dates (such as the DHCP lease expiry time) are encoded somewhat stranger
    than even IP addresses:

    E.g. "$07e2030e10071100" is:
         0x07e2 : year = 2018
             0x03 : month = March
               0x0e : day-of-month = 14
                 0x10 : hour = 16 (seems to at least use 24hr clock!)
                   0x07 : minute = 07
                     0x11 : second = 17
                       0x00 : junk
    """
    if vmdate is None or vmdate in ["", "$0000000000000000"]:
        return None
    year = int(vmdate[1:5], base=16)
    month = int(vmdate[5:7], base=16)
    dom = int(vmdate[7:9], base=16)
    hour = int(vmdate[9:11], base=16)
    minute = int(vmdate[11:13], base=16)
    second = int(vmdate[13:15], base=16)
    return datetime.datetime(year, month, dom, hour, minute, second)

class Enum(enum.Enum):
    """A convenience wrapper around the Enum class.

    This provides two extra methods for driving enum values from
    either keys or values.

    """
    @classmethod
    def from_name(cls, name):
        """Find the enum with the given name"""
        try:
            return [e for e in cls if e.name == name][0]
        except IndexError:
            raise IndexError("Name '%s' does not exist for class %s" % (str(name), cls.__name__))

    @classmethod
    def from_value(cls, value):
        """Find the enum with the given value"""
        try:
            return [e for e in cls if e.value == value][0]
        except IndexError:
            raise IndexError("Value '%s' does not exist for class %s" % (str(value), cls.__name__))

@enum.unique
class Boolean(Enum):
    """The hub's representation of True and False"""
    # Fixme: This is complete and utter guesswork
    TRUE = "1"
    FALSE = "0"

@enum.unique
class IPProtocol(Enum):
    """IP IPProtocols"""
    UDP = "0"
    TCP = "1"
    BOTH = "2"

@enum.unique
class IPVersion(Enum):
    "IP Address Version"
    IPV4 = "1"
    IPV6 = "2"

@enum.unique
class SNMPType(Enum):
    """SNMP Data Types.

    ...I think...
    """
    INT = 2
    PORT = 66
    STRING = 4

KNOWN_PROPERTIES = set()

def collect_stats(func):
    """A function decorator to count how many calls are done to the func.

    it also collects timing information
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        self = args[0]
        self._increment_counter(func.__name__ + ':calls')
        start = time.time()
        result = func(*args, **kwargs)
        self._increment_counter(func.__name__ + ':secs',
                                increment=time.time()-start)
        return result
    return wrapper

def listed_property(func):
    """A function decorator which adds the function to the list of known attributes"""
    KNOWN_PROPERTIES.add(func.__name__)
    return func

def snmp_property(oid):
    """A function decorator to present an MIB value as an attribute.

    This works similar to the built-in property() class, but with a
    twist:

    - The constructor requires an OID

    - the getter method will receive a keyword argument: snmp_value
      which contains the value retrieved from SNMP.

    - the setter method is expected to return a value: The return
      value will be passed to snmp_set

    """
    class Decorator():
        """The actual decorator.

        But since this is defined inside the 'snmp_property' function,
        it has access to the OID
        """
        def __init__(self, fget=None, fset=None):
            self._fget = fget
            self._fset = fset
            self._listed = False
            self._name = None
            self._update()

        def getter(self, fget):
            """Decorator for a getter.

            The getter method will receive a keyword argument:
            snmp_value which contains the value retrieved from SNMP.
            """
            self._fget = fget
            self._update()
            return self

        def setter(self, fset):
            """Decorator for a setter.

            Unlike property()'s getter, this is expected to return a
            value - this will then be se in SNMP.

            """
            self._fset = fset
            self._update()
            return self

        def _update(self):
            for func in filter(operator.truth, [self._fget, self._fset]):
                self.__doc__ = func.__doc__
                self.__name__ = func.__name__
                if not self._listed:
                    listed_property(func)
                    self._listed = True
                return

        def __get__(self, hub, *args, **kwargs):
            if not self._fget:
                raise AttributeError("Attribute {attr} on {hub} is not settable"
                                     .format(attr=self._name, hub=hub))
            kwargs["snmp_value"] = hub.snmp_get(oid)
            return self._fget(*args, **kwargs)


        def __set__(self, hub, *args, **kwargs):
            if not self._fset:
                raise AttributeError("Attribute {attr} on {hub} is not readable"
                                     .format(attr=self._name, hub=hub))

            newval = self._fset(hub, *args, **kwargs)
            if isinstance(newval, tuple):
                hub.snmp_set(oid, newval[0], newval[1])
            else:
                hub.snmp_set(oid, newval)
            return newval

    return Decorator


def snmp_table(top_oid, columns):
    """A function decorator which does a walk of an snmp table

    The function gets passed an extra keyword argument: table_rows,
    which is an array of namespace objects, where the columns can be
    referenced by name.

    The unique row ID for each row gets assigned to the 'row_idx'
    value in the namespace object.

    The "columns" parameter to the decorator describes the columns: It
    is expected to be a dicts, where the key is the (partial) OID
    number of the column, and the value indicates the column name.

    columns = {"1": "columnname1"
               "2": "columnname2"}

    if the SNMP walk returns columns not listed in the dict, they will
    be ignored.

    """
    def real_wrapper(func):
        def col_num(walked_oid):
            return walked_oid[len(top_oid)+1:].split('.')[0]

        def row_num(walked_oid):
            return int(walked_oid[len(top_oid)+1:].split('.')[1])

        rowcls = collections.namedtuple('SNMPRow',
                                        field_names=list(columns.values()) + ['row_idx'],
                                        defaults=itertools.repeat(None, len(columns)+1))

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            self = args[0]
            results = [x for x in self.snmp_walk(top_oid).items()
                       if col_num(x[0]) in columns]
            results.sort(key=lambda x: (row_num(x[0]), col_num(x[0])))

            tabrows = []
            for (dummy, val) in itertools.groupby(results,
                                                  lambda x: row_num(x[0])):
                therow = rowcls(**{columns[col_num(ccc[0])]: ccc[1]
                                   for ccc in val})._replace(row_idx=dummy)
                tabrows.append(therow)

            kwargs['table_rows'] = tabrows
            return func(*args, **kwargs)
        return wrapper
    return real_wrapper

class SNMPSetError(AttributeError):
    """Gets raised when the hub refuses an SNMP Set"""
    def __init__(self, hub, oid, response):
        AttributeError.__init__(self,
                                "Hub {hub} refused to set OID {oid}: Response was {response}"
                                .format(hub=hub, oid=oid, response=response))
        warnings.warn(self)
        self.hub = hub
        self.oid = oid
        self.response = response

class Hub:
    """A Virgin Media Hub3.

    This class provides a pythonic interface to the Virgin Media Hub3.

    """
    def __init__(self, hostname='192.168.0.1', http_timeout=30, **kwargs):

        self._credential = None
        self._url = 'http://' + hostname
        self._hostname = hostname
        self._username = None
        self._password = None
        self.http_timeout = http_timeout
        self._nonce = {
            "_": int(round(time.time() * 1000)),
            "_n": "%05d" % random.randint(10000, 99999)
            }
        self._nonce_str = "_n=%s&_=%s" % (self._nonce["_n"], self._nonce["_"])
        self.counters = {}
        self._modelname = None
        self._family = None
        self._unapplied_settings = False
        if kwargs:
            self.login(**kwargs)

    def _increment_counter(self, name, increment=1):
        """Increase a counter increment (usually) 1.

        If the counter does not exist yet, it will be created"""
        self.counters[name] = self.counters.get(name, 0) + increment

    @collect_stats
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
                resp = requests.get(self._url + '/' + url,
                                    cookies={"credential": self._credential},
                                    timeout=self.http_timeout,
                                    **kwargs)
            else:
                resp = requests.get(self._url + '/' + url,
                                    timeout=self.http_timeout,
                                    **kwargs)
            self._increment_counter('received_http_' + str(resp.status_code))
            if resp.status_code == 401:
                retry401 -= 1
                if retry401 > 0 and self.is_loggedin:
                    warnings.warn("Got http status %s - Retrying after logging in again" \
                                  %(resp.status_code))
                    self.login(username=self._username, password=self._password)
                    self._increment_counter('_get_retries_401')
                    continue
            if resp.status_code == 500:
                retry500 -= 1
                if retry500 > 0:
                    warnings.warn("Got http status %s - retrying after %s seconds" \
                                  % (resp.status_code, sleep))
                    time.sleep(sleep)
                    sleep *= 2
                    self._increment_counter('_get_retries_500')
                    self._increment_counter('_get_retries_500_sleep_secs',
                                            increment=sleep)
                    continue
            break
        resp.raise_for_status()
        if resp.status_code == 401:
            raise AccessDenied(url)
        return resp

    @collect_stats
    def _params(self, keyvalues):
        res = {}
        res.update(self._nonce)
        res.update(keyvalues)
        return res

    @collect_stats
    def login(self, username=None, password="admin"):
        """Log into the router.

        This will capture the credentials to be used in subsequent requests.

        If no username is given, it will query the router for the
        default username first.
        """
        if not username:
            username = self.auth_username

        resp = self._get('login',
                         retry401=0,
                         params=self._params({
                             "arg": base64.b64encode((username + ':' + password).encode('ascii'))}))

        if not resp.content:
            raise LoginFailed(textwrap.dedent(
                """
                No credential cookie in the response.
                Arris is bad like that.
                Most likely bad username/password"""), resp)

        try:
            attrs = json.loads(base64.b64decode(resp.content))
        except Exception:
            raise LoginFailed("Cannot decode json response:\n" + resp.content, resp)

        if attrs.get("gwWan") == "f" and attrs.get("conType") == "LAN":
            if attrs.get("muti") == "GW_WAN":
                warnings.warn("Warning: Remote user has already logged in: " \
                              "Some things may fail with HTTP 401...")
            elif attrs.get("muti") == "LAN":
                warnings.warn("Warning: Other local user has already logged in: " \
                              "Some things may fail with HTTP 401...")
        elif attrs.get("gwWan") == "t":
            if attrs.get("muti") == "LAN":
                warnings.warn("Warning: Local user has already logged in: " \
                              "Some things may fail with HTTP 401...")
            elif attrs.get("muti") == "GW_WAN":
                warnings.warn("Warning: Other remote user has already logged in: " \
                              "Some things may fail with HTTP 401...")

        self._credential = resp.text
        self._username = username
        self._password = password
        self._modelname = attrs.get("modelname")
        self._family = attrs.get("family")

    @property
    @listed_property
    def modelname(self):
        """The model name of the hub"""
        return self._modelname

    @property
    @listed_property
    def family(self):
        """The hardware family of he hub"""
        return self._family

    @property
    def is_loggedin(self):
        """True if we have authenticated to the hub"""
        return self._credential is not None

    @collect_stats
    def logout(self):
        """Logs out from the hub"""
        if self.is_loggedin:
            try:
                self._get('logout', retry401=0, params=self._nonce)
            finally:
                self._credential = None
                self._username = None
                self._password = None

    @collect_stats
    def __enter__(self):
        """Context manager support: Called on the way in"""
        return self

    @collect_stats
    def __exit__(self, exc_type, exc_value, traceback):
        """Context manager support: Called on the way out"""
        try:
            self.logout()
        except requests.exceptions.HTTPError:
            # Avoid raising exceptions on the way out if our app had a problem
            if not exc_type:
                raise
        return False

    @collect_stats
    def snmp_get(self, oid):
        """Retrieves a single SNMP value from the hub"""
        resp = self.snmp_gets(oids=[oid])
        return resp[oid]

    @collect_stats
    def snmp_gets(self, oids):
        """Retrieves multiple OIDs from the hub.

        oids is expected to be an iterable of OIDs.

        This will return a dict, with the keys being the OIDs
        """
        resp = self._get("snmpGet?oids=" + ';'.join(oids) + ';&' + self._nonce_str)
        cont = resp.content
        try:
            resp = json.loads(cont)
        except ValueError:
            warnings.warn('Response content:', cont)
            raise
        return resp

    @collect_stats
    def snmp_set(self, oid, value=None, datatype=None):
        """Set the value of a given OID on the hub

        If the value cannot be set, an exception will be raised.

        The return value will be a boolean indicating whether the hub
        considered this a change or not.

        """
        oid_value = oid
        if value is not None:
            oid_value += '=' + str(value)
        oid_value += ';'
        if datatype is not None and str(datatype.value) != "":
            oid_value += str(datatype.value)

        resp = self._get("snmpSet?oid={oid};&{nonce}".format(oid=oid_value,
                                                             nonce=self._nonce_str))
        resp.raise_for_status()
        if not oid in resp.json().keys():
            raise SNMPSetError(self, oid, resp.text)

        if resp.status_code == 304:
            return False
        self._unapplied_settings = True
        return True

    def apply_settings(self):
        """Tells the hub to make the previous saved settings take effect."""
        if not self._unapplied_settings:
            return
        # self.snmp_set("1.3.6.1.4.1.4115.1.20.1.1.9.0")
        self.snmp_set("1.3.6.1.4.1.4115.1.20.1.1.9.0", 1, SNMPType.INT)
        self._unapplied_settings = False

    def __str__(self):
        return "Hub(hostname=%s, username=%s)" % (self._hostname, self._username)

    def __bool__(self):
        return self._credential is not None

    @collect_stats
    def __del__(self):
        self.logout()

    @collect_stats
    def snmp_walk(self, oid):
        """Perfor an SNMP Walk from the given OID.

        The resulting data will be returned as a dict, where the keys
        are OIDs and the values are their corresponding values.

        """
        jsondata = self._get('walk?oids=%s;%s' % (oid, self._nonce_str)).text

        # The hub has an ANNOYING bug: Sometimes the json result
        # include the single line
        #
        #    "Error in OID formatting!"
        #
        # which really messes up the JSON decoding (!). Since the OID
        # is obviously correct, and the hub happily returns other
        # data, our only recourse is to remove such lines before
        # attempting to interpret it as JSON... (sigh).
        #
        jsondata = "\n".join([x for x in jsondata.split("\n") if x != "Error in OID formatting!"])

        # print "snmp_walk of %s:" % oid
        # print jsondata
        result = json.loads(jsondata)
        # Strip off the final ANNOYING "1" entry!
        if result.get("1") == "Finish":
            del result["1"]
        return result

    @property
    @listed_property
    def lanIPAddress(self):
        return json.loads(self._get('getPreLoginData').content)["gwaddr"]

    @property
    @listed_property
    def configFile(self):
        "Nobody knows what this is for..."
        return json.loads(self._get('getRouterStatus').content)["1.3.6.1.2.1.69.1.4.5.0"]


    #
    # Functions that just deal with SNMP values
    #
    # People: Try to keep these in the SNMP mib order...
    #
    @snmp_property("1.3.6.1.4.1.4115.1.3.3.1.1.1.3.1.0")
    def max_cpe_allowed(self, snmp_value):
        """The value of MaxCpeAllowed in the CM config file.

        ... whatever THAT means...

        """
    @snmp_property("1.3.6.1.4.1.4115.1.3.3.1.1.1.3.2.0")
    def network_access(self, snmp_value):
        """Whether the hub has got network access."""
        return snmp_value == "1"

    @snmp_property("1.3.6.1.4.1.4115.1.3.4.1.1.14.0")
    def docsis_base_tod_status(self, snmp_value):
        """The TOD status"""
        statusmap = {
            "0": "Not Provisioned",
            "1": "Missing Server Address",
            "2": "Missing Server Address",
            "3": "Missing Server Address",
            "4": "Starting Request",
            "5": "Request Failed",
            "6": "No Response Received",
            "7": "Invalid Data Format",
            "8": "Retrieved",
            "9": "Failed"
            }
        try:
            return statusmap[snmp_value]
        except KeyError:
            return "Unknown SNMP value %s" % snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.3.4.1.3.8.0")
    def cmDoc30SetupPacketCableRegion(self, snmp_value):
        "TODO: Figure out what this is..."
        return int(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.1.0")
    def wan_conn_type(self, snmp_value):
        "The type of WAN connection"
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.2.0")
    def wan_conn_hostname(self, snmp_value):
        "The host name the hub presents to the ISP"
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.3.0")
    def wan_conn_domainname(self, snmp_value):
        "The domain name given to the hub by the ISP"
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.4.0")
    def wan_mtu_size(self, snmp_value):
        """The MTU on the WAN"""
        return extract_int(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.3.1")
    def wan_current_ipaddr_ipv4(self, snmp_value):
        """The current external IP address of the hub"""
        return extract_ip(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.3.2")
    def wan_current_ipaddr_ipv6(self, snmp_value):
        "Current external IPv6 address of hub"
        return  extract_ipv6(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.8.1")
    def wan_current_netmask(self, snmp_value):
        """The WAN network mask - e.g. '255.255.248.0'"""
        return extract_ip(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.6.1")
    def wan_current_gw_ipv4(self, snmp_value):
        """Default gateway of the hub"""
        return extract_ip(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.6.2")
    def wan_current_gw_ipv6(self, snmp_value):
        "Default IPv6 gateway"
        return  extract_ipv6(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.10.1.0")
    def wan_user_name(self, snmp_value):
        """WAN L2TP user name"""
        return snmp_value if snmp_value else None

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.10.2.0")
    def wan_password(self, snmp_value):
        """WAN L2TP password"""
        return snmp_value if snmp_value else None

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.10.3.0")
    def wan_enable_idle_timeout(self, snmp_value):
        """enable/disable WAN L2TP idle timeout"""
        return snmp_value == "1"

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.10.4.0")
    def wan_idle_timeout(self, snmp_value):
        """WAN L2TP idle timeout in seconds.

        Presumably, this only has effect when wan_enable_idle_timeout
        is True

        """
        return extract_int(snmp_value)

    @property
    @listed_property
    def wan_tunnel_addr(self):
        addrtype = self.snmp_get("1.3.6.1.4.1.4115.1.20.1.1.1.10.5.0")
        if addrtype == "0":
            return None
        return extract_ip(self.snmp_get("1.3.6.1.4.1.4115.1.20.1.1.1.10.6.0"))

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.10.8.0")
    def wan_keepalive_enabled(self, snmp_value):
        return snmp_value == "1"

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.10.9.0")
    def wan_keepalive_timeout(self, snmp_value):
        return extract_int(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.11.1.0")
    def wan_use_auto_dns(self, snmp_value):
        return snmp_value == "1"

    @property
    @listed_property
    @snmp_table("1.3.6.1.4.1.4115.1.20.1.1.1.11.2.1",
                {"2": "addrtype",
                 "3": "address"})
    def dns_servers(self, table_rows):
        """DNS servers used by the hub.

        This will probably also be the DNS servers the hub hands out
        in DHCP responses.

        The return value will be a list of strings - each string
        representing an IP address.

        """
        return [extract_ip_generic(x.address, IPVersion.from_value(x.addrtype))
                for x in table_rows]

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.13.0")
    def wan_if_macaddr(self, snmp_value):
        """MAC address on the WAN interface.

        This is the mac address your ISP will see

        """
        return extract_mac(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.12.3.0")
    def wan_dhcp_duration_ipv4(self, snmp_value):
        """The number of seconds the current WAN DHCP ipv4 lease will remain valid.

        Since this gives 'seconds remaining', this will be counting down...

        """
        return extract_int(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.12.4.0")
    def wan_dhcp_expire_ipv4(self, snmp_value):
        """The date/time the current WAN DHCP lease will expire.

        """
        return extract_date(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.12.7.0")
    def wan_dhcp_duration_ipv6(self, snmp_value):
        """The number of seconds the current WAN DHCP ipv6 lease will remain valid.

        Since this gives 'seconds remaining', this will be counting down...

        """
        return extract_int(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.12.8.0")
    def wan_dhcp_expire_ipv6(self, snmp_value):
        """The date/time the current WAN DHCP lease will expire.

        """
        return extract_date(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.12.9.0")
    def wan_dhcp_server_ip(self, snmp_value):
        """IP address of DHCP server that gave the hub a lease"""
        return extract_ip(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.17")
    def wan_ip_prov_mode(self, snmp_value):
        """eRouter initialization mode"""
        if snmp_value == 1:
            return "Router"
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.3.200")
    def lan_subnetmask(self, snmp_value):
        return extract_ip(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.5.200")
    def lan_gateway_ipv4(self, snmp_value):
        return extract_ip(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.7.200")
    def lan_gateway2_ipv4(self, snmp_value):
        return extract_ip(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.9.200")
    def lan_dhcp_enabled(self, snmp_value):
        return int(snmp_value) == 1

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.11.200")
    def lan_dhcpv4_range_start(self, snmp_value):
        return extract_ip(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.13.200")
    def lan_dhcpv4_range_end(self, snmp_value):
        return extract_ip(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.14.200")
    def lan_dhcpv4_leasetime(self, snmp_value):
        """The lease time (in seconds)"""
        return extract_int(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.29.200")
    def lan_dhcpv6_prefixlength(self, snmp_value):
        return extract_int(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.31.200")
    def lan_dhcpv6_range_start(self, snmp_value):
        if snmp_value == "$00000000000000000000000000000000":
            return None
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.33.200")
    def lan_dhcpv6_leasetime(self, snmp_value):
        return extract_int(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.39.200")
    def lan_parentalcontrols_enabled(self, snmp_value):
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10001")
    def wifi_24ghz_essid(self, snmp_value):
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10101")
    def wifi_5ghz_essid(self, snmp_value):
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10001")
    def wifi_24ghz_password(self, snmp_value):
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10101")
    def wifi_5ghz_password(self, snmp_value):
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.5.6.0")
    def language(self, snmp_value):
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.5.7.0")
    def name(self, snmp_value):
        "The name the hub calls itself"
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.5.8.0")
    def serial_number(self, snmp_value):
        "Serial number of the hub"
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.5.9.0")
    def bootcode_version(self, snmp_value):
        "Presumably the IPL firmware version?"
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.5.10.0")
    def hardware_version(self, snmp_value):
        "Hardware version of the hub"
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.5.11.0")
    def firmware_version(self, snmp_value):
        """Software version of the hub."""
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.5.14.0")
    def customer_id(self, snmp_value):
        "The value 8 appears to indicate Virgin Media"
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.5.15.0")
    def current_time(self, snmp_value):
        """The current time on the hub.

        Usually, this will be set to GMT
        """
        return extract_date(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.5.16.1.2.1")
    def auth_username(self, snmp_value):
        """The name of the admin user"""
        return snmp_value

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.5.62.0")
    def first_install_wizard_completed(self, snmp_value):
        return snmp_value == "1"

    @snmp_property("1.3.6.1.4.1.4491.2.1.14.1.5.4.0")
    def esafeErouterInitModeCtrl(self, snmp_value):
        "TODO: Figure out what this is..."
        return int(snmp_value)

    @collect_stats
    def device_list(self):
        """Iterator which retrieves devices known to the hub.

        This will return successive DeviceInfo instances, which can be
        queried for each device.

        Beware that since the Virgin Media hub is underpowered,
        retrieving this list will take some time...

        """
        mac_prefix = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.4.200.1.4"
        for oid, mac in list(self.snmp_walk(mac_prefix).items()):
            yield DeviceInfo(self, oid[len(mac_prefix)+1:], extract_mac(mac))

    def get_device(self, ipv4_address):
        """Get information for the given device

        If the hub knows about a network device on the local lan (or
        wifi) with the given IP address, a DeviceInfo will be
        returned.

        If the device is not known to the hub, None will be returned.
        """
        mac = self.snmp_get("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.4.200.1.4.%s" % ipv4_address)
        if not mac:
            return None
        return DeviceInfo(self, ipv4_address, extract_mac(mac))


    @snmp_table("1.3.6.1.4.1.4115.1.20.1.1.4.12.1",
                {"1": "index",
                 "2": "desc",
                 "3": "ext_port_start",
                 "4": "ext_port_end",
                 "5": "proto",
                 "6": "local_addr_type",
                 "7": "local_addr",
                 "9": "local_port_start",
                 "10": "local_port_end",
                 "11": "rowstatus"})
    def portforward_list(self, table_rows=None):
        """Get a list of port forwardings from the hub.

        This is not a lightweight operations due to the speed of the
        hub...

        """
        return [PortForwardEntry.from_snmp(x) for x in table_rows]


    def portforward_add(self, pfentry):
        oldlist = self.portforward_list()

        new_idx = max(map(int, [x.row_idx for x in oldlist]))
        if new_idx is None:
            new_idx = 1
        else:
            new_idx += 1

        def doset(column, val, datatype):
            self.snmp_set("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.{1}.{0}" \
                          .format(new_idx, column),
                          val,
                          datatype)

        # The order might look odd, but this is the same order as the
        # web interface does it...
        doset(11, 5, SNMPType.INT) # 5 seems to be a special value here indicating "creation" ?
        doset(3, pfentry.ext_port_start, SNMPType.PORT)
        doset(4, pfentry.ext_port_end, SNMPType.PORT)
        doset(5, pfentry.proto.value, SNMPType.INT)
        doset(6, pfentry.local_addr_type.value, SNMPType.INT)
        doset(7, ipv4_to_dollar(pfentry.local_addr).upper().replace('$', '%24'), SNMPType.STRING)
        doset(9, pfentry.local_port_start, SNMPType.PORT)
        doset(10, pfentry.local_port_end, SNMPType.PORT)
        doset(11, 1, SNMPType.INT)
        self.apply_settings()

    def portforward_del(self, proto, ext_port_start, ext_port_end):
        """Remove a given port forwarding entry from the hub.

        If the port forwarding entry is not found, it is silently ignored.
        """
        try:
            for oldentry in self.portforward_list():
                if oldentry.ext_port_start == ext_port_start \
                   and oldentry.ext_port_end == ext_port_end  \
                   and oldentry.proto == proto:
                    self.snmp_set("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.11.{0}" \
                                  .format(oldentry.row_idx),
                                  6, # 6 seems to be a special value indicating removal?
                                  SNMPType.INT)
        finally:
            self.apply_settings()

class PortForwardEntry(types.SimpleNamespace):
    """Object to represent a port forwarding rule.

    """
    @classmethod
    def portsummary(cls, start, end):
        """Summarise a port range.

            If the start and end are the same, then we only want to show
            the single port number

        """
        if start == end:
            return str(start)
        return "{0}-{1}".format(start, end)

    @classmethod
    def from_snmp(cls, snmprow):
        """Create a PortForwardEntry from an SNMP table row.

        For convenience, this creates two extra attributes: ext_ports
        and local_ports which contain string representations of the
        port range for human consumption:

        - If only one port is being forwarded, it will simply contain
          that.

        - If a port range is being forwarded, it will contain the
          start and end port numbers separated by a hyphen.

        """
        props = snmprow._asdict()

        # Cast port numbers
        for k, v in props.items():
            if "port" in k:
                props[k] = extract_int(v)

        props["enabled"] = Boolean.from_value(props["rowstatus"])
        del props["rowstatus"]

        props["local_addr_type"] = IPVersion.from_value(props["local_addr_type"])
        props["local_addr"] = extract_ip_generic(props["local_addr"],
                                                 props["local_addr_type"],
                                                 zero_is_none=False)

        props["proto"] = IPProtocol.from_value(props["proto"])

        props["ext_ports"] = cls.portsummary(props["ext_port_start"], props["ext_port_end"])
        props["local_ports"] = cls.portsummary(props["local_port_start"], props["local_port_end"])
        return cls(**props)

class DeviceInfo:
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
    def connected(self):
        """Whether the device is currently connected to the hub.

        For some reason, the hub "remembers" recently connected
        devices - which is useful.
        """
        return self._hub.snmp_get("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.14.200.1.4.%s"
                                  % self._ipv4_address) == "1"

    @property
    def name(self):
        """The name the device reports to the hub.

        This name most likely comes from the DHCP request issued by
        the device, or possibly the mDNS name broadcasted by
        it.  Nobody knows for sure, but the hub knows somehow!
        """
        thename = self._hub.snmp_get("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.3.200.1.4.%s" \
                                    % self._ipv4_address)
        if thename == "unknown":
            return None
        return thename

    @property
    def mac_address(self):
        return self._mac_address

    def __str__(self):
        return "DeviceInfo(ipv4_address=%s, mac_address=%s, connected=%s, name=%s)" \
            % (self.ipv4_address, self.mac_address, self.connected, self.name)

def _demo():
    with Hub() as hub:
        password = os.environ.get('HUB_PASSWORD')
        if password:
            hub.login(password=password)

        print('Demo Properties:')
        for name in sorted(KNOWN_PROPERTIES):
            try:
                val = getattr(hub, name)
                print('-', name, ":", val.__class__.__name__, ":", val)
            except Exception:
                print("Problem with property", name)
                raise

        print("Port Forwardings")
        for portforward in hub.portforward_list():
            print("-", portforward)

        print("Device List")
        for dev in [x for x in hub.device_list() if x.connected]:
            print("-", dev)

        print("Session counters:")
        for counter in sorted(hub.counters):
            print('-', counter, hub.counters[counter])

if __name__ == '__main__':
    _demo()

# Local Variables:
# compile-command: "./virginmedia.py"
# End:
