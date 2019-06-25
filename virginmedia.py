#!/usr/bin/python3
"""Python API for the Virgin Media Hub 3

The Virgin Media Hub 3 is a re-badged Arris router - this module may
work for other varieties too.

"""

import base64
import collections
import functools
import itertools
import json
import operator
import os
import random
import socket
import textwrap
import time
import types
import warnings

import requests

import snmp

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
    if addrtype == snmp.IPVersion.IPv4:
        return extract_ip(hexvalue, zero_is_none)
    if addrtype == snmp.IPVersion.IPv6:
        return extract_ipv6(hexvalue, zero_is_none)

    return "Unknown:{hexvalue=%s, addrtype=%s}" % (hexvalue, addrtype)

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

def param_check(argid, checker):
    """A function decorator that enforces that a parameter should pass _checker_.

    The parameter can be indicated in two ways:

    - as an integer N: The N'th parameter must satisfy the check

    - as a string X: The keyword argument X must satisfy the check

    The decorator will raise ValueError if attempts are made at
    calling the function with invalid parameters.

    """
    def decorator(func):

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if isinstance(argid, int):
                param = args[argid]
            else:
                param = kwargs[argid]

            checker(param)
            return func(*args, **kwargs)
        return wrapper

    if not isinstance(argid, (int, str)):
        raise TypeError("param_check takes an int or str, not %s" % argid.__class__)

    return decorator

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
            self._name = None
            self._datatype = None
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
            if isinstance(fset, types.MethodType):
                self._fset = fset
                self._update()
                return self

            self._datatype = fset
            return self

        def __call__(self, func):
            # Gets invoked when we have a setter() decorator with a parameter
            self._fset = func
            self._update()
            return self

        def _update(self):
            for func in filter(operator.truth, [self._fget, self._fset]):
                self.__doc__ = func.__doc__
                self.__name__ = func.__name__
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
                hub.snmp_set(oid, *newval)
            else:
                hub.snmp_set(oid, newval, self._datatype)
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

WanNetwork = collections.namedtuple("WanNetwork", ['ipaddr', 'prefix', 'netmask', 'gw'])

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

    language = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.5.6.0",
                              doc="""\
                              Hub interface language.

                              On the Virgin Media hub, setting this
                              appears to have no effect.  """)

    name = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.5.7.0")
    serial_number = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.5.8.0")
    bootcode_version = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.5.9.0")
    hardware_version = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.5.10.0")
    firmware_version = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.5.11.0")
    customer_id = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.5.14.0")
    wifi_24ghz_essid = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10001")
    wifi_24ghz_password = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10001")
    wifi_5ghz_essid = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10101")
    wifi_5ghz_password = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10101")

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
            raise LoginFailed("Cannot decode json response:\n" + resp.text, resp)

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
    def modelname(self):
        """The model name of the hub"""
        return self._modelname

    @property
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

    def backup(self):
        """Performs a backup of the hub

        The actual backup is returned
        """
        resp = self._get('/backup?' + self._nonce_str)
        resp.raise_for_status()
        return bytearray(resp.content)

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
            if datatype == snmp.DataType.STRING:
                oid_value += '=' + str(value).replace('$', '%24')
            else:
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
        self.snmp_set("1.3.6.1.4.1.4115.1.20.1.1.9.0", 1, snmp.DataType.INT)
        self._unapplied_settings = False

    def reboot(self):
        """Instructs the hub to reboot"""
        self.apply_settings()
        self.snmp_set("1.3.6.1.4.1.4115.1.20.1.1.5.4.0", 1, snmp.DataType.INT)

    def __str__(self):
        return "Hub(hostname=%s, username=%s)" % (self._hostname, self._username)

    def __bool__(self):
        """A hub is 'True' if we have credentials to log in.

        Note: This does not necessarily mean we _can_ log in: The
        credentials might be bad...

        """
        return self._credential is not None

    @collect_stats
    def __del__(self):
        """Logs out of the hub"""
        self.logout()

    @collect_stats
    def snmp_walk(self, oid):
        """Perform an SNMP Walk from the given OID.

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

        result = json.loads(jsondata)
        # Strip off the final ANNOYING "1" entry!
        if result.get("1") == "Finish":
            del result["1"]
        return result

    max_cpe_allowed = snmp.Attribute("1.3.6.1.4.1.4115.1.3.3.1.1.1.3.1.0",
                                     snmp.IntTranslator)
    "This reflects the 'MaxCpeAllowed' parameter in the CM config file"

    network_access = snmp.Attribute("1.3.6.1.4.1.4115.1.3.3.1.1.1.3.2.0",
                                    snmp.BoolTranslator)
    """Whether the hub has got network access."""

    @snmp_property("1.3.6.1.4.1.4115.1.3.4.1.1.14.0")
    # pylint: disable=R0201
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
    # pylint: disable=R0201
    def cmDoc30SetupPacketCableRegion(self, snmp_value):
        "TODO: Figure out what this is..."
        return int(snmp_value)

    @snmp_property("1.3.6.1.4.1.4115.1.20.1.1.1.1.0")
    # pylint: disable=R0201
    def wan_conn_type(self, snmp_value):
        "The type of WAN connection"
        return snmp_value

    wan_conn_hostname = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.2.0")
    "The host name the hub presents to the ISP"

    wan_conn_domainname = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.3.0")
    "The domain name given to the hub by the ISP"

    wan_mtu_size = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.4.0",
                                  snmp.IntTranslator)
    "The MTU on the WAN"

    @property
    @snmp_table("1.3.6.1.4.1.4115.1.20.1.1.1.7.1",
                {"2": "addrtype",
                 "3": "ipaddr",
                 "4": "prefix",
                 "5": "gwtype",
                 "6": "gw",
                 "7": "iptype",
                 "8": "netmask",
                 "9": "prefix_delegation_v6",
                 "10": "prefix_delegation_v6_len",
                 "11": "preferred_lifetime_v6",
                 "12": "valid_lifetime_v6"})
    def wan_networks(self, table_rows):
        """List of WAN networks.

        It seems to be possible for the router to have multiple external IP addresses...
        """
        res = [WanNetwork(extract_ip_generic(row.ipaddr, snmp.IPVersion(row.addrtype)),
                          int(row.prefix) if row.prefix is not None else None,
                          extract_ip(row.netmask) if row.netmask is not None else None,
                          extract_ip_generic(row.gw, snmp.IPVersion(row.addrtype)))
               for row in table_rows
               if row.prefix is not None]
        return res

    wan_current_ipaddr_ipv4 = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.3.1",
                                             snmp.IPv4Translator)
    "The current external IP address of the hub"

    wan_current_ipaddr_ipv6 = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.3.2",
                                             snmp.IPv6Translator)
    "Current external IPv6 address of hub"

    wan_current_netmask = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.8.1",
                                         snmp.IPv4Translator)
    "The WAN network mask - e.g. '255.255.248.0'"

    wan_current_gw_ipv4 = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.6.1",
                                         snmp.IPv4Translator)
    "Default gateway of the hub"

    wan_current_gw_ipv6 = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.6.2",
                                         snmp.IPv6Translator)
    "Default IPv6 gateway"

    wan_l2tp_username = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.10.1.0")
    "WAN L2TP user name"

    wan_l2tp_password = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.10.2.0")
    "WAN L2TP password"

    wan_l2tp_enable_idle_timeout = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.10.3.0",
                                                  snmp.BoolTranslator)
    "enable/disable WAN L2TP idle timeout"

    wan_l2tp_idle_timeout = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.10.4.0",
                                           snmp.IntTranslator)
    "WAN L2TP idle timeout in seconds"

    wan_l2tp_tunnel_addr = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.10.6.0",
                                          snmp.IPAddressTranslator)

    wan_l2tp_tunnel_hostname = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.10.7.0")
    "Host name of the tunnel server. Either hostname or IP address is required."

    wan_l2tp_keepalive_enabled = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.10.8.0",
                                                snmp.BoolTranslator)
    "Whether keepalive is enabled on the WAN"

    wan_l2tp_keepalive_timeout = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.10.9.0",
                                                snmp.IntTranslator)

    wan_use_auto_dns = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.11.1.0",
                                      snmp.BoolTranslator)
    "Use automatic DNS servers as specified by ISP and DHCP"

    @property
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
        return [extract_ip_generic(x.address, snmp.IPVersion(x.addrtype))
                for x in table_rows]

    @property
    def wan_current_table(self):
        """Table contains information for a specific Wan IP address.

        In some environments, there may be both an IPv6 and IPv6
        address or multiple IPv6 addresses.

        The size of this table is usually limited to 4 entries

        """
        mapping = \
            {
                "1": {"name": "IPIndex"},
                "2": {"name": "IPAddrType",
                      "translator": snmp.IPVersionTranslator,
                      "doc": "Static IP address type"},
                "3": {"name": "IPAddr",
                      "translator": snmp.IPAddressTranslator,
                      "doc": "Static IP addressfor Wan connection"},
                "4": {"name": "Prefix",
                      "translator": snmp.IntTranslator,
                      "doc": "Netmask (Prefix)"},
                "8": {"name": "NetMask",
                      "translator": snmp.IPv4Translator,
                      "doc": "Netmask if it is IPv4"},
                "5": {"name": "GWType",
                      "translator": snmp.IPVersionTranslator,
                      "doc": "Gateway Address type"},
                "6": {"name": "GW",
                      "translator": snmp.IPAddressTranslator,
                      "doc": "Gateway address"},
                # "7": {"name": "IPType",
                #       "translator": snmp.IPVersionTranslator,
                #       "doc": "Type of IP address. This appears to be unreliable..."},
                "9": {"name": "PrefixDelegationV6",
                      "translator": snmp.IPv6Translator,
                      "doc": "The prefix, or initial bits of the address, given "
                             "to the router to delegate to its attached CPEs"},
                "10": {"name": "PrefixDelegationV6Len",
                       "translator": snmp.IntTranslator,
                       "doc": "The length for the prefix to be delegated to attached CPEs"},
                "11": {"name": "PreferredLifetimeV6",
                       "translator": snmp.IntTranslator,
                       "doc": "The preferred lifetime for the assigned IPv6 address of the router"},
                "12": {"name": "ValidLifetimeV6",
                       "translator": snmp.IntTranslator,
                       "doc": "The valid lifetime for the assigned IPv6 address of the router"},
            }
        return snmp.Table(self,
                          "1.3.6.1.4.1.4115.1.20.1.1.1.7.1",
                          mapping)

    wan_if_macaddr = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.13.0",
                                    snmp.MacAddressTranslator)
    """MAC address on the WAN interface.

    This is the mac address your ISP will see, and it is most likely
    tied to our account with the ISP.
    """

    wan_dhcp_duration_ipv4 = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.12.3.0",
                                            snmp.IntTranslator)
    "The number of seconds the current WAN DHCP ipv4 lease will remain valid"

    wan_dhcp_expire_ipv4 = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.12.4.0",
                                          snmp.DateTimeTranslator)
    "The date/time the current WAN DHCP lease will expire."

    wan_dhcp_duration_ipv6 = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.12.7.0",
                                            snmp.IntTranslator)
    "The number of seconds the current WAN DHCP ipv6 lease will remain valid"

    wan_dhcp_expire_ipv6 = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.12.8.0",
                                          snmp.DateTimeTranslator)
    "The date/time the current WAN DHCP lease will expire."

    wan_dhcp_server_ip = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.12.9.0",
                                        snmp.IPv4Translator)
    "IP address of DHCP server that gave the hub a lease"

    wan_ip_prov_mode = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.1.17.0")
    "eRouter initialization mode"

    @property
    def lan_networks(self):
        """Information about the local LAN networks

        The router can normally handle more than one network, A single
        network can span multiple interfaces.

        """
        mapping = \
            {
                "1": {"name": "name"},
                "27": {"name": "interfaces",
                       "doc": """\
                            Name of the member physical network interface (or virtual network interface in the
                            case of a wireless SSID) comprising the logical interface, aka LAN subnet. This mib
                            object takes in an unsigned integer with the following bitmap setup: Single-Band
                            support: 0x00000001 // ethernet 0x00000002 // usb (unsupported) 0x00000004 // moca
                            0x00000008 // ssid1 0x00000010 // ssid2 0x00000020 // ssid3 0x00000040 // ssid4
                            0x00000080 // ssid5 0x00000100 // ssid6 0x00000200 // ssid7 0x00000400 // ssid8
                            Dual-Band Support: 0x00000001 // ethernet 0x00000002 // usb (unsupported)
                            0x00000004 // moca 0x00000008 // ssid1 & ssid9 0x00000010 // ssid2 & ssid10
                            0x00000020 // ssid3 & ssid11 0x00000040 // ssid4 & ssid12 0x00000080 // ssid5 &
                            ssid13 0x00000100 // ssid6 & ssid14 0x00000200 // ssid7 & ssid15 0x00000400 //
                            ssid8 & ssid16 Example of mapping the ethernet, usb, moca, and ssid1 to the primary
                            LAN subnet: 0x0000000F = (Integer) 15 NOTE - A physical/virtual interface may not
                            be assigned to more than one logical interface"""},
                "8": {"name": "vlan",
                      "translator": snmp.IntTranslator,
                      "doc": "VLAN ID - use zero for untagged"},
                "21": {"name": "passthrough",
                       "doc": """\
                            Whether or not this Lan is in pass-thru mode or bridged/NAT. To put the device into
                            non-bridged mode with routing and NAT disabled -- pass-thru, use: passThru(1). To
                            put the device into bridged (routed) mode with Network Address Translation (NAT)
                            enabled use: routedNAT(2). To put the device into bridged (routed) mode with
                            Network Address Translation (NAT) disabled use: routedNoNAT(3)"""},
                "4": {"name": "gateway_ip_type",
                      "translator": snmp.IPVersionTranslator},
                "5": {"name": "gateway_ip",
                      "translator": snmp.IPAddressTranslator,
                      "doc": "Gateway IP address"},
                "6": {"name": "gateway_ip2_type",
                      "translator": snmp.IPVersionTranslator},
                "7": {"name": "gateway_ip2",
                      "translator": snmp.IPAddressTranslator,
                      "doc": "Second gateway IP address"},
                "2": {"name": "subnet_mask_type",
                      "translator": snmp.IPVersionTranslator},
                "3": {"name": "subnet_mask",
                      "translator": snmp.IPv4Translator},
                "9": {"name": "use_dhcp",
                      "translator": snmp.BoolTranslator,
                      "doc": "enable or disable the DHCP server on this LAN"},
                "10": {"name": "dhcp_start_ip_type",
                       "translator": snmp.IPVersionTranslator},
                "11": {"name": "dhcp_start_ip",
                       "translator": snmp.IPAddressTranslator,
                       "doc": "Start of DHCP IP range"},
                "12": {"name": "dhcp_end_ip_type",
                       "translator": snmp.IPVersionTranslator},
                "13": {"name": "dhcp_end_ip",
                       "translator": snmp.IPAddressTranslator,
                       "doc": "End of DHCP IP range"},
                "14": {"name": "dhcp_lease_time",
                       "translator": snmp.IntTranslator,
                       "doc": "DHCP Lease time in seconds"},
                "15": {"name": "domain_name"},
                "19": {"name": "dns_relay_enabled",
                       "translator": snmp.BoolTranslator},
                "25": {"name": "dns_override_enabled",
                       "translator": snmp.BoolTranslator,
                       "doc": """\
                            If DNS override is enabled, the IP addresses in arrisRouterLanDNSTable will be
                            passed to LAN clients via DHCP.  Otherwise, the DNS servers received by the WAN
                            connection will be passed to the LAN clients."""},
                "22": {"name": "firewall_enabled",
                       "translator": snmp.BoolTranslator},
                "23": {"name": "upnp_enabled",
                       "translator": snmp.BoolTranslator},
                "24": {"name": "aging_time",
                       "translator": snmp.IntTranslator,
                       "doc": "The timeout period in seconds for aging out dynamically " \
                       "learned forwarding information. " \
                       "The default value of zero means do not age "},
                "39": {"name": "parental_controls_enabled",
                       "translator": snmp.BoolTranslator},
                "26": {"name": "nat_algs_enabled",
                       "doc": """\
                            Specifies which NAT application layer gateway supplements are enabled on this
                            device.  The default value for this object is for all ALG's to be enabled. Reserved
                            bits are for ALGs that are currently not supported."""},
                "28": {"name": "environment_control",
                       "translator": snmp.BoolTranslator,
                       "doc": """\
                              Controls whether or not the settings which define the operating environment of
                              the logical interface, aka LAN subnet, are changeable via the GUI. When equal to
                              unlocked, the environment settings MAY be changed via the UI. When equal to
                              locked, the environment settings MAY NOT be changed via the UI"""},
            }
        return snmp.Table(self,
                          "1.3.6.1.4.1.4115.1.20.1.1.2.2.1",
                          mapping)

    lan_subnetmask = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.3.200",
                                    snmp.IPv4Translator)

    lan_gateway = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.5.200",
                                 snmp.IPAddressTranslator)

    lan_gateway2 = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.7.200",
                                  snmp.IPAddressTranslator)

    lan_dhcp_enabled = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.9.200",
                                      snmp.BoolTranslator)

    lan_dhcpv4_range_start = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.11.200",
                                            snmp.IPv4Translator)
    "The first IP address of the DHCP allocation range on the LAN"

    lan_dhcpv4_range_end = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.13.200",
                                          snmp.IPv4Translator)
    "The last IP address of the DHCP allocation range on the LAN"

    lan_dhcpv4_leasetime = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.14.200",
                                          snmp.IntTranslator)
    "The lease time (in seconds)"


    lan_dhcpv6_prefixlength = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.29.200",
                                             snmp.IntTranslator)

    lan_dhcpv6_range_start = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.31.200",
                                            snmp.IPv6Translator)

    lan_dhcpv6_leasetime = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.33.200",
                                          snmp.IntTranslator)

    lan_parentalcontrols_enabled = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.39.200",
                                                  snmp.BoolTranslator)
    "Whether parental controls are enabled"

    current_time = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.5.15.0",
                                  snmp.DateTimeTranslator)
    "The current time on the hub."

    auth_username = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.5.16.1.2.1")
    "The name of the admin user"


    first_install_wizard_completed = snmp.Attribute("1.3.6.1.4.1.4115.1.20.1.1.5.62.0",
                                                    snmp.BoolTranslator)

    esafeErouterInitModeCtrl = snmp.Attribute("1.3.6.1.4.1.4491.2.1.14.1.5.4.0")
    "TODO: Figure out what this is..."

    def device_list(self):
        """Iterator which retrieves devices known to the hub.

        This will return successive DeviceInfo instances, which can be
        queried for each device.

        Beware that since the Virgin Media hub is underpowered,
        retrieving this list will take some time...

        """
        mac_prefix = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.4.200.1.4"
        for oid, mac in list(self.snmp_walk(mac_prefix).items()):
            yield DeviceInfo(self, oid[len(mac_prefix)+1:], snmp.MacAddressTranslator.pyvalue(mac))

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
        return DeviceInfo(self, ipv4_address, snmp.MacAddressTranslator.pyvalue(mac))


    @property
    def portforwards(self):
        """The port forwarding table from the hub

        Traffic arriving from the WAN will be forwarded to the internal
        servers as per the mapping.

        This is not a lightweight operations due to the speed of the
        hub...

        """
        return snmp.PortForwardTable(self)

    def portforward_add(self,
                        ext_port_start,
                        ext_port_end=None,
                        proto=snmp.IPProtocol.TCP,
                        local_addr_type=snmp.IPVersion.IPv4,
                        local_addr=None,
                        local_port_start=None,
                        local_port_end=None):
        """Add a new (static) port forwarding entry.

        """
        if not isinstance(proto, snmp.IPProtocol):
            raise TypeError("proto arg to portforward_add must be an IP Protocol"
                            " - not %s" % proto.__class__)
        if not isinstance(ext_port_start, int):
            raise TypeError("ext_port_start arg to portforward_add must be an int"
                            " - not %s" % ext_port_start.__class__)
        if local_addr is None:
            local_addr = socket.gethostbyname(socket.gethostname())
            if local_addr.startswith("127.0."):
                raise ValueError("No local_addr passed and unable to find local ip... sorry.")
        # TODO: Check types of other parameters?

        if ext_port_end is None:
            ext_port_end = ext_port_start
        if local_port_start is None:
            local_port_start = ext_port_start
        if local_port_end is None:
            local_port_end = ext_port_end

        pflist = self.portforwards

        for pfentry in pflist.values():
            if proto.overlaps(pfentry.proto) \
               and (pfentry.ext_port_start <= ext_port_start <= pfentry.ext_port_end
                    or pfentry.ext_port_start <= ext_port_end <= pfentry.ext_port_end) \
                and pfentry.rowstatus == snmp.RowStatus.ACTIVE:
                raise ValueError("New PF entry overlaps with existing ones")

        if pflist:
            row_key = str(max(map(int, pflist.keys()))+1)
        else:
            row_key = "1"

        newrow = pflist.new_row(
            row_key,
            rowstatus=snmp.RowStatus.CREATE_AND_WAIT,
            proto=proto,
            ext_port_start=ext_port_start,
            ext_port_end=ext_port_end,
            local_addr_type=local_addr_type,
            local_addr=local_addr,
            local_port_start=local_port_start,
            local_port_end=local_port_end
        )

        newrow.rowstatus = snmp.RowStatus.ACTIVE

    @property
    def etherports(self):
        return snmp.EtherPortTable(self)

    @property
    def bsstable(self):
        return snmp.BSSTable(self)

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

HUB_PROPERTIES = [name
                  for name, value in Hub.__dict__.items()
                  if not name.startswith("_") and not callable(value)]

def _demo():
    with Hub() as hub:
        password = os.environ.get('HUB_PASSWORD')
        if password:
            hub.login(password=password)

        print('Demo Properties:')
        for name in sorted(HUB_PROPERTIES):
            try:
                val = getattr(hub, name)
                print('-', name, ":", val.__class__.__name__, ":", val)
            except Exception:
                print("Problem with property", name)
                raise

        print("Port Forwardings")
        print(hub.portforwards.format())

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
