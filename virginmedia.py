#!/usr/bin/python3
"""Python API for the Virgin Media Hub 3

The Virgin Media Hub 3 is a re-badged Arris router - this module may
work for other varieties too.

"""

import base64
import collections
import datetime
import json
import os
import os.path
import random
import textwrap
import time
import warnings

import requests

import arris
import snmp
import utils

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

# pylint: disable=no-member
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
        self._modelname = None
        self._family = None
        self._unapplied_settings = False
        if kwargs:
            self.login(**kwargs)

    @property
    def uptime(self):
        """How long the hub has been running for"""
        return datetime.timedelta(seconds=self._uptime_centiseconds / 100)

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
            if resp.status_code == 401:
                retry401 -= 1
                if retry401 > 0 and self.is_loggedin:
                    warnings.warn("Got http status %s - Retrying after logging in again" \
                                  %(resp.status_code))
                    self.login(username=self._username, password=self._password)
                    continue
            if resp.status_code == 500:
                retry500 -= 1
                if retry500 > 0:
                    warnings.warn("Got http status %s - retrying after %s seconds" \
                                  % (resp.status_code, sleep))
                    time.sleep(sleep)
                    sleep *= 2
                    continue
            break
        resp.raise_for_status()
        if resp.status_code == 401:
            raise AccessDenied(url)
        return resp

    def _params(self, keyvalues):
        res = {}
        res.update(self._nonce)
        res.update(keyvalues)
        return res

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

    def __enter__(self):
        """Context manager support: Called on the way in"""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Context manager support: Called on the way out"""
        try:
            self.logout()
        except requests.exceptions.HTTPError:
            # Avoid raising exceptions on the way out if our app had a problem
            if not exc_type:
                raise
        return False

    def snmp_get(self, oid):
        """Retrieves a single SNMP value from the hub"""
        resp = self.snmp_gets(oids=[oid])
        return resp[oid]

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

    def __del__(self):
        """Logs out of the hub"""
        self.logout()

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

        try:
            result = json.loads(jsondata)
        except json.decoder.JSONDecodeError:
            warnings.warn('Response content:\n%s\n' % jsondata)
            raise
        # Strip off the final ANNOYING "1" entry!
        if result.get("1") == "Finish":
            del result["1"]
        return result


    @property
    def wan_networks(self):
        """List of WAN networks

        In some environments, there may be both an IPv6 and IPv6 address
        or multiple IPv6 addresses.

        The size of this table is usually limited to 4 entries

        """
        return arris.WanNetworksTable(self)

    @property
    def dns_servers(self):
        """List DNS servers know by the hub.

        These are the default DNS servers handed out to DHCP clients.
        """
        return arris.DNSServerTable(self)

    @property
    def clients(self):
        """Information internal clients.

        This includes both wired and wireless clients.

        Retrieving this list can take 10 seconds or more...

        """
        return arris.LanClientTable(self)

    @property
    def lan_networks(self):
        """Information about the local LAN networks

        The router can normally handle more than one network, A single
        network can span multiple interfaces.

        """
        return arris.LanTable(self)

    @property
    def wifi_clients(self):
        """List of WIFI clients"""
        return arris.WifiClientTable(self)

    @property
    def portforwards(self):
        """The port forwarding table from the hub

        Traffic arriving from the WAN will be forwarded to the internal
        servers as per the mapping.

        This is not a lightweight operations due to the speed of the
        hub...

        """
        return arris.PortForwardTable(self)

    @property
    def etherports(self):
        """List of ethernet ports on the hub"""
        return arris.EtherPortTable(self)

    @property
    def bsstable(self):
        """List of WIFI networks"""
        return arris.BSSTable(self)

    @property
    def mso_log(self):
        """MSO Log

         A log of configuration changes that are not done by the
        user. Assumed to be the MSO remotely or a technician.

        """
        return arris.MSOLogTable(self)

    @property
    def fw_log(self):
        """Firewall Log"""
        return arris.FirewallLogTable(self)

def oidsplit(oid):
    """Split an OID into a tuple with a sequence of integers.

    This is useful for sorting, as string sorts will not sort OIDs
    right.

    """
    return tuple([int(x) for x in oid.split('.')])

def _setup_properties(dirname):
    """Add class variables from the yaml file"""
    import yaml
    with open(os.path.join(dirname, "attributes.yml")) as attr_file:
        attrmap = yaml.load(attr_file)

    oids = list(attrmap.keys())
    for oid1, oid2 in zip(oids, oids[1:]):
        if oidsplit(oid2) < oidsplit(oid1):
            warnings.warn("OID ordering is wrong: %s should be after %s" % (oid2, oid1))

    names = []
    for oid, settings in attrmap.items():
        try:
            if settings['name'] in names:
                raise ValueError("Duplicate name for oid %s" % oid)
            names.append(settings['name'])

            kwargs = {"oid": oid}
            if 'translator' in settings:
                # pylint: disable=eval-used
                kwargs['translator'] = eval(settings['translator'])
            if 'doc' in settings:
                kwargs['doc'] = settings['doc']

            setattr(Hub, settings['name'], snmp.Attribute(**kwargs))
        except Exception:
            warnings.warn("Problem with OID %s" % oid)
            raise

_setup_properties(os.path.dirname(__file__))

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
                if isinstance(val, snmp.Table):
                    print('-', name, '(', val.__class__.__name__, ") :")
                    print(utils.format_table(val))
                else:
                    print('-', name, ":", val.__class__.__name__, ":", val)
            except Exception:
                print("Problem with property", name)
                raise

        print("Port Forwardings")
        print(hub.portforwards.format())

        print("Clients:")
        print(utils.format_table(hub.clients))

if __name__ == '__main__':
    _demo()

# Local Variables:
# compile-command: "./virginmedia.py"
# End:
