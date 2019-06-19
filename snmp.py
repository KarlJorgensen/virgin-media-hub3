#!/usr/bin/python3
"""Basic SNMP support for the Virgin Media Hub

This module implements the underlying convenience classes for setting
and retrieving SNMP OIDs in a pythonic way.

"""
import datetime
import enum
import textwrap

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
class IPVersion(Enum):
    "IP Address Version"
    IPV4 = "1"
    IPV6 = "2"

@enum.unique
class Type(Enum):
    """SNMP Data Types.

    ...I think...
    """
    INT = 2
    PORT = 66
    STRING = 4

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

class RawAttribute:
    """An abstraction of an SNMP attribute.

    This behaves like a normal attribute: Reads of it will retrieve
    the value from the hub, and writes to it will send the value back
    to the hub.

    For convenience, the value will be cached so repeated reads can be
    done without needing multiple round-trips to the hub.

    This allows you to read/write the 'raw' values. For most use cases
    you probably want to use the Attribute class, as this can do
    translation.
    """
    def __init__(self, oid, datatype, value=None):
        self._oid = oid
        self._datatype = datatype
        self._value = value
        self._value_gotten = (value is not None)
        self.__doc__ = "SNMP Attribute {0}, assumed to be {1}".format(oid, datatype.name)

    @property
    def oid(self):
        """The SNMP Object Identifier"""
        return self._oid

    @property
    def datatype(self):
        """The Data Type - one of the Type enums"""
        return self._datatype

    def refresh(self, instance):
        """Re-read the value from the hub"""
        self._value = instance.snmp_get(self._oid)
        self._value_gotten = True

    def __get__(self, instance, owner):
        if not self._value_gotten:
            self.refresh(instance)
        return self._value

    def __set__(self, instance, value):
        instance.snmp_set(self._oid, value, self._datatype)
        readback = instance.snmp_get(self._oid)
        if readback != value:
            raise ValueError("{hub} did not accept a value of '{value}' for {oid}: "
                             "It read back as '{rb}'!?"
                             .format(hub=instance,
                                     value=value,
                                     oid=self._oid,
                                     rb=readback))
        self._value = readback

    def __delete__(self, instance):
        raise NotImplementedError("Deleting SNMP values do not make sense")

class NullTranslator:
    """A translator which does nothing"""
    type = Type.STRING
    @staticmethod
    def snmp(human_value):
        "Returns the input value"
        return human_value
    @staticmethod
    def human(snmp_value):
        "Returns the input value"
        return snmp_value

class BoolTranslator:
    "Translates python boolean values to/from the router's representation"
    type = Type.INT
    @staticmethod
    def snmp(human_value):
        if isinstance(human_value, str) and human_value.lower() == "false":
            return "2"
        return "1" if human_value else "2"
    @staticmethod
    def human(snmp_value):
        return snmp_value == "1"

class IntTranslator:
    """Translates integers values to/from the router's representation.

    Generally, the router represents them as decimal strings, but it
    is nice to have them typecast correctly.

    """
    type = Type.INT
    @staticmethod
    def snmp(human_value):
        return str(int(human_value))
    @staticmethod
    def human(snmp_value):
        if snmp_value == "":
            return 0
        return int(snmp_value)

class MacAddressTranslator:
    """
    The hub represents mac addresses as e.g. "$787b8a6413f5" - i.e. a
    dollar sign followed by 12 hex digits, which we need to transform
    to the traditional mac address representation.
    """
    type = Type.STRING
    @staticmethod
    def human(snmp_value):
        res = snmp_value[1:3]
        for idx in range(3, 13, 2):
            res += ':' + snmp_value[idx:idx+2]
        return res
    @staticmethod
    def snmp(human_value):
        raise NotImplementedError()

class IPv4Translator:
    """Handles translation of IPv4 addresses to/from the hub.

    The hub encodes IPv4 addresses in hex, prefixed by a dollar sign,
    e.g. "$c2a80464" => 192.168.4.100
    """

    type = Type.STRING

    @staticmethod
    def snmp(human_value):
        "Translates an ipv4 address to something the hub understands"
        if human_value is None:
            return "$00000000"
        def tohex(decimal):
            return "{0:0>2s}".format(hex(int(decimal))[2:].lower())
        return "$" + ''.join(map(tohex, human_value.split('.')))

    @staticmethod
    def human(snmp_value):
        "Translates a hub-representation of an ipv4 address to human-readable form"
        if snmp_value in ["", "$00000000"]:
            return None
        ipaddr = (str(int(snmp_value[1:3], base=16))
                  + '.' + str(int(snmp_value[3:5], base=16))
                  + '.' + str(int(snmp_value[5:7], base=16))
                  + '.' + str(int(snmp_value[7:9], base=16)))
        return ipaddr

class IPv6Translator:
    """
        The router encodes IPv6 address in hex, prefixed by a dollar sign
    """

    type = Type.STRING

    @staticmethod
    def snmp(human_value):
        raise NotImplementedError()

    @staticmethod
    def human(snmp_value):
        if snmp_value == "$00000000000000000000000000000000":
            return None
        res = snmp_value[1:5]
        for chunk in range(5, 30, 4):
            res += ':' + snmp_value[chunk:chunk+4]
        return res

class DateTimeTranslator:
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
    type = Type.STRING
    @staticmethod
    def human(snmp_value):
        if snmp_value is None or snmp_value in ["", "$0000000000000000"]:
            return None
        year = int(snmp_value[1:5], base=16)
        month = int(snmp_value[5:7], base=16)
        dom = int(snmp_value[7:9], base=16)
        hour = int(snmp_value[9:11], base=16)
        minute = int(snmp_value[11:13], base=16)
        second = int(snmp_value[13:15], base=16)
        return datetime.datetime(year, month, dom, hour, minute, second)

    @staticmethod
    def snmp(human_value):
        raise NotImplementedError()

class Attribute(RawAttribute):
    """A generic SNMP Attribute which can use a translator.

    The translator will map the SNMP values to and from 'human' values
    """
    def __init__(self, oid, translator=NullTranslator, value=None, doc=None):
        RawAttribute.__init__(self, oid, datatype=translator.type, value=value)
        self._translator = translator
        if doc:
            self.__doc__ = textwrap.dedent(doc) + "\n\nCorresponds to SNMP attribute {0}, translated by {1}" \
                .format(oid, translator.__name__)
        else:
            self.__doc__ = "SNMP Attribute {0}, as translated by {1}" \
                .format(oid, translator.__name__)

    def __get__(self, instance, owner):
        return self._translator.human(RawAttribute.__get__(self, instance, owner))

    def __set__(self, instance, value):
        return RawAttribute.__set__(self, instance, self._translator.snmp(value))
