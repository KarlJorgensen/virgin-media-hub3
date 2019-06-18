#!/usr/bin/python3
"""Basic SNMP support for the Virgin Media Hub

This module implements the underlying convenience classes for setting
and retrieving SNMP OIDs in a pythonic way.

"""
import enum


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

class Attribute:
    """An abstraction of an SNMP attribute.

    This behaves like a normal attribute: Reads of it will retrieve
    the value from the hub, and writes to it will send the value back
    to the hub.

    For convenience, the value will be cached so repeated reads can be
    done without needing multiple round-trips to the hub.
    """
    def __init__(self, oid, datatype=Type.STRING, value=None):
        self._oid = oid
        self._datatype = datatype
        self._value = value
        self._value_gotten = (value is not None)

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
            raise ValueError("Hub {hub} did not accept a value of '{value}' for {oid}: "
                             "It read back as '{rb}'"
                             .format(hub=instance,
                                     value=value,
                                     oid=self._oid,
                                     rb=readback))
        self._value = readback

    def __delete__(self, instance):
        raise NotImplementedError("Deleting SNMP values do not make sense")
