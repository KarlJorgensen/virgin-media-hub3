#!/usr/bin/python3
"""Basic SNMP support for the Virgin Media Hub

This module implements the underlying convenience classes for setting
and retrieving SNMP OIDs in a pythonic way.

"""
import datetime
import enum
import textwrap

import utils

@enum.unique
class IPVersion(enum.Enum):
    "IP Address Version"
    IPv4 = "1"
    IPv6 = "2"
    GodKnows = "4"

@enum.unique
class DataType(enum.Enum):
    """SNMP Data Types.

    ...I think...
    """
    INT = 2
    PORT = 66
    STRING = 4

@enum.unique
class Boolean(enum.Enum):
    """The hub's representation of True and False"""
    # Fixme: This is complete and utter guesswork
    TRUE = "1"
    FALSE = "0"

@enum.unique
class IPProtocol(enum.Enum):
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
        """The Data Type - one of the DataType enums"""
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

class Translator:
    snmp_datatype = DataType.STRING
    @staticmethod
    def snmp(python_value):
        "Returns the input value"
        return python_value
    @staticmethod
    def pyvalue(snmp_value):
        "Returns the input value"
        return snmp_value

class NullTranslator(Translator):
    """A translator which does nothing.

    Except that it maps the empty string to None and back...
    """
    @staticmethod
    def snmp(python_value):
        if python_value is None:
            return ""
        return str(python_value)
    @staticmethod
    def pyvalue(snmp_value):
        if snmp_value == "":
            return None
        return snmp_value

class EnumTranslator(Translator):
    """A translator which translates based on Enums"""
    def __init__(self, enumclass, snmp_datatype=DataType.STRING):
        self.enumclass = enumclass
        self.snmp_datatype = snmp_datatype

    def snmp(self, python_value):
        return self.enumclass[python_value]
    def pyvalue(self, snmp_value):
        return self.enumclass(snmp_value)
    @property
    def name(self):
        self.__str__()
    def __str__(self):
        return "{0}({1})".format(self.__class__.__name__, self.enumclass.__name__)
    __repr__ = __str__

class BoolTranslator(Translator):
    "Translates python boolean values to/from the router's representation"
    snmp_datatype = DataType.INT
    @staticmethod
    def snmp(python_value):
        if isinstance(python_value, str) and python_value.lower() == "false":
            return "2"
        return "1" if python_value else "2"
    @staticmethod
    def pyvalue(snmp_value):
        return snmp_value == "1"

# pylint: disable=invalid-name
IPVersionTranslator = EnumTranslator(IPVersion)

class IntTranslator(Translator):
    """Translates integers values to/from the router's representation.

    Generally, the router represents them as decimal strings, but it
    is nice to have them typecast correctly.

    """
    snmp_datatype = DataType.INT
    @staticmethod
    def snmp(python_value):
        if python_value == None:
            return ""
        return str(int(python_value))
    @staticmethod
    def pyvalue(snmp_value):
        if snmp_value == "":
            return None
        return int(snmp_value)

class MacAddressTranslator(Translator):
    """
    The hub represents mac addresses as e.g. "$787b8a6413f5" - i.e. a
    dollar sign followed by 12 hex digits, which we need to transform
    to the traditional mac address representation.
    """
    @staticmethod
    def pyvalue(snmp_value):
        res = snmp_value[1:3]
        for idx in range(3, 13, 2):
            res += ':' + snmp_value[idx:idx+2]
        return res
    @staticmethod
    def snmp(python_value):
        raise NotImplementedError()

class IPv4Translator(Translator):
    """Handles translation of IPv4 addresses to/from the hub.

    The hub encodes IPv4 addresses in hex, prefixed by a dollar sign,
    e.g. "$c2a80464" => 192.168.4.100
    """
    @staticmethod
    def snmp(python_value):
        "Translates an ipv4 address to something the hub understands"
        if python_value is None:
            return "$00000000"
        def tohex(decimal):
            return "{0:0>2s}".format(hex(int(decimal))[2:].lower())
        return "$" + ''.join(map(tohex, python_value.split('.')))

    @staticmethod
    def pyvalue(snmp_value):
        "Translates a hub-representation of an ipv4 address to a python-friendly form"
        if snmp_value in ["", "$00000000"]:
            return None
        ipaddr = (str(int(snmp_value[1:3], base=16))
                  + '.' + str(int(snmp_value[3:5], base=16))
                  + '.' + str(int(snmp_value[5:7], base=16))
                  + '.' + str(int(snmp_value[7:9], base=16)))
        return ipaddr

class IPv6Translator(Translator):
    """
        The router encodes IPv6 address in hex, prefixed by a dollar sign
    """

    @staticmethod
    def snmp(python_value):
        raise NotImplementedError()

    @staticmethod
    def pyvalue(snmp_value):
        if snmp_value == "$00000000000000000000000000000000":
            return None
        res = snmp_value[1:5]
        for chunk in range(5, 30, 4):
            res += ':' + snmp_value[chunk:chunk+4]
        return res

class DateTimeTranslator(Translator):
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
    @staticmethod
    def pyvalue(snmp_value):
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
    def snmp(python_value):
        raise NotImplementedError()

class Attribute(RawAttribute):
    """A generic SNMP Attribute which can use a translator.

    The translator will map the SNMP values to/from Python values
    """
    def __init__(self, oid, translator=NullTranslator, value=None, doc=None):
        RawAttribute.__init__(self, oid, datatype=translator.snmp_datatype, value=value)
        self._translator = translator
        try:
            translator_name = translator.__name__
        except AttributeError:
            translator_name = translator.name

        if doc:
            self.__doc__ = textwrap.dedent(doc) + \
                "\n\nCorresponds to SNMP attribute {0}, translated by {1}" \
                .format(oid, translator_name)
        else:
            self.__doc__ = "SNMP Attribute {0}, as translated by {1}" \
                .format(oid, translator_name)

    def __get__(self, instance, owner):
        return self._translator.pyvalue(RawAttribute.__get__(self, instance, owner))

    def __set__(self, instance, value):
        return RawAttribute.__set__(self, instance, self._translator.snmp(value))

class TransportProxy:
    """Forwards snmp_get/snmp_set calls to another class/instance."""
    def __init__(self, transport):
        """Create a TransportProxy which forwards to the given transport"""
        self._transport = transport
    def snmp_get(self, *args, **kwargs):
        return self._transport.snmp_get(*args, *kwargs)
    def snmp_set(self, *args, **kwargs):
        return self._transport.snmp_set(*args, *kwargs)
    def snmp_walk(self, *args, **kwargs):
        return self._transport.snmp_walk(*args, *kwargs)

class TransportProxyDict(TransportProxy, dict):
    def __init__(self, transport, cells=None):
        TransportProxy.__init__(self, transport)

class RowBase(TransportProxy):
    def __init__(self, proxy, keys):
        super().__init__(proxy)
        self._keys = keys

    def keys(self):
        return self._keys

    def values(self):
        return [getattr(self, name) for name in self._keys]

    def __len__(self):
        return len(self._keys)

    def __getitem__(self, key):
        return getattr(self, self._keys[key])

    def __iter__(self):
        return self.keys().iter()

    def __contains__(self, item):
        return item in self._keys

    def __str__(self):
        return self.__class__.__name__ + '(' \
            + ', '.join([key+'="'+str(getattr(self, key))+'"'
                         for key in self._keys]) \
            + ')'

    def __repr__(self):
        return self.__class__.__name__ + '(' \
            + ', '.join([key+'="'+repr(getattr(self, key))+'"'
                         for key in self._keys]) \
            + ')'

class Table(TransportProxyDict):
    def __init__(self, transport, table_oid, column_mapping, walk_result=None):
        super().__init__(transport)

        if not walk_result:
            walk_result = transport.snmp_walk(table_oid)

        def column_id(oid):
            return oid[len(table_oid)+1:].split('.')[0]

        def row_id(oid):
            return '.'.join(oid[len(table_oid)+1:].split('.')[1:])

        # First walk through the snmpwalk, and collect up every
        # cell. This is essentially a 2-dimensional sparse dict, with
        # each cell being a tuple(oid, value, column_mapping_entry)
        result_dict = dict()
        for oid, raw_value in walk_result.items():
            this_column_id = column_id(oid)
            if this_column_id not in column_mapping.keys():
                # Skip stuff not in the mappings
                continue
            this_row_id = row_id(oid)
            if this_row_id not in result_dict:
                result_dict[this_row_id] = dict()

            result_dict[this_row_id][column_mapping[this_column_id]['name']] = \
                (oid, raw_value, column_mapping[this_column_id])

        # Then go through the result, and create a row object for each
        # row. Essentially, each row is a different class, as it may
        # have different attributes
        for rowkey, row in result_dict.items():
            class_dict = {mapping["name"]: Attribute(oid=oid,
                                                     value=raw_value,
                                                     doc=mapping.get('doc'),
                                                     translator=mapping.get('translator',
                                                                            NullTranslator))
                          for oid, raw_value, mapping in row.values()}

            RowClass = type('Row', (RowBase,), class_dict)
            self[rowkey] = RowClass(self, class_dict)

    def format(self):
        return utils.format_table(self.aslist())

    def aslist(self):
        return self.values()
