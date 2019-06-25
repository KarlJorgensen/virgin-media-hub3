#!/usr/bin/python3
"""Basic SNMP support for the Virgin Media Hub

This module implements the underlying convenience classes for setting
and retrieving SNMP OIDs in a pythonic way.

See also: https://tools.ietf.org/html/rfc3781

"""
import datetime
import enum
import textwrap
import warnings

import netaddr
import utils

@enum.unique
class IPVersion(enum.Enum):
    "IP Address Version"
    IPv4 = "1"
    IPv6 = "2"
    GodKnows = "4"

    def __human__(self):
        return self.name

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

    def __human__(self):
        return self.name

    def overlaps(self, other):
        if not isinstance(other, IPProtocol):
            raise TypeError("overlaps() expects an IPProtocol instance")
        if self == other:
            return True
        return (self == IPProtocol.BOTH) or (other == IPProtocol.BOTH)

class AttributeStatus(enum.Enum):
    """Current status of attributes.

    This is used for indicating whether the cached value is valid,
    needs writing or has been read already

    """
    OK = 1
    UNSET = 2
    "We have yet to read it, and we have no value to write"
    NEEDS_WRITE = 2
    NEEDS_READ = 3

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
    def __init__(self,
                 oid,
                 datatype,
                 status=AttributeStatus.NEEDS_READ,
                 value=None,
                 instance=None,
                 readback_after_write=True):
        self._oid = oid
        self._datatype = datatype
        self._status = status
        self._value = value
        self._readback_after_write = readback_after_write
        self.__doc__ = "SNMP Attribute {0}, assumed to be datatype {1}".format(oid, datatype.name)
        if self._status == AttributeStatus.NEEDS_WRITE and instance is None:
            raise TypeError("When creating attributes with NEEDS_WRITE, "
                            "instance value is mandatory")

        if self._status == AttributeStatus.NEEDS_WRITE:
            self._write(instance, value)

    @property
    def oid(self):
        """The SNMP Object Identifier"""
        return self._oid

    @property
    def datatype(self):
        """The Data Type - one of the DataType enums"""
        return self._datatype

    def reread(self, instance):
        """Re-read the value from the hub"""
        self._value = instance.snmp_get(self._oid)
        self._status = AttributeStatus.OK

    def __get__(self, instance, owner):
        if self._status == AttributeStatus.NEEDS_READ:
            self.reread(instance)
        elif self._status == AttributeStatus.UNSET:
            raise AttributeError("OID '{0}' has not yet been set".format(self._oid))
        return self._value

    def _write(self, instance, value):
        instance.snmp_set(self._oid, value, self._datatype)
        if self._readback_after_write:
            readback = instance.snmp_get(self._oid)
            if str(readback) != str(value):
                raise ValueError("hub did not accept a value of '{value}' for {oid}: "
                                 "It read back as '{rb}'!?"
                                 .format(value=value,
                                         oid=self._oid,
                                         rb=readback))
        self._value = value
        self._status = AttributeStatus.OK

    __set__ = _write

    def __delete__(self, instance):
        raise NotImplementedError("Deleting SNMP values do not make sense")

    def __str__(self):
        return "{s.__class__.__name__}({s._oid}, {s._datatype}, {s._status}, {s._value}" \
            .format(s=self)

class Translator:
    """Base class for translators.

    It is a translators job to translate between SNMP values and
    Python values - both ways.

    """
    snmp_datatype = DataType.STRING
    @staticmethod
    def snmp(python_value):
        "Returns the python equivalent of the given SNMP value"
        return python_value
    @staticmethod
    def pyvalue(snmp_value):
        "Returns the SNMP equivalent of the given python value"
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
    def __init__(self, enumclass, snmp_datatype=DataType.STRING, doc=None):
        self.enumclass = enumclass
        self.snmp_datatype = snmp_datatype
        if doc:
            self.__doc__ = doc

    def snmp(self, python_value):
        if not isinstance(python_value, self.enumclass):
            python_value = self.enumclass[str(python_value)]

        return python_value.value

    def pyvalue(self, snmp_value):
        return self.enumclass(snmp_value)
    @property
    def name(self):
        """The string name of the python constant"""
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
        if snmp_value is None:
            raise ValueError("This could not have come from SNMP...")
        if snmp_value is None:
            raise ValueError("This could not have come from SNMP...")
        return snmp_value == "1"

# pylint: disable=invalid-name
IPVersionTranslator = EnumTranslator(IPVersion)

def _dummy_for_doctest():
    """Translates to/from IP versions

    >>> IPVersionTranslator.pyvalue("1")
    <IPVersion.IPv4: '1'>
    >>> IPVersionTranslator.pyvalue("2").name
    'IPv6'
    >>> IPVersionTranslator.snmp(IPVersion.IPv4)
    '1'
    """

IPProtocolTranslator = EnumTranslator(IPProtocol, snmp_datatype=DataType.INT)

class IntTranslator(Translator):
    """Translates integers values to/from the router's representation.

    Generally, the router represents them as decimal strings, but it
    is nice to have them typecast correctly.

    """
    snmp_datatype = DataType.INT
    @staticmethod
    def snmp(python_value):
        """Translates an python integer to an SNMP string

        This is mostly just a case of converting to the base 10 string
        representation of the python integer.

        >>> IntTranslator.snmp(None)
        ''
        >>> IntTranslator.snmp(1)
        '1'
        >>> IntTranslator.snmp(None)
        ''
        >>> IntTranslator.snmp(23)
        '23'

        """
        if python_value is None:
            return ""
        return str(int(python_value))

    @staticmethod
    def pyvalue(snmp_value):
        """Translates an SNMP string to a python integer.

        This is mostly just a case of using the int() function, with
        the exception of the empty string.

        >>> IntTranslator.pyvalue("")

        >>> IntTranslator.pyvalue("7")
        7

        """
        if snmp_value == "":
            return None
        if snmp_value is None:
            raise ValueError("This could not have come from SNMP...")
        return int(snmp_value)

class PortTranslator(IntTranslator):
    """Translates port numbers

    Port numbers are integers, but are represented as a different data
    type at the hub...

    """
    snmp_datatype = DataType.PORT

class MacAddressTranslator(Translator):
    """
    The hub represents mac addresses as e.g. "$787b8a6413f5" - i.e. a
    dollar sign followed by 12 hex digits, which we need to transform
    to the traditional mac address representation.

    >>> MacAddressTranslator.pyvalue('')

    >>> MacAddressTranslator.snmp(None)
    '$000000000000'
    >>> MacAddressTranslator.pyvalue('$787b8a6413f5')
    EUI('78-7B-8A-64-13-F5')
    >>> MacAddressTranslator.snmp(netaddr.EUI('78-7B-8A-64-13-F5'))
    '$787b8a6413f5'
    """
    @staticmethod
    def pyvalue(snmp_value):
        if snmp_value is None or snmp_value in ['', '$000000000000']:
            return None
        if not snmp_value.startswith('$') or len(snmp_value) != 13:
            raise ValueError("'%s' is not a sensible SNMP Mac Address"
                             % snmp_value)
        return netaddr.EUI(snmp_value[1:])
    @staticmethod
    def snmp(python_value):
        if python_value is None:
            return '$000000000000'
        return "${0:012x}".format(int(python_value))

class IPv4Translator(Translator):
    """Handles translation of IPv4 addresses to/from the hub.

    The hub encodes IPv4 addresses in hex, prefixed by a dollar sign.

    >>> IPv4Translator.snmp(None)
    '$00000000'
    >>> IPv4Translator.pyvalue('')

    >>> IPv4Translator.snmp('192.168.4.100')
    '$c0a80464'
    >>> IPv4Translator.pyvalue("$c0a80464")
    IPAddress('192.168.4.100')
    >>> IPv4Translator.pyvalue("$c0a80464").version
    4
    """
    @staticmethod
    def snmp(python_value):
        "Translates an ipv4 address to something the hub understands"
        if python_value is None:
            return "$00000000"
        if not isinstance(python_value, netaddr.IPAddress):
            python_value = netaddr.IPAddress(python_value, 4)
        if python_value.version != 4:
            raise ValueError("%s is not an IPv4 address" % python_value)

        return '$' + ''.join(["{0:02x}".format(w) for w in python_value.words])

    @staticmethod
    def pyvalue(snmp_value):
        "Translates a hub-representation of an ipv4 address to a python-friendly form"
        if snmp_value == "":
            return None
        if not snmp_value.startswith("$") or len(snmp_value) != 9:
            raise ValueError("Value '%s' is not an SNMP IPv4Address" % snmp_value)
        if {x for x in snmp_value[1:]} == set('0'):   # All zeros
            return None

        return netaddr.IPAddress(int(snmp_value[1:], 16))

class IPv6Translator(Translator):
    """The router encodes IPv6 address in hex, prefixed by a dollar sign.

    >>> IPv6Translator.snmp("::1")
    '$0000000000000001'
    >>> IPv6Translator.pyvalue('$0000000000000001')
    IPAddress('::1')
    >>> IPv6Translator.pyvalue('$00000000000000000000000000000001')
    IPAddress('::1')
    >>> IPv6Translator.pyvalue('$0000000000000001').version
    6
    >>> IPv6Translator.pyvalue('$00000000000000000000000000000001').version
    6
    >>> IPv6Translator.pyvalue('$000c0fd8400ff5580000').version
    6
    >>> IPv6Translator.pyvalue('$000c0fd8400ff5580000')
    IPAddress('::c:fd8:400f:f558:0')
    >>> IPv6Translator.snmp(netaddr.IPAddress('::c:fd8:400f:f558:0'))
    '$0000000cfd8400ff55800'
    """
    @staticmethod
    def snmp(python_value):
        "Translates an IPv6 address to something the hub understands"
        if python_value is None:
            return "$00000000000000000000000000000000"
        if not isinstance(python_value, netaddr.IPAddress):
            python_value = netaddr.IPAddress(python_value, 6)
        if python_value.version != 6:
            raise ValueError("%s is not an IPv6 address" % python_value)

        return '$' + ''.join(["{0:02x}".format(w) for w in python_value.words])

    @staticmethod
    def pyvalue(snmp_value):
        if snmp_value == "":
            return None
        if not snmp_value.startswith('$') or not 8 < len(snmp_value) <= 33:
            raise ValueError("Value '%s' is not an SNMP IPv6Address" % snmp_value)

        if {x for x in snmp_value[1:]} == set('0'):   # All zeros
            return None

        res = netaddr.IPAddress(int(snmp_value[1:], 16), 6)
        if res.version != 6:
            raise ValueError("Value '%s' is not an SNMP IPv6Address" % snmp_value)
        return res

class IPAddressTranslator(Translator):
    """Translates to/from IP address. It will understand both IPv4 and
    IPv6 addresses

    >>> IPAddressTranslator.snmp(None)
    '$00000000'
    >>> IPAddressTranslator.pyvalue('')

    >>> IPAddressTranslator.pyvalue('$00000000')

    >>> IPAddressTranslator.pyvalue('$00000000000000000000000000000000')

    >>> IPAddressTranslator.snmp('192.168.4.100')
    '$c0a80464'
    >>> IPAddressTranslator.pyvalue("$c0a80464")
    IPAddress('192.168.4.100')
    >>> IPAddressTranslator.pyvalue("$c0a80464").version
    4
    >>> IPAddressTranslator.snmp("::1")
    '$0000000000000001'
    >>> IPAddressTranslator.pyvalue('$00000000000000000000000000000001')
    IPAddress('::1')
    >>> IPAddressTranslator.pyvalue('$00000000000000000000000000000001').version
    6
    >>> IPAddressTranslator.pyvalue('$000c0fd8400ff5580000').version
    6
    >>> IPAddressTranslator.pyvalue('$000c0fd8400ff5580000')
    IPAddress('::c:fd8:400f:f558:0')
    >>> IPAddressTranslator.snmp(netaddr.IPAddress('::c:fd8:400f:f558:0'))
    '$0000000cfd8400ff55800'
    """
    @staticmethod
    def snmp(python_value):
        if python_value is None:
            return "$00000000"
        python_value = netaddr.IPAddress(python_value)
        if python_value.version == 4:
            return IPv4Translator.snmp(python_value)
        return IPv6Translator.snmp(python_value)

    @staticmethod
    def pyvalue(snmp_value):
        if snmp_value == "":
            return None
        if not snmp_value.startswith("$") or len(snmp_value) < 9:
            return ValueError("%s is not an SNMP representation of an IP address!?" % snmp_value)
        if len(snmp_value) == 9:
            return IPv4Translator.pyvalue(snmp_value)
        return IPv6Translator.pyvalue(snmp_value)

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

    >>> DateTimeTranslator.pyvalue('$07e2030e10071100')
    datetime.datetime(2018, 3, 14, 16, 7, 17)
    >>> DateTimeTranslator.pyvalue('$0000000000000000')

    >>> DateTimeTranslator.pyvalue('')

    >>> DateTimeTranslator.snmp(datetime.datetime(2018, 3, 14, 16, 7, 17))
    '$07e2030e10071100'

    >>> DateTimeTranslator.snmp(None)
    '$0000000000000000'

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
        if not python_value:
            return '$0000000000000000'

        if not isinstance(python_value, datetime.datetime):
            raise TypeError("DateTimeTranslator.snmp takes a datetime.datetime arg")

        return '$' + \
            "{p.year:04x}{p.month:02x}{p.day:02x}" \
            "{p.hour:02x}{p.minute:02x}{p.second:02x}00".format(p=python_value)

class RowStatus(enum.Enum):
    """SNMIv2 Row Status values

    As documented on
    https://www.webnms.com/snmp/help/snmpapi/snmpv3/table_handling/snmptables_basics.html

    """
    ACTIVE = "1"
    """The conceptual row with all columns is available for use by the
    managed device
    """

    NOT_IN_USE = "2"
    """the conceptual row exists in the agent, but is unavailable for
    use by the managed device"""

    NOT_READY = """3"""
    """the conceptual row exists in the agent, one or more required
    columns in the row are not instantiated"""

    CREATE_AND_GO = """4"""
    """supplied by a manager wishing to create a new instance of a
    conceptual row and make it available for use"""

    CREATE_AND_WAIT = """5"""
    """supplied by a manager wishing to create a new instance of a
    conceptual row but not making it available for use"""

    DESTROY = """6"""
    """supplied by a manager wishing to delete all of the instances
    associated with an existing conceptual row"""

RowStatusTranslator = EnumTranslator(RowStatus, snmp_datatype=DataType.INT)

class Attribute(RawAttribute):
    """A generic SNMP Attribute which can use a translator.

    This allows us to have pythonic variables representing OID values:
    Reads will retrieve the value from router, and writes will update
    the route - with the translator doing the necessary translation
    between Python values and router representation.

    """
    def __init__(self,
                 oid,
                 translator=NullTranslator,
                 instance=None,
                 value=None,
                 status=AttributeStatus.NEEDS_READ,
                 doc=None,
                 readback_after_write=True):
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

        if status == AttributeStatus.NEEDS_READ:
            RawAttribute.__init__(self,
                                  oid=oid,
                                  datatype=translator.snmp_datatype,
                                  instance=instance,
                                  status=status,
                                  readback_after_write=readback_after_write)
        else:
            RawAttribute.__init__(self,
                                  oid=oid,
                                  datatype=translator.snmp_datatype,
                                  instance=instance,
                                  status=status,
                                  value=translator.snmp(value),
                                  readback_after_write=readback_after_write)

    def __get__(self, instance, owner):
        return self._translator.pyvalue(RawAttribute.__get__(self, instance, owner))

    def __set__(self, instance, value):
        return RawAttribute.__set__(self, instance, self._translator.snmp(value))

    def __str__(self):
        return "{s.__class__.__name__}({s._oid}, {s._translator}, {s._status}, {s._value}" \
            .format(s=self)

class TransportProxy:
    """Forwards snmp_get/snmp_set calls to another class/instance."""
    def __init__(self, transport):
        """Create a TransportProxy which forwards to the given transport"""
        self._transport = transport
        self.snmp_get = transport.snmp_get
        self.snmp_set = transport.snmp_set
        self.snmp_walk = transport.snmp_walk

class TransportProxyDict(TransportProxy, dict):
    def __init__(self, transport):
        TransportProxy.__init__(self, transport)
        dict.__init__(self)

class RowBase(TransportProxy):
    """Base class for representing SNMP Tables"""
    def __init__(self, proxy, keys):
        super().__init__(proxy)
        self._keys = keys

    def keys(self):
        return self._keys

    def values(self):
        return [getattr(self, name) for name in self._keys]

    def __len__(self):
        return len(self._keys)

    def items(self):
        return [(name, getattr(self, name)) for name in self._keys]

    def __getitem__(self, key):
        return getattr(self, key)

    def get(self, key, default=None):
        if key in self._keys:
            return self[key]
        return default

    def __iter__(self):
        return self.keys().iter()

    def __contains__(self, item):
        return item in self._keys

    def __str__(self):
        return self.__class__.__name__ + '(' \
            + ', '.join(["{0}={1}".format(key, str(getattr(self, key)))
                         for key in self._keys]) \
            + ')'

    def __repr__(self):
        return self.__class__.__name__ + '(' \
            + ', '.join(["{0}={1}".format(key, repr(getattr(self, key)))
                         for key in self._keys]) \
            + ')'

def parse_table(table_oid, walk_result):
    """Restructure the result of an SNMP table into rows and columns

    """
    def column_id(oid):
        return oid[len(table_oid)+1:].split('.')[0]

    def row_id(oid):
        return '.'.join(oid[len(table_oid)+1:].split('.')[1:])

    result_dict = dict()
    for oid, raw_value in walk_result.items():
        this_column_id = column_id(oid)
        this_row_id = row_id(oid)
        if this_row_id not in result_dict:
            result_dict[this_row_id] = dict()
        result_dict[this_row_id][this_column_id] = raw_value
    return result_dict

class Table(TransportProxyDict):
    """A pythonic representation of an SNMP table

    The python representation of the table is a dict() - not an array,
    as each entry in the table has an ID: the ID becomes the key of
    the resulting dict.

    Each entry in the result is a (customised) RowBase class, where
    SNMP attributes are mapped to Attribute instances: Updates to the
    attributes will result in the hub being updated.

    Although the resulting table is updateable (updates to attributes
    in the row will result in SNMP Set calls), the table does not
    support deletion or insertion of elements: it is of fixed size.

    The column_mapping describes how to translate OID columns to
    Python values in the resulting rows:

    {
      "1": {"name": "port_number",
            "translator": snmp.IntTranslator,
            "doc": "Port number for Foobar"},
      "2": {"name": "address",
            "translator": snmp.IPv4Translator}
    }

    The keys in the dict correspond to the SNMP OID column numbers -
    i.e. the first part after the table_oid.

    The values of each key must be a dict, where the following keys
    are understood:

    - "name": (mandatory) The resulting python attribute name. This must be a
              valid python attribute name.

    - "translator": (optional) The class/instance of a translator to
                    map between python and SNMP representations. If
                    none is given, the default NullTranslator will be
                    used.

    - "doc": (optional) the doc string to associate with the attribute.
    """
    def __init__(self,
                 transport,
                 table_oid,
                 column_mapping,
                 row_class=RowBase,
                 walk_result=None):
        """Instantiate a new table based on an SNMP walk

        """
        super().__init__(transport)
        self._oid = table_oid
        self._row_class = row_class
        self._column_mapping = column_mapping

        if not walk_result:
            walk_result = transport.snmp_walk(table_oid)

        if not walk_result:
            warnings.warn("SNMP Walk of '%s' yielded no results" % table_oid)

        rawtable = parse_table(table_oid, walk_result)

        result_dict = dict()
        for row_id, row in rawtable.items():
            result_dict[row_id] = dict()
            for column_id, raw_value in row.items():
                if not column_id in column_mapping:
                    continue
                result_dict[row_id][column_id] = (table_oid + '.' + column_id + '.' + row_id,
                                                  raw_value,
                                                  column_mapping[column_id])
            if not result_dict[row_id]:
                del result_dict[row_id]

        # Then go through the result, and create a row object for each
        # row. Essentially, each row is a different class, as it may
        # have different attributes
        for rowkey, row in result_dict.items():
            # Build up the columns in the row
            class_dict = {
                mapping["name"]: Attribute(oid=oid,
                                           translator=mapping.get('translator', NullTranslator),
                                           instance=self,
                                           value=mapping.get('translator',
                                                             NullTranslator).pyvalue(raw_value),
                                           status=AttributeStatus.OK,
                                           readback_after_write=mapping.get("readback_after_write",
                                                                            True),
                                           doc=mapping.get('doc'))
                for oid, raw_value, mapping in row.values()
            }
            if not class_dict:
                # Empty rows are not interesting...
                continue
            # A litle trick: Redo it with a new dict, so we can get
            # the order "right" - i.e. the order it is done in the
            # mappings
            class_dict = {column['name']: class_dict[column['name']]
                          for column in column_mapping.values()
                          if column['name'] in class_dict}

            RowClass = type('Row', (self._row_class,), class_dict)
            self[rowkey] = RowClass(self, class_dict)

        if not self:
            warnings.warn("SMTP walk of %s resulted in zero rows"
                          % table_oid)

    @property
    def oid(self):
        """The base OID of the table, as passed to the contructor"""
        return self._oid

    def new_row(self, row_key, **kwargs):
        """Creates a new row in the table

        A new row may or may not have as many columns as the
        table. The initial value of the columns should be passed using
        keyword arguments: The row will only have the columns named as
        keyword arguments.

        """
        if row_key in self:
            raise ValueError("Key '%s' already exists in table" % row_key)

        mapping_names = [mapping["name"] for mapping in self._column_mapping.values()]

        for arg in kwargs:
            if arg not in mapping_names:
                raise TypeError("Invalid kwarg name '%s' - "
                                "expected one of %s" % (arg, mapping_names))

        rowclass_dict = {
            mapping["name"]: Attribute(
                oid=self.oid + '.' + column_oid + '.' + row_key,
                doc=mapping.get('doc'),
                instance=self,
                value=kwargs[mapping["name"]],
                status=AttributeStatus.NEEDS_WRITE,
                translator=mapping.get('translator', NullTranslator),
                readback_after_write=mapping.get('readback_after_write', True)
            )
            for column_oid, mapping in self._column_mapping.items()
            if mapping["name"] in kwargs
        }
        RowClass = type('Row', (self._row_class,), rowclass_dict)
        therow = RowClass(self, rowclass_dict)

        self[row_key] = therow
        return therow

    def format(self):
        """Get a string representation of the table for human consumption.

        This is nicely ordered in auto-sized columns with headers and
        (almost) graphics:

            +-------------+--------+---------------+-----------------------------------------+
            | IPAddr      | Prefix | NetMask       | GW                                      |
            +-------------+--------+---------------+-----------------------------------------+
            | 86.21.83.42 | 21     | 255.255.248.0 | 86.21.80.1                              |
            |             | 0      |               | 0000:000c:000f:cea0:000f:caf0:0000:0000 |
            +-------------+--------+---------------+-----------------------------------------+

        This format is best suited for tables with a limited number of
        columns and/or wide terminals.

        """
        return utils.format_table(self)

    def format_by_row(self):
        """Get a string representation of the table for human consumption.

        This lists each row as a sequence of lines, followed by the
        next row etc.  This format is well suited for tables with many
        columns and/or narrow terminals.

        """
        return utils.format_by_row(self)

    def aslist(self):
        """Get the rows as a list

        This will 'lose' the ID of the rows, which most of the time is
        not a problem.

        """
        return self.values()

    def __delitem__(self, key):
        if key in self and hasattr(self[key], 'rowstatus'):
            self[key].rowstatus = RowStatus.DESTROY
        dict.__delitem__(self, key)

class PortForwardTable(Table):
    """The port forwarding table from the hub

        Traffic arriving from the WAN will be forwarded to the internal
        servers as per the mapping.
    """
    def __init__(self, hub):
        super().__init__(table_oid="1.3.6.1.4.1.4115.1.20.1.1.4.12.1",
                         transport=hub,
                         column_mapping={
                             "11": dict(name="rowstatus",
                                        doc="Row status to add/remove rows",
                                        translator=RowStatusTranslator,
                                        readback_after_write=False),
                             "5": dict(name="proto",
                                       translator=IPProtocolTranslator),
                             "3": dict(name="ext_port_start",
                                       translator=PortTranslator),
                             "4": dict(name="ext_port_end",
                                       translator=PortTranslator),
                             "6": dict(name="local_addr_type",
                                       translator=IPVersionTranslator),
                             "7": dict(name="local_addr",
                                       translator=IPAddressTranslator),
                             "9": dict(name="local_port_start",
                                       translator=PortTranslator),
                             "10": dict(name="local_port_end",
                                        translator=PortTranslator)
                         })

class EtherPortTable(Table):
    """The physical ethernet ports

    """
    def __init__(self, hub):
        super().__init__(table_oid="1.3.6.1.4.1.4115.1.20.1.1.2.8.1",
                         transport=hub,
                         column_mapping={
                             "1": dict(name="idx"),
                             "2": dict(name="if_index"),
                             "3": dict(name="enabled",
                                       translator=BoolTranslator),
                             "4": dict(name="duplex",
                                       translator=BoolTranslator),
                             "5": dict(name="speed_mbps",
                                       translator=IntTranslator),
                             "6": dict(name="auto_negotiate",
                                       translator=BoolTranslator),
                             "7": dict(name="haslink",
                                       translator=BoolTranslator)
                         })

    def __delitem__(self, key):
        raise NotImplementedError("Deleting physical ethernet ports requires more than just python")

class BSSTable(Table):
    """Wifi networks"""
    def __init__(self, hub):
        super().__init__(table_oid="1.3.6.1.4.1.4115.1.20.1.1.3.22.1",
                         transport=hub,
                         column_mapping={
                             "1": dict(name="mac",
                                       translator=MacAddressTranslator),
                             "2": dict(name="ssid"),
                             "3": dict(name="active",
                                       translator=BoolTranslator),
                             "4": dict(name="ssid_broadcast",
                                       translator=BoolTranslator),
                             "5": dict(name="security_mode"),
                             "6": dict(name="access_mode"),
                             "7": dict(name="network_isolate",
                                       translator=BoolTranslator),
                             "8": dict(name="mac_access_count",
                                       translator=IntTranslator),
                             "10": dict(name="arp_audit_interval",
                                        translator=IntTranslator),
                             "11": dict(name="max_wifi_clients",
                                        translator=IntTranslator),
                             "12": dict(name="wmm_enable",
                                        translator=BoolTranslator),
                             "13": dict(name="wmm_apsd"),
                             "14": dict(name="active_timeout",
                                        translator=DateTimeTranslator),
                             "15": dict(name="default_ssid"),
                             "16": dict(name="sta_steering",
                                        translator=BoolTranslator),
                         })

class LanTable(Table):
    """Information about the local LAN networks

    The router can normally handle more than one network, A single
    network can span multiple interfaces.

    """
    def __init__(self, transport):
        super().__init__(
            table_oid="1.3.6.1.4.1.4115.1.20.1.1.2.2.1",
            transport=transport,
            column_mapping={
                "1": dict(name="name"),
                "27": dict(name="interfaces",
                           doc="""\
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
                            be assigned to more than one logical interface"""),
                "8": dict(name="vlan",
                          translator=IntTranslator,
                          doc="VLAN ID - use zero for untagged"),
                "21": dict(name="passthrough",
                           doc="""\
                            Whether or not this Lan is in pass-thru mode or bridged/NAT. To put the device into
                            non-bridged mode with routing and NAT disabled -- pass-thru, use: passThru(1). To
                            put the device into bridged (routed) mode with Network Address Translation (NAT)
                            enabled use: routedNAT(2). To put the device into bridged (routed) mode with
                            Network Address Translation (NAT) disabled use: routedNoNAT(3)"""),
                "4": dict(name="gateway_ip_type",
                          translator=IPVersionTranslator),
                "5": dict(name="gateway_ip",
                          translator=IPAddressTranslator,
                          doc="Gateway IP address"),
                "6": dict(name="gateway_ip2_type",
                          translator=IPVersionTranslator),
                "7": dict(name="gateway_ip2",
                          translator=IPAddressTranslator,
                          doc="Second gateway IP address"),
                "2": dict(name="subnet_mask_type",
                          translator=IPVersionTranslator),
                "3": dict(name="subnet_mask",
                          translator=IPv4Translator),
                "9": dict(name="use_dhcp",
                          translator=BoolTranslator,
                          doc="enable or disable the DHCP server on this LAN"),
                "10": dict(name="dhcp_start_ip_type",
                           translator=IPVersionTranslator),
                "11": dict(name="dhcp_start_ip",
                           translator=IPAddressTranslator,
                           doc="Start of DHCP IP range"),
                "12": dict(name="dhcp_end_ip_type",
                           translator=IPVersionTranslator),
                "13": dict(name="dhcp_end_ip",
                           translator=IPAddressTranslator,
                           doc="End of DHCP IP range"),
                "14": dict(name="dhcp_lease_time",
                           translator=IntTranslator,
                           doc="DHCP Lease time in seconds"),
                "15": dict(name="domain_name"),
                "19": dict(name="dns_relay_enabled",
                           translator=BoolTranslator),
                "25": dict(name="dns_override_enabled",
                           translator=BoolTranslator,
                           doc="""\
                            If DNS override is enabled, the IP addresses in arrisRouterLanDNSTable will be
                            passed to LAN clients via DHCP.  Otherwise, the DNS servers received by the WAN
                            connection will be passed to the LAN clients."""),
                "22": dict(name="firewall_enabled",
                           translator=BoolTranslator),
                "23": dict(name="upnp_enabled",
                           translator=BoolTranslator),
                "24": dict(name="aging_time",
                           translator=IntTranslator,
                           doc="The timeout period in seconds for aging out dynamically " \
                           "learned forwarding information. " \
                           "The default value of zero means do not age "),
                "39": dict(name="parental_controls_enabled",
                           translator=BoolTranslator),
                "26": dict(name="nat_algs_enabled",
                           doc="""\
                            Specifies which NAT application layer gateway supplements are enabled on this
                            device.  The default value for this object is for all ALG's to be enabled. Reserved
                            bits are for ALGs that are currently not supported."""),
                "28": dict(name="environment_control",
                           translator=BoolTranslator,
                           doc="""\
                              Controls whether or not the settings which define the operating environment of
                              the logical interface, aka LAN subnet, are changeable via the GUI. When equal to
                              unlocked, the environment settings MAY be changed via the UI. When equal to
                              locked, the environment settings MAY NOT be changed via the UI"""),
            })

class WifiClientTable(Table):
    """Information about the currently connected WIFI clients

    """
    def __init__(self, transport):
        super().__init__(
            table_oid="1.3.6.1.4.1.4115.1.20.1.1.3.42.1",
            transport=transport,
            column_mapping={
                "1": dict(name="index"),
                "2": dict(name="ip_version",
                          translator=IPVersionTranslator),
                "3": dict(name="ipaddr",
                          translator=IPAddressTranslator),
                "5": dict(name="hostname"),
                "6": dict(name="mac",
                          translator=MacAddressTranslator),
                "7": dict(name="manufacturer"),
                "8": dict(name="status"),
                "9": dict(name="first_seen",
                          translator=DateTimeTranslator),
                "10": dict(name="last_seen",
                           translator=DateTimeTranslator),
                #  These seem unreliable!? So why bother...
                # "11": dict(name="idle_seconds",
                #            translator=IntTranslator),
                # "12": dict(name="connected_secs",
                #            translator=IntTranslator),
                "13": dict(name="state"),
                "14": dict(name="flags"),
                "15": dict(name="tx_packets",
                           translator=IntTranslator,
                           doc="# of packets transmitted from this device since it was connected"),
                "16": dict(name="tx_fail",
                           translator=IntTranslator,
                           doc="# of packet xmit failures from this device since it was connected"),
                "17": dict(name="rx_unicast_pkts",
                           translator=IntTranslator,
                           doc="# of unicast packets from this device since it was last connected"),
                "18": dict(name="rx_multicast_pkts",
                           translator=IntTranslator,
                           doc="# of multicast packets from this device since it was last connected"),
                "19": dict(name="last_tx_rate",
                           translator=IntTranslator,
                           doc="Reception rate of the last packet transmitted by this wireless device in kbps/sec"),
                "20": dict(name="last_rx_rate",
                           translator=IntTranslator,
                           doc="Reception rate of the last packet received by this wireless device in kbps/sec"),
                "21": dict(name="supported_rates",
                           doc="Supported rate set for this device"),
                "22": dict(name="rssi",
                           doc="Received Signal Strength Indicator - higher values (towards +infinity) are better")
            })


def _run_tests():
    import doctest
    import sys

    fail_count, test_count = doctest.testmod(report=True)
    if fail_count:
        raise SystemExit("%d out of %d doc tests failed" % (fail_count, test_count))
    print("%s: Doc tests were all OK" % sys.argv[0])

if __name__ == "__main__":
    _run_tests()
