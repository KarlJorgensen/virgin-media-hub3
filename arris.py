#!/usr/bin/python
"""Arris specific SNMP support"""

import enum

import snmp

class ClientType(snmp.HumaneEnum):
    """Client types in the LanClientTable"""

    UNKNOWN = "0"
    "No client should use this value"

    DYNAMIC = "1"
    """The client IP address is in DHCPv6 or DHCPv6 lease file, but it
    is not configured as Reserved client on WebGUI)"""

    STATIC = "5"
    """If the client is online, and we can't find the client information
    in DHCPv4 or DHCPv6 lease file and it is not configured as
    Reserved client on WebGUI, then we put it types to static. Notice
    IPv6 stateless client and link local client would also tagged as
    this type)

    """
    DYNAMIC_RESERVED = "6"
    "The Reserved client configured on WebGUI"

# pylint: disable=invalid-name
ClientTypeTranslator = snmp.EnumTranslator(ClientType)

class WanNetworksTable(snmp.Table):
    """List of WAN networks

    In some environments, there may be both an IPv6 and IPv6 address
    or multiple IPv6 addresses.

    The size of this table is usually limited to 4 entries
    """
    def __init__(self, transport):
        super().__init__(
            table_oid="1.3.6.1.4.1.4115.1.20.1.1.1.7.1",
            transport=transport,
            column_mapping={
                "1": dict(name="Index"),
                "2": dict(name="addr_type",
                          translator=snmp.IPVersionTranslator,
                          doc="Static IP address type"),
                "3": dict(name="ipaddr",
                          translator=snmp.IPAddressTranslator,
                          doc="Static IP addressfor Wan connection"),
                "4": dict(name="prefix",
                          translator=snmp.IntTranslator,
                          doc="Netmask (Prefix)"),
                "8": dict(name="netmask",
                          translator=snmp.IPv4Translator,
                          doc="Netmask if it is IPv4"),
                "5": dict(name="gw_ip_type",
                          translator=snmp.IPVersionTranslator,
                          doc="Gateway Address type"),
                "6": dict(name="gw",
                          translator=snmp.IPAddressTranslator,
                          doc="Gateway address"),
                # "7": dict(name="iptype",
                #           translator=snmp.IPVersionTranslator,
                #           doc="Type of IP address. This appears to be unreliable..."),
                "9": dict(name="prefix_delegation",
                          translator=snmp.IPv6Translator,
                          doc="The prefix, or initial bits of the address, given "
                          "to the router to delegate to its attached CPEs"),
                "10": dict(name="prefix_delegation_len",
                           translator=snmp.IntTranslator,
                           doc="The length for the prefix to be delegated to attached CPEs"),
                "11": dict(name="preferredlifetimev6",
                           translator=snmp.IntTranslator,
                           doc="The preferred lifetime for the assigned IPv6 address "
                           "of the router"),
                "12": dict(name="validlifetimev6",
                           translator=snmp.IntTranslator,
                           doc="The valid lifetime for the assigned IPv6 address "
                           "of the router")
            })

class DNSServerTable(snmp.Table):
    """List of DNS servers known/used by the hub"""
    def __init__(self, transport):
        super().__init__(
            table_oid="1.3.6.1.4.1.4115.1.20.1.1.1.11.2.1",
            transport=transport,
            column_mapping={
                "1": dict(name="index",
                          translator=snmp.IntTranslator),
                "2": dict(name="ip_version",
                          translator=snmp.IPVersionTranslator),
                "3": dict(name="ipaddr",
                          translator=snmp.IPAddressTranslator)})

class Interfaces(enum.IntFlag):
    """Bitmask for interfaces"""
    ETHERNET = 0x00000001
    USB = 0x00000002
    MOCA = 0x00000004  # apparantly unsupported on TG2492LG-85/10
    SSID1 = 0x00000008
    SSID2 = 0x00000010
    SSID3 = 0x00000020
    SSID4 = 0x00000040
    SSID5 = 0x00000080
    SSID6 = 0x00000100
    SSID7 = 0x00000200
    SSID8 = 0x00000400

class BitmaskTranslator(snmp.Translator):
    """Translates an SNMP bitmask to/from a python set"""

    def __init__(self, enumclass):
        self._enumclass = enumclass

    def snmp(self, python_value):
        if isinstance(python_value, self._enumclass):
            return str(python_value.value)
        raise TypeError

    def pyvalue(self, snmp_value):
        return self._enumclass(int(snmp_value))

class LanTable(snmp.Table):
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
                           translator=BitmaskTranslator(Interfaces),
                           doc="physical network interfaces for this logical network"),
                "8": dict(name="vlan",
                          translator=snmp.IntTranslator,
                          doc="VLAN ID - use zero for untagged"),
                "21": dict(name="passthrough",
                           doc="""\
                            Whether or not this Lan is in pass-thru mode or bridged/NAT. To put the device into
                            non-bridged mode with routing and NAT disabled -- pass-thru, use: passThru(1). To
                            put the device into bridged (routed) mode with Network Address Translation (NAT)
                            enabled use: routedNAT(2). To put the device into bridged (routed) mode with
                            Network Address Translation (NAT) disabled use: routedNoNAT(3)"""),
                "4": dict(name="gw_ip_type",
                          translator=snmp.IPVersionTranslator),
                "5": dict(name="gw_ip",
                          translator=snmp.IPAddressTranslator,
                          doc="Gateway IP address"),
                # "6": dict(name="gw_ip2_type",
                #           translator=snmp.IPVersionTranslator),
                # "7": dict(name="gw_ip2",
                #           translator=snmp.IPAddressTranslator,
                #           doc="Second gateway IP address"),
                "2": dict(name="subnet_mask_type",
                          translator=snmp.IPVersionTranslator),
                "3": dict(name="subnet_mask",
                          translator=snmp.IPv4Translator),
                "9": dict(name="use_dhcp",
                          translator=snmp.BoolTranslator,
                          doc="enable or disable the DHCP server on this LAN"),
                "10": dict(name="dhcp_start_ip_type",
                           translator=snmp.IPVersionTranslator),
                "11": dict(name="dhcp_start_ip",
                           translator=snmp.IPAddressTranslator,
                           doc="Start of DHCP IP range"),
                "12": dict(name="dhcp_end_ip_type",
                           translator=snmp.IPVersionTranslator),
                "13": dict(name="dhcp_end_ip",
                           translator=snmp.IPAddressTranslator,
                           doc="End of DHCP IP range"),
                "14": dict(name="dhcp_lease_time",
                           translator=snmp.IntTranslator,
                           doc="DHCP Lease time in seconds"),
                "15": dict(name="domain_name"),
                "19": dict(name="dns_relay",
                           translator=snmp.BoolTranslator),
                "25": dict(name="dns_override",
                           translator=snmp.BoolTranslator,
                           doc="""\
                            If DNS override is enabled, the IP addresses in arrisRouterLanDNSTable will be
                            passed to LAN clients via DHCP.  Otherwise, the DNS servers received by the WAN
                            connection will be passed to the LAN clients."""),
                "22": dict(name="firewall",
                           translator=snmp.BoolTranslator),
                "23": dict(name="upnp",
                           translator=snmp.BoolTranslator),
                "24": dict(name="aging_time",
                           translator=snmp.IntTranslator,
                           doc="The timeout period in seconds for aging out dynamically " \
                           "learned forwarding information. " \
                           "The default value of zero means do not age "),
                "39": dict(name="parental_controls",
                           translator=snmp.BoolTranslator),
                "26": dict(name="nat_algs",
                           doc="""\
                            Specifies which NAT application layer gateway supplements are enabled on this
                            device.  The default value for this object is for all ALG's to be enabled. Reserved
                            bits are for ALGs that are currently not supported."""),
                "28": dict(name="env_control",
                           translator=snmp.BoolTranslator,
                           doc="""\
                              Controls whether or not the settings which define the operating environment of
                              the logical interface, aka LAN subnet, are changeable via the GUI. When equal to
                              unlocked, the environment settings MAY be changed via the UI. When equal to
                              locked, the environment settings MAY NOT be changed via the UI"""),
            })


class LanClientTable(snmp.Table):
    """Information about LAN clients.

    This includes both wired and wireless clients.

    Retrieving this list can take 10 seconds or more...
    """
    def __init__(self, transport):
        super().__init__(
            table_oid="1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1",
            transport=transport,
            column_mapping={
                "1": dict(name="addrtype",
                          translator=snmp.IPVersionTranslator),
                "2": dict(name="ipaddr",
                          translator=snmp.IPAddressTranslator),
                "3": dict(name="hostname"),
                "4": dict(name="mac_address",
                          translator=snmp.MacAddressTranslator),
                "6": dict(name="adapter_type"),
                "7": dict(name="client_type",
                          translator=ClientTypeTranslator),
                "9": dict(name="lease_end",
                          translator=snmp.DateTimeTranslator),
                "13": dict(name="rowstatus",
                           translator=snmp.RowStatusTranslator),
                "14": dict(name="online",
                           translator=snmp.BoolTranslator),
                "15": dict(name="comment"),
                # "17": dict(name="manufacturer"),
                "18": dict(name="serialno"),
                "19": dict(name="product_class"),
                "20": dict(name="device_name"),
                "24": dict(name="last_change_secs",
                           translator=snmp.IntTranslator),
                "25": dict(name="connected_secs",
                           translator=snmp.IntTranslator)
                })

class EtherPortTable(snmp.Table):
    """The physical ethernet ports

    """
    def __init__(self, hub):
        super().__init__(table_oid="1.3.6.1.4.1.4115.1.20.1.1.2.8.1",
                         transport=hub,
                         column_mapping={
                             "1": dict(name="idx"),
                             "2": dict(name="if_index"),
                             "3": dict(name="enabled",
                                       translator=snmp.BoolTranslator),
                             "4": dict(name="duplex",
                                       translator=snmp.BoolTranslator),
                             "5": dict(name="speed_mbps",
                                       translator=snmp.IntTranslator),
                             "6": dict(name="auto_negotiate",
                                       translator=snmp.BoolTranslator),
                             "7": dict(name="haslink",
                                       translator=snmp.BoolTranslator)
                         })

    def __delitem__(self, key):
        raise NotImplementedError("Deleting physical ethernet ports requires more than just python")

class AccessMode(snmp.HumaneEnum):
    """Defines which wifi clients will be allowed to connect"""
    ALLOW_ANY = "1"
    WHITELIST = "2"
    """Only stations whose MAC address appears in the
    arrisRouterMACAccessTable will be allowed to connect.
    """
    BLACKLIST = "3"
    """Only stations whose MAC address do NOT appear in the
    arrisRouterMACAccessTable will be allowed to connect.
    """

class BSSTable(snmp.Table):
    """Wifi networks"""
    def __init__(self, hub):
        super().__init__(table_oid="1.3.6.1.4.1.4115.1.20.1.1.3.22.1",
                         transport=hub,
                         column_mapping={
                             "1": dict(name="mac",
                                       translator=snmp.MacAddressTranslator),
                             "2": dict(name="ssid"),
                             "3": dict(name="active",
                                       translator=snmp.BoolTranslator),
                             "4": dict(name="ssid_broadcast",
                                       translator=snmp.BoolTranslator),
                             "5": dict(name="security_mode"),
                             "6": dict(name="access_mode",
                                       translator=snmp.EnumTranslator(AccessMode)),
                             "7": dict(name="network_isolate",
                                       translator=snmp.BoolTranslator,
                                       doc="when isolated, devices on this network "
                                       "cannot access other local networks"),
                             # mac_access_count is always zero on TG2492LG-85/10 !?
                             # Useless.
                             # "8": dict(name="mac_access_count",
                             #           translator=snmp.IntTranslator),
                             "10": dict(name="arp_audit_interval",
                                        translator=snmp.IntTranslator),
                             "11": dict(name="max_wifi_clients",
                                        translator=snmp.IntTranslator),
                             "12": dict(name="wmm_enable",
                                        translator=snmp.BoolTranslator),
                             "13": dict(name="wmm_apsd"),
                             "14": dict(name="active_timeout",
                                        translator=snmp.DateTimeTranslator),
                             "15": dict(name="default_ssid"),
                             "16": dict(name="sta_steering",
                                        translator=snmp.BoolTranslator),
                         })

class WifiClientTable(snmp.Table):
    """Information about the currently connected WIFI clients

    """
    def __init__(self, transport):
        super().__init__(
            table_oid="1.3.6.1.4.1.4115.1.20.1.1.3.42.1",
            transport=transport,
            column_mapping={
                "1": dict(name="index"),
                "2": dict(name="ip_version",
                          translator=snmp.IPVersionTranslator),
                "3": dict(name="ipaddr",
                          translator=snmp.IPAddressTranslator),
                "5": dict(name="hostname"),
                "6": dict(name="macaddr",
                          translator=snmp.MacAddressTranslator),
                "7": dict(name="manufacturer"),
                "8": dict(name="status"),
                "9": dict(name="first_seen",
                          translator=snmp.DateTimeTranslator),
                "10": dict(name="last_seen",
                           translator=snmp.DateTimeTranslator),
                #  These seem unreliable!? So why bother...
                # "11": dict(name="idle_seconds",
                #            translator=snmp.IntTranslator),
                # "12": dict(name="connected_secs",
                #            translator=snmp.IntTranslator),
                "13": dict(name="state"),
                "14": dict(name="flags"),
                "15": dict(name="tx_packets",
                           translator=snmp.IntTranslator,
                           doc="# of packets transmitted from this device "
                           "since it was connected"),
                "16": dict(name="tx_fail",
                           translator=snmp.IntTranslator,
                           doc="# of packet xmit failures from this device "
                           "since it was connected"),
                "17": dict(name="rx_unicast_pkts",
                           translator=snmp.IntTranslator,
                           doc="# of unicast packets from this device "
                           "since it was last connected"),
                "18": dict(name="rx_multicast_pkts",
                           translator=snmp.IntTranslator,
                           doc="# of multicast packets from this device "
                           "since it was last connected"),
                "19": dict(name="last_tx_rate",
                           translator=snmp.IntTranslator,
                           doc="Reception rate of the last packet transmitted "
                           "by this wireless device in kbps/sec"),
                "20": dict(name="last_rx_rate",
                           translator=snmp.IntTranslator,
                           doc="Reception rate of the last packet received by "
                           "this wireless device in kbps/sec"),
                "21": dict(name="supported_rates",
                           doc="Supported rate set for this device"),
                "22": dict(name="rssi",
                           translator=snmp.IntTranslator,
                           doc="Received Signal Strength Indicator - "
                           "higher values (towards +infinity) are better")
            })

class PortForwardTable(snmp.Table):
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
                                        translator=snmp.RowStatusTranslator,
                                        readback_after_write=False),
                             "5": dict(name="proto",
                                       translator=snmp.IPProtocolTranslator),
                             "3": dict(name="ext_port_start",
                                       translator=snmp.PortTranslator),
                             "4": dict(name="ext_port_end",
                                       translator=snmp.PortTranslator),
                             "6": dict(name="local_addr_type",
                                       translator=snmp.IPVersionTranslator),
                             "7": dict(name="local_addr",
                                       translator=snmp.IPAddressTranslator),
                             "9": dict(name="local_port_start",
                                       translator=snmp.PortTranslator),
                             "10": dict(name="local_port_end",
                                        translator=snmp.PortTranslator)
                         })

class TODStatus(snmp.HumaneEnum):
    """NTP status for the hub"""
    NOT_PROVISIONED = "0"
    MISSING_SERVER_ADDRESS1 = "1"
    MISSING_SERVER_ADDRESS2 = "2"
    MISSING_SERVER_ADDRESS3 = "3"
    STARTING_REQUEST = "4"
    REQUEST_FAILED = "5"
    NO_RESPONSE_RECEIVED = "6"
    INVALID_DATA_FORMAT = "7"
    RETRIEVED = "8"
    FAILED = "9"

# pylint: disable=invalid-name
TODStatusTranslator = snmp.EnumTranslator(TODStatus)

def _run_tests():
    import doctest
    import sys

    fail_count, test_count = doctest.testmod(report=True)
    if fail_count:
        raise SystemExit("%d out of %d doc tests failed" % (fail_count, test_count))
    print("%s: Doc tests were all OK" % sys.argv[0])

if __name__ == "__main__":
    _run_tests()
