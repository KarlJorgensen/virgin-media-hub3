HACKING
=======

To hack around with the source code, you will need:

- A virgin media router. Preferably a Virgin Media Hub 3. These are
  customised Arris routers - most of the development was done with a
  TG2492LG-85, hardware version 10, bootcode version 4.2.0.45,
  firmware version 9.1.1802.613.  (this information can be obtained
  using the "hub info" command")

  Most (all?) of the code should work OK with other similar Arris
  routers - this is entirely untested, so this would probably be a
  good area to improve.

  If you have a different model please update SUPPORTED_ROUTERS.md
  with your findings.

- Knowing python really really helps!

- A decent understanding of HTTP: Communication with the router is
  entirely via HTTP

- A decent understanding of SNMP helps, as the router uses SNMP
  over-HTTP

- GNU Make
- python3
- pylint3
- python-requests

- For some tasks, it is useful to first do the task through the web
  interface and use Firefox's developer mode to track the HTTP
  requests. Alternatively, use tcpdump and/or wireshark to capture and
  analyze the traffic.

Interesting other stuff:

- https://wikidevi.com/wiki/Virgin_Media_Super_Hub_3
- Hacking an Arris Cablemodem : https://blog.korelogic.com/blog/2016/02/12
- Teardown: https://www.mobile-computer-repairs.co.uk/blog/topic/29/routers/Arris-TG2492
- https://www.netscylla.com/blog/2019/02/04/Arris-CableModem-SNMP.html


MIBs:
- https://mibs.observium.org/mib/ARRIS-MTA-DEVICE-MIB/
- https://mibs.observium.org/mib/ARRIS-ROUTER-DEVICE-MIB/
- https://mibs.observium.org/mib/ARRIS-CM-DOC30-DEVICE-MIB/
- http://www.bowe.id.au/michael/isp/docsis/mibs/arris-docsis3/moca_11.mib
- https://mibs.observium.org/mib/ESAFE-MIB/
