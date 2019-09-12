virgin-media-hub3
=================

This is a python API and command line interface for the Virgin Media
Hub 3 broadband router.

This allows you to view/change the configuration of the router through
a decent API or through the command line.

Unlike the (rather mediocre) web interface, this allows you to
view/change settings that are not necessarily exposed through the web
interface. For example, you can add port forwardings for ports that
the web interface will not allow (e.g. port 53 if you want to run a
local DNS server).

The Virgin Media Hub 3 is a customised version of the Arris TG2492
router:

- Sales blurb:  https://www.arris.com/products/touchstone-telephony-gateway-tg2492-s/

- End user documentation : https://fccid.io/UIDTG2492/User-Manual/Users-Guide-3118366

At the moment, this repo is somewhat basic: There is no python pip
package structure. Yet. And no Debian or RedHat packages.

And it has dependencies: Nothing serious:

- python-requests
- python-netaddr
- pyyaml

To use it, you use the source:

    git clone git@github.com:KarlJorgensen/virgin-media-hub3.git
    cd virgin-media-hub3
    pip install -r requirements.txt
    export HUB_PASSWORD=YourRouterPassword
    export HUB=YourRouterAddress
    ./hub info
    ./hub --help


There is a sizeable number of subcommands - check the output of
<kbd>hub --help</kbd> for details.  For more details about each
subcommand, invoke the subcommand with the <kbd>--help</kbd>
parameter - e.g. <kbd>./hub portforward-add --help</kbd>.

For example, to add a port forwarding to your internal web server at
<kbd>192.168.0.16</kbd>:

    ./hub portforward-add TCP 80 192.168.0.16 80
	./hub property-set firewall_enabled True

Enjoy!
