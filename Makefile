#!/usr/bin/make -f

PYFILES=utils.py arris.py snmp.py virginmedia.py hub

all : selftest pylints

.PHONY: clean

# A deeper selftest. Even if they succeed, the output should be
# eyeballed by a developer.
.PHONY: selftest
selftest: pylints unittests
	./virginmedia.py
	./hub property-list
	./hub backup
	./hub info
	./hub snmp-walk 1.3.6.1.4.1.4115.1.20.1.1.1.7.1
	./hub snmp-walk 1.3.6.1.4.1.4115.1.20.1.1.1.7.1 --byrow
	./hub ether-ports
	./hub wan-status
	./hub wan-networks
	./hub lan-networks
	./hub wifi-status
	./hub portforward-list
	./hub property-get hardware_version firmware_version serial_number
	! ./hub property-set hardware_version "This should fail. Do not worry."

.PHONY: pylints
pylints: $(PYFILES:%=.%.lint)

clean ::
	rm -f $(PYFILES:%=.%.lint)

# Unit tests that do not require access to an actual Virgin Media Hub
.PHONY: unittests
unittests: pylints
	python3 ./utils.py
	python3 ./snmp.py
	python3 ./arris.py
	./hub --help

# pylint exit code is a bitmask - we are only interested in fatal/error here
.%.lint : %
	pylint3 --reports=n --output-format=parseable $< ; test $$(( $$? & 3 )) -eq 0
	touch $@
