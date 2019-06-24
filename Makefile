#!/usr/bin/make -f

PYFILES=utils.py snmp.py virginmedia.py hub

all : selftest pylints

.PHONY: clean

.PHONY: selftest
selftest: pylints unittests
	./utils.py
	./virginmedia.py
	./hub property-list
	./hub info
	./hub snmp-walk 1.3.6.1.4.1.4115.1.20.1.1.1.7.1
	./hub snmp-walk 1.3.6.1.4.1.4115.1.20.1.1.1.7.1 --byrow
	./hub wan-status
	./hub wan-iplist
	./hub lan-networks
	./hub wifi-status
	./hub portforward-list
	./hub property-get hardware_version firmware_version serial_number
	! ./hub property-set hardware_version "This should fail. Do not worry."

.PHONY: pylints
pylints: $(PYFILES:%=.%.lint)

clean ::
	rm -f $(PYFILES:%=.%.lint)

.PHONY: unittests
unittests: pylints
	python3 ./utils.py
	python3 ./snmp.py

# pylint exit code is a bitmask - we are only interested in fatal/error here
.%.lint : %
	pylint3 --reports=n --output-format=parseable $< ; test $$(( $$? & 3 )) -eq 0
	touch $@

router.dat : perms
	./configure | ./encode > router.dat

.PHONY : perms
perms:
	chmod +x configure encode decode
