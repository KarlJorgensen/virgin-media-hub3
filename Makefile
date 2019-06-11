#!/usr/bin/make -f


all : selftest pylints

.PHONY: clean

.PHONY: selftest
selftest: pylints
	./virginmedia.py
	./hub properties
	./hub info
	./hub lanstatus
	./hub wanstatus
	./hub portforward_list
	./hub get_property hardware_version firmware_version serial_number
	! ./hub set_property hardware_version "This should fail. Do not worry."

.PHONY: pylints
pylints: .hub.lint .virginmedia.py.lint

clean ::
	rm -f .hub.lint .virginmedia.py.lint

# pylint exit code is a bitmask - we are only interested in fatal/error here
.%.lint : %
	pylint3 --reports=n --output-format=parseable $< ; test $$(( $$? & 3 )) -eq 0
	touch $@

router.dat : perms
	./configure | ./encode > router.dat

.PHONY : perms
perms:
	chmod +x configure encode decode
