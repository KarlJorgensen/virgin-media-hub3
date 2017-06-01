#!/usr/bin/make -f

router.dat : perms
	./configure | ./encode > router.dat

.PHONY : perms
perms:
	chmod +x configure encode decode
