all:	cbridge tools

cbridge:	.FORCE
	make -C src

tools:	.FORCE
	make -C tools

clean:	.FORCE
	make -C src clean
	make -C tools clean

.FORCE:
