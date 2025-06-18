all:	cbridge tools

cbridge:	.FORCE
	make -C src

tools:	.FORCE
	make -C tools

.FORCE:
