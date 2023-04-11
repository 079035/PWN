ifndef objtree
all:
	make -C ../linux-5.4.63-1+drhlke M="$$PWD" modules

clean:
	make -C ../linux-5.4.63-1+drhlke M="$$PWD" clean
endif

obj-m += lke-bof.o
lke-bof-objs += main.o vuln.o
