ifndef objtree
all:
	make -C ../linux-5.4.63-1+drhlke M="$$PWD" modules

clean:
	make -C ../linux-5.4.63-1+drhlke M="$$PWD" clean
endif

CFLAGS_lke-ret2usr.o += -fno-stack-protector
obj-m += lke-ret2usr.o
