# Make sure to comment out CC, AR, RANLIB in the Makefile
.EXPORT_ALL_VARIABLES:
PREFIX=build

all: 
	mkdir -p $(PREFIX)
	$(MAKE) install

clean:
	$(MAKE) realclean
	rm -rf $(PREFIX)
