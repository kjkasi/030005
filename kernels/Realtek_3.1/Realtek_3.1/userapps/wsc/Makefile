CRYPTLIB = portingssl
WSCSRC = src

all:
	make -C $(CRYPTLIB)

	@echo "" > ./.diff_config; 

	@if [ -e .kernel_config ]; then \
		diff .kernel_config ../../linux/.config > .diff_config; \
		if [ -s .diff_config ]; then \
		        cp ../../linux/.config .kernel_config; \
			make -C $(WSCSRC) clean; \
                fi; \
        else \
                cp ../../linux/.config ./.kernel_config; \
	fi;

	make -C $(WSCSRC)
	
clean:
	make -C $(CRYPTLIB) clean
	make -C $(WSCSRC) clean

romfs:
	$(ROMFSINST) $(WSCSRC)/wscd /bin/wscd
	$(ROMFSINST) $(WSCSRC)/wscd.conf /etc/wscd.conf
