.EXPORT_ALL_VARIABLES:
CFLAGS += -D_BYTE_ORDER=_BIG_ENDIAN
CFLAGS += -I$(ATHEROS_DIR)/wlan/core # change to reflect local setup; directory for atheros src
CFLAGS += -I$(ATHEROS_DIR)/wlan/core/include # change to reflect local setup; directory for atheros src
MADWIFIPATH=$(ATHEROS_DIR)/wlan/core

all: 
	$(MAKE)

clean:
	$(MAKE) clean
