GCC_PREFIX = /usr
CC_CMD = gcc
LD_CMD = gcc
CC = $(GCC_PREFIX)/bin/$(CC_CMD)
LD = $(GCC_PREFIX)/bin/$(LD_CMD)

# Configure OPSEC SDK 6.1 path.
OPSEC_DIR = /opt/Check_Point_OPSEC_SDK_6.1_linux50/pkg_rel

LIB_DIR = $(OPSEC_DIR)/lib/release.dynamic
LIBS = -lpthread -lresolv -ldl -lnsl -lopsec -lcpprod50 -lsicauth -lskey -lfwsetdb -lndb \
	-lsic -lcp_policy -lcpca -lckpssl -lcpcert -lcpcryptutil -lEncode -lcpprng \
	-lProdUtils -lcpbcrypt -lcpopenssl -lAppUtils -lComUtils -lResolve -lEventUtils -lDataStruct \
	-lOS

CFLAGS += -m32 -g -Wall -fPIC -I$(OPSEC_DIR)/include -DLINUX -DUNIXOS=1

APP_NAME = lea_client
OBJ_FILES = lea_client.o

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $*.c

build: $(OBJ_FILES)
	$(LD) $(CFLAGS) -L$(LIB_DIR) -o $(APP_NAME) $(OBJ_FILES) $(LIBS)
.PHONY: build

clean:
	rm -f *.o $(APP_NAME)
.PHONY: clean

run: build
run: export LD_LIBRARY_PATH=$(LIB_DIR)
run:
	./$(APP_NAME) lea.conf
.PHONY: run