BUILD_ROOT = ${PWD}/../../../../build
EXAMPLE = example_vhost_net_app
EXAMPLE_SRC = ./example/example.c
EXAMPLE_NAME = example_vhost_net_app
EXAMPLE_CFLAGS += -std=gnu99 -Wall -g -L./lib/ -L${BUILD_ROOT}/lib -ljnprvnet -lrt -lpcap -lnl-3 -lnl-genl-3
INCLS = -I${PWD}/../../../../build/include
EXAMPLE_CFLAGS += ${INCLS}

LIB = contrail_vhost_net
LIB_NAME = libjnprvnet.a
LIB_C_SRCS += ./src/client.c ./src/sh_mem.c ./src/vhost_client.c ./src/virt_queue.c
LIB_OBJS = ${LIB_C_SRCS:.c=.o}
LIB_CFLAGS += -std=gnu99

 
.PHONY: all clean distclean src_clean  lib_clean example_clean $(LIB) example

all: $(LIB) example

lib: $(LIB)

example: $(LIB)
		$(CC) $(EXAMPLE_SRC) -o $(EXAMPLE_NAME) $(EXAMPLE_CFLAGS)
		mv $(EXAMPLE_NAME) ./example

$(LIB): $(LIB_C_SRCS)
		$(CC) -c $(LIB_C_SRCS) $(LIB_CFLAGS)
		mv *.o ./src
		ar -rcs $(LIB_NAME) $(LIB_OBJS)
		mkdir -p ./lib
		mv $(LIB_NAME) ./lib

clean:  lib_clean example_clean src_clean
		rm -f *.o *.core

src_clean:
		rm -rf ./src/*.o

lib_clean:
		rm -rf ./lib/$(LIB_NAME) ./lib/*.core

example_clean:
		rm -rf ./example/$(EXAMPLE_NAME)

distclean: clean
