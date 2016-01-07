APP = vhost_net_app 
C_SRCS = client.c main.c sh_mem.c util.c uvhost.c virt_queue.c


C_OBJS = ${C_SRCS:.c=.o}

program_OBJS = $(C_OBJS)


CFLAGS =  -std=gnu99 -lrt -lpcap -g #-Wc11-extensions -Wall -pedantic -pedantic-errors -g -lrt -D_POSIX_C_SOURCE=200112L 
 
.PHONY: all clean distclean 

all: $(APP)

$(APP): $(program_OBJS)
		$(CC) $(program_OBJS) -o $(APP) $(CFLAGS)


clean:
		rm -f *.o *.core $(APP)	

distclean: clean
