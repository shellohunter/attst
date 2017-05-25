CFLAGS += -Wall -Werror -g

exe := autotest-agent.exe
exeobjs := agent.o cache.o usock.o log.o common.o

all: $(exe)

$(exe) : $(exeobjs)
	$(CC) $(CFLAGS) -lpthread -llua -lcrypto -lssl -o $@ $^

$(exeobjs): %.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-$(RM) -f *.o $(exe)
