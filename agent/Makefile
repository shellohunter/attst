CFLAGS += -Wall -g

exe := autotest-agent.exe
exeobjs := autotest-agent.o cache.o

all: $(exe)

$(exe) : $(exeobjs)
	$(CC) $(CFLAGS) -lpthread -llua -o $@ $^

$(exeobjs): %.o : %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

clean:
	-$(RM) -f *.o $(exe)
