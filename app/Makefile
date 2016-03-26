
.PHONY : all clean

all: bindshell wukong

OBJS= bindshell.o wukong.o

CFLAGS+= -O2 -Wall -Wno-unused-result

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

bindshell: bindshell.o
	$(CC) $< -o $@

wukong: wukong.o
	$(CC) $< -o $@
	
	
clean:
	-$(RM) $(OBJS) bindshell wukong
