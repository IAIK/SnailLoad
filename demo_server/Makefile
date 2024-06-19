CFLAGS=-O3 -Wall -Wextra -pthread
LDFLAGS=-static -pthread

TARGETS=demo_server

.PHONY: all
all: $(TARGETS)

.PHONY: clean
clean:
	rm -f $(TARGETS) *.o

demo_server: demo_server.o
demo_server.o: demo_server.c snailload.h
