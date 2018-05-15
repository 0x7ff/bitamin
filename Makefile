CC ?= clang
OPTFLAGS ?= -DNDEBUG -O3 -march=native
DBGFLAGS ?= -g
CFLAGS ?= -Wall -Wextra -pedantic -std=c99 -DRAND_BLOCK

.PHONY: all
all:
	$(CC) $(CFLAGS) $(OPTFLAGS) bitamin.c -o bitamin

.PHONY: debug
debug:
	$(CC) $(CFLAGS) $(DBGFLAGS) bitamin.c -o bitamin

.PHONY: clean
clean:
	$(RM) bitamin
