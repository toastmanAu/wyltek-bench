CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -I/usr/include
LDFLAGS = -lssl -lcrypto -lsodium -lsecp256k1 -lm
TARGET  = wyltek-bench

all: $(TARGET)

$(TARGET): src/bench.c
	$(CC) $(CFLAGS) -o $(TARGET) src/bench.c $(LDFLAGS)

static: src/bench.c
	$(CC) $(CFLAGS) -static -o $(TARGET)-static src/bench.c $(LDFLAGS) -lpthread

clean:
	rm -f $(TARGET) $(TARGET)-static

test: $(TARGET)
	./$(TARGET) --quick --verbose

.PHONY: all static clean test
