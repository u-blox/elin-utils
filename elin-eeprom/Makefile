CC ?= $(CROSS_COMPILE)gcc
CFLAGS += -DVERSION=\"$(GIT_VERSION)\"
TARGET = elin-eeprom
OBJS = main.o

GIT_VERSION := $(shell git describe --abbrev=4 --dirty --always --tags)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $^ $(CFLAGS) -o $(TARGET)

clean:
	rm -f *.o $(TARGET)

.PHONY: clean
