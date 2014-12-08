#CROSS_COMPILE = /opt/arm-2013.05/bin/arm-none-linux-gnueabi-
CC = $(CROSS_COMPILE)gcc
CFLAGS = -O2 -g -Wall

TARGET = owl355eepromparser
OBJS = main.o 
DEPLOY_DIR = /tftpboot

DEPS := $(OBJS:.o=.d)

all: $(TARGET)

-include $(DEPS)

%.o: %.c
	$(CC) -c -MD $(CFLAGS) -o $@ $< 

$(TARGET): $(OBJS)
	$(CC) $^ $(CFLAGS) -o $(TARGET)

install: $(TARGET)
	@[ -d $(DEPLOY_DIR) ] || mkdir -p $(DEPLOY_DIR)
	@cp -f $(TARGET) $(DEPLOY_DIR)/

clean:
	rm -f *.o *.d $(TARGET) cscope.out

tags:
	@find . -name '*.[ch]' > cscope.list && cscope -b && rm -f cscope.list

.PHONY: clean tags
