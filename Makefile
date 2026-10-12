PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk

ifeq ($(HOST),1)
CC := cc
else
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
endif

TARGET := ps5-localsend.elf
SOURCES := src/main.c src/json.c src/sha256.c src/sender.c
CFLAGS += -std=c11 -O2 -Wall -Wextra -Werror -D_DEFAULT_SOURCE -Isrc

.PHONY: all clean test
all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES)

clean:
	rm -f $(TARGET)

test:
	$(MAKE) HOST=1 clean all
	python3 -m unittest discover -s tests -v
