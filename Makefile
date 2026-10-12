# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 heydemoura
PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk

ifeq ($(HOST),1)
CC := cc
CFLAGS += -DHOST_BUILD
else
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
LDADD += -lSceHttp -lSceSsl -lSceSystemService -lSceAppInstUtil
endif

TARGET := ps5-localsend.elf
SOURCES := src/main.c src/assets.c src/json.c src/sha256.c src/sender.c
ifneq ($(HOST),1)
SOURCES += src/sce_http.c src/launcher.c
endif
CFLAGS += -std=c11 -O2 -Wall -Wextra -Werror -D_DEFAULT_SOURCE -Isrc

.PHONY: all clean test
all: $(TARGET)

src/webui.inc: assets/webui.html tools/embed_webui.py
	python3 tools/embed_webui.py

$(TARGET): $(SOURCES) src/webui.inc assets/icon0.png
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDADD)

clean:
	rm -f $(TARGET)

test:
	$(MAKE) HOST=1 clean all
	python3 -m unittest discover -s tests -v
