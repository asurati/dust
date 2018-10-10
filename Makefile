#
# Copyright (c) 2018 Amol Surati
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

CC  := gcc
BIN := dust

CFLAGS := -c -I ./include -MMD -MP
CFLAGS += -Wall -Wextra -Werror -Wshadow -Wfatal-errors -Wpedantic -pedantic-errors
CFLAGS += -flto
CFLAGS += -fstack-protector-strong
#CFLAGS += -g -O3 -D_FORTIFY_SOURCE=2
CFLAGS += -g -O0

LDFLAGS := -flto

CSRC := $(wildcard *.c)
DEP := $(CSRC:.c=.d)
OBJ := $(CSRC:.c=.o)

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

-include $(DEP)

c:
	rm -f $(BIN) $(OBJ) $(DEP)
r:
	@./$(BIN)

.PHONY: all c r
