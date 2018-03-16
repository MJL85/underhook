# Minimal Makefile
#
# By: Michael Laforest <paralizer -AT- users -DOT- sourceforge -DOT- net>
#
# $Header: /cvsroot/doommod/dmm/src/Makefile,v 1.2 2005/10/25 19:29:56 paralizer Exp $

#
# Change this to your GCC 3.3 version.
#
CC = gcc

####################################################
#
# You should not need to edit below this line.
#
####################################################

#
# Universal cflags
#
CFLAGS = -Wall -Wextra -pipe -m32

#
# Object flags
#
FLAGS = $(CFLAGS)

#
# Debug object flags
#
DFLAGS = $(CFLAGS) -g

#
# Linking flags
#
LDFLAGS = -ldl

#
# Target binaries (always created as BIN)
#
BIN = test
DBIN = test-bin

#
# Inclusion paths.
#
INCLUDES = -I. -I../src

#
# Find all source files.
#
SRC_FILES = $(wildcard *.c)

#
# Generate a list of object files
#
OBJS = $(SRC_FILES:%.c=%.o)

DOBJS = $(OBJS:%.o=d_%.o)

#
# Need this for the 'clean' target.
#
EXISTING_OBJS = $(wildcard *.o)


###############################
#
# Build targets.
#
###############################

release:
	@echo
	@echo ------
	@echo - Building UnderHook - Test API program ...
	@echo ------
	make $(BIN)
	
	@echo
	@echo --
	@echo -- Build complete.
	@echo --
	@echo

debug: $(DBIN)

#
# If they exist, remove the files:
#   *.o
#
clean:
	@if [ ! -z "$(EXISTING_OBJS)" ]; \
	then \
		rm *.o &> /dev/null ; \
		echo "Cleaned files."; \
	else \
		echo "No files to clean."; \
	fi

$(BIN): $(OBJS)
	$(CC) $(FLAGS) $(LDFLAGS) $(OBJS) -o $(BIN)

$(DBIN): $(DOBJS)
	$(CC) $(DFLAGS) $(LDFLAGS) $(DOBJS) -o $(BIN)

%.o: %.c
	$(CC) $(FLAGS) $(INCLUDES) -c $<

d_%.o: %.c
	$(CC) $(DFLAGS) $(INCLUDES) -c $< -o $@
