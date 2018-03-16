# Minimal Makefile
#
# By: Michael Laforest <paralizer -AT- users -DOT- sourceforge -DOT- net>
#
# $Header$

#
# Change this to your GCC version.
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
CFLAGS = -Wall -pipe -m32

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
LDFLAGS = -shared

#
# Target binaries (always created as BIN)
#
BIN = uhook.so
DBIN = uhook-bin.so

#
# Inclusion paths.
#
#INCLUDES = -I. -I../include
INCLUDES = -I.

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
	@echo - Building UnderHook ...
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
