# Minimal Makefile
#
# By: Michael Laforest <paralizer -AT- users -DOT- sourceforge -DOT- net>
#
# This Makefile will invoke the Makefile in
# the src/ subdirectory.
#
# $Header$

Release:
	cd src/ && $(MAKE) release
	@mv src/uhook.so . &> /dev/null

debug:
	cd src/ && $(MAKE) debug
	@mv src/uhook.so . &> /dev/null

clean:
	cd src/ && $(MAKE) clean


