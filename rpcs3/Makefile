# The RPCS3 installers, for the release: Linux's and macOS's .sh and Windows' .bat in build/, each
# carrying the PS3 app's modules (make_installers.py, from install.sh and install.ps1).
#   make          builds the PS3 app (make app in ../ps3, which takes DEBUG= and DOCKER= as there),
#                 then the installers from its staged files
#   make clean    removes build/

all:
	$(MAKE) -C ../ps3 app
	python3 make_installers.py

clean:
	rm -rf build

.PHONY: all clean
