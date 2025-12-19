OS_NAME = $(shell uname)

CFLAGS=-I../src

ifeq ($(OS_NAME), Darwin)
# pip3 install PyInstaller, and make sure pyinstaller ends up in your PATH, e.g. by
# PATH=$PATH:$(pip3 show PyInstaller | grep Location: | sed -e 's/ *Location: *//' | sed -e 's|/lib/python.*|/bin|')
CONVERSE=dist/Converse.app
else
CONVERSE=
endif

all:	hostat finger $(CONVERSE)


hostat: hostat.c ../src/cbridge-chaos.h
	$(CC) $(CFLAGS) -o $@ $<

finger: finger.c ../src/cbridge-chaos.h
	$(CC) $(CFLAGS) -o $@ $<

ifeq ($(OS_NAME), Darwin)
dist/Converse.app: converse.py qsend.py chaosnet.py Converse-icon.icns
	pyinstaller --noconfirm --windowed --name Converse --icon Converse-icon.icns converse.py
endif

clean:
	rm -f hostat finger
	rm -rf dist/Converse dist/Converse.app build/Converse
