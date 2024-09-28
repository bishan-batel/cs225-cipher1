PRG=gnu.exe
GCC=gcc
GCCFLAGS=-O2 -Wall -Wextra -ansi -pedantic 
MSC=cl
MSCFLAGS=/EHa /W4 /Za /Zc:forScope /nologo /D_CRT_SECURE_NO_DEPRECATE /D"_SECURE_SCL 0" /O2i /GL

OBJECTS0=cipher.c
DRIVER0=driver.c

VALGRIND_OPTIONS=-q --leak-check=full

OSTYPE := $(shell uname)
ifeq (,$(findstring CYGWIN,$(OSTYPE)))
CYGWIN=
else
CYGWIN=-Wl,--enable-auto-import
endif

all: gcc0
gcc0:
	$(GCC) -o $(PRG) $(CYGWIN) $(DRIVER0) $(OBJECTS0) $(GCCFLAGS)
msc0:
	$(MSC) /Fe$@.exe           $(DRIVER0) $(OBJECTS0) $(MSCFLAGS)
0 1 2 3 4 5 6:
	@echo "running test$@"
	@echo "should run in less than 100 ms"
	./$(PRG) $@ >studentout$@
	@echo "lines after the next are mismatches with master output -- see out$@"
	diff out$@ studentout$@ --strip-trailing-cr
7:
	@echo "running test$@"
	@echo "should run in less than 1500 ms"
	./$(PRG) $@ >studentout$@
	@echo "lines after the next are mismatches with master output -- see out$@"
	diff out$@ studentout$@ --strip-trailing-cr
mem0 mem1 mem2 mem3 mem4 mem5 mem6 mem7 mem8 mem9 mem10 mem11:
	@echo "running memory test $@"
	@echo "should run in less than 1500 ms"
	valgrind $(VALGRIND_OPTIONS) ./$(PRG) $(subst mem,,$@) 1>/dev/null 2>difference$@
	@echo "lines after this are memory errors"; cat difference$@
clean:
	rm -f *.exe *.tds *.o *.obj *manifest* studentout* diff*
