CC=clang++
FLAGS=-O2 -march=native -msse2 -Wall -std=c++11 
LIBS=
all:packetstats
packetstats:packetstats.cpp readpcap.c
	$(CC) packetstats.cpp -o packetstats $(FLAGS) $(LIBS)
clean:
	rm -f packetstats

