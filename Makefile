CC=clang++
FLAGS=-O2 -march=native -msse2 -Wall
LIBS=-lpcap
all:packetstats
packetstats:packetstats.cpp
	$(CC) packetstats.cpp -o packetstats $(FLAGS) $(LIBS)
clean:
	rm -f packetstats

