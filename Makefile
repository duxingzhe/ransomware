CXX=c++
CFLAGS=-O -Wall
AES_SRC=AES256/AES256.cpp AES256/AES256_Base.cpp AES256/AES256_PRNG.cpp AES256/S_Box.cpp

all: ransom

ransom: $(AES_SRC) ransom.cpp wipe.cpp
	$(CXX) $(CFLAGS) $^ -o $@

clean:
	-rm -rf ransom ransom.exe
