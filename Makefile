.PHONY: all common-packages challenges challenge57 challenge58 challenge59

all: common-packages challenges

common-packages:
	go test -v -count=1 ./elliptic

challenges: challenge57 challenge58 challenge59

challenge57:
	go test -v -count=1 ./challenge57

challenge58:
	go test -v -count=1 ./challenge58

challenge59:
	go test -v -count=1 ./challenge59
