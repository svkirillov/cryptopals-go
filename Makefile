.PHONY: all common-packages challenges challenge57 challenge58 challenge59 challenge60

all: common-packages challenges

common-packages:
	go test -v -count=1 ./elliptic ./x128

challenges: challenge57 challenge58 challenge59 challenge60

challenge57:
	go test -v -count=1 ./challenge57

challenge58:
	go test -v -count=1 ./challenge58

challenge59:
	go test -v -count=1 ./challenge59

challenge60:
	go test -v -count=1 ./challenge60
