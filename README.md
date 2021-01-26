# cryptopals-go

## Challenge 57

Terms of challenge: [challenge57.txt](docs/challenge57.txt)

Run all tests for challenge 57:

```sh
make challenge57
```

## Challenge 58

Terms of challenge: [challenge58.txt](docs/challenge58.txt)

Run all tests for challenge 58:

```sh
make challenge58
```

Run a test for Pollard's Method for Catching Kangaroos Algorithm:

```sh
go test -v -count=1 ./challenge58 -run TestCatchWildKangaroo
```

Run a test for Catching Kangaroos Attack:

```sh
go test -v -count=1 ./challenge58 -run TestCatchingKangaroosAttack
```

## Challenge 59

Terms of challenge: [challenge59.txt](docs/challenge59.txt)

Run all tests for challenge 59:

```sh
make challenge59
```

## Challenge 60

Terms of challenge: [challenge60.txt](docs/challenge60.txt)

Run all tests for challenge 60:

```sh
make challenge60
```

Run a test for Pollard's Method for Catching Kangaroos Algorithm on an elliptic curve:

```sh
go test -v -count=1 ./challenge60 -run TestECKangarooAlgorithm
```

Run a test for Insecure Twist Attack:

```sh
go test -v -count=1 ./challenge60 -run TestInsecureTwistAttack
```
