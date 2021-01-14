# cryptopals-go

## Challenge 58

Terms of challenge: [challenge58.txt](./tasks/challenge58.txt)

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
