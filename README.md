# cryptopals-go

## Challenge 58

Terms of challenge: [challenge58.txt](./tasks/challenge58.txt)

Run test for Pollard's Method for Catching Kangaroos Algorithm:

```sh
go test -v -count=1 ./challenge58 -run TestCatchWildKangaroo
```


Run quick test for Catching Kangaroos Attack:

```sh
go test -v -count=1 ./challenge58 -run TestCatchingKangaroosAttackFast
```

Run slow test for Catching Kangaroos Attack:

```sh
go test -v -count=1 ./challenge58 -run TestCatchingKangaroosAttackSlow
```
