package challenge60

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"runtime"
	"sync"

	"github.com/svkirillov/cryptopals-go/elliptic"
	"github.com/svkirillov/cryptopals-go/helpers"
	"github.com/svkirillov/cryptopals-go/oracle"
	"github.com/svkirillov/cryptopals-go/x128"
)

type twistPoint struct {
	order *big.Int
	point *big.Int
}

type equation struct {
	reminder *big.Int
	module   *big.Int
}

// quadraticResidue calculates the v coordinate given the u.
// If u not on the curve then v = nil, otherwise v != nil.
func quadraticResidue(u *big.Int) (v *big.Int) {
	// v^2 = u^3 + A*u^2 + u
	// v = sqrt(u^3 + A*u^2 + u) mod P

	tmp := new(big.Int).Exp(u, helpers.BigTwo, x128.P)
	tmp.Mul(tmp, x128.A).Mod(tmp, x128.P)

	v = new(big.Int).Exp(u, helpers.BigThree, x128.P)
	v = v.Add(v, tmp).Mod(v, x128.P).Add(v, u).Mod(v, x128.P).ModSqrt(v, x128.P)

	return
}

// convertToWeierstrass converts a point on Montgomery curve to a point on
// Weierstrass curve.
func convertToWeierstrass(u *big.Int) (x, y *big.Int, err error) {
	v := quadraticResidue(u)
	if v == nil {
		return nil, nil, fmt.Errorf("%d does not represent a point on x128 curve", u)
	}

	p128 := elliptic.P128()

	// u = x - 178
	// v = y
	x = new(big.Int).SetUint64(178)
	x.Add(x, u)
	y = v

	if p128.IsOnCurve(x, y) {
		// y is already taken with a minus if the second operand is evaluated
		return x, y, nil
	}

	return nil, nil, fmt.Errorf("(%d, %d) is not a point on p128 curve", x, y)
}

// findTwistPoint returns a point on the twist with given order.
func findTwistPoint(twistOrder, order *big.Int) *big.Int {
	k := new(big.Int).Div(twistOrder, order).Bytes()

	for {
		// a. Choose a random u mod p and verify that u^3 + A*u^2 + u is a
		//    nonsquare in GF(p).
		u, err := rand.Int(rand.Reader, x128.P)
		if err != nil {
			panic(err)
		}

		// if v == nil then we are on the twist
		if v := quadraticResidue(u); v == nil {
			// b. Call the order of the twist n. To find an element of order q,
			//    calculate ladder(u, n/q).
			point := x128.ScalarMult(u, k)
			if point.Cmp(helpers.BigZero) != 0 {
				return point
			}
		}
	}
}

// findAllTwistPoints finds all points on twist curves.
func findAllTwistPoints() (twistOrder *big.Int, points []twistPoint) {
	// 1. Calculate the order of the twist and find its small factors. This
	//    one should have a bunch under 2^24.
	// It is known, that both curves contain 2*p+2 points: |E| + |T| = 2*p + 2
	// Then order of the twist is equal to 2*p + 2 - q, q = x128.N
	amountOfCurvePoints := new(big.Int)
	amountOfCurvePoints.Mul(helpers.BigTwo, x128.P).Add(amountOfCurvePoints, helpers.BigTwo)
	twistOrder = new(big.Int).Sub(amountOfCurvePoints, x128.N)

	factors := helpers.Factorize(twistOrder, new(big.Int).SetUint64(1<<24))
	if len(factors) != 0 && factors[0].Cmp(helpers.BigTwo) == 0 {
		factors = factors[1:]
	}

	// 2. Find points with those orders.
	for _, order := range factors {
		u := findTwistPoint(twistOrder, order)
		points = append(points, twistPoint{
			order: order,
			point: u,
		})
	}

	return
}

// f maps group elements to scalars.
// See tasks/challenge58.txt:24 and tasks/challenge58.txt:94 for details.
func f(y, k, p *big.Int) *big.Int {
	// f = 2^(y mod k) mod p
	return new(big.Int).Exp(helpers.BigTwo, new(big.Int).Mod(y, k), p)
}

// calcK calculates k based on a formula in this paper: https://arxiv.org/pdf/0812.0789.pdf
func calcK(a, b *big.Int) *big.Int {
	// k = log2(sqrt(b-a)) + log2(log2(sqrt(b-a))) - 2
	sqrtba := math.Sqrt(float64(new(big.Int).Sub(b, a).Uint64()))
	logSqrt := math.Log2(sqrtba)
	logLogSqrt := math.Log2(logSqrt)
	return new(big.Int).SetUint64(uint64(logSqrt + logLogSqrt - 2))
}

// calcN calculates amount of leaps for tame kangaroo.
func calcN(p, k *big.Int) *big.Int {
	N := new(big.Int).Set(helpers.BigZero)

	for i := new(big.Int).Set(helpers.BigZero); i.Cmp(k) < 0; i.Add(i, helpers.BigOne) {
		N.Add(N, f(i, k, p))
	}

	// N = N/k * 4
	// see for details: tasks/challenge58.txt:99
	tmp := new(big.Int).Rsh(k, 2)
	if tmp.Cmp(helpers.BigZero) == 0 {
		N.Div(N, k).Mul(N, tmp.SetUint64(4))
	} else {
		N.Div(N, tmp)
	}

	return N
}

// tameKangaroo returns distance traveled by tame kangaroo and where he
// ended up.
func tameKangaroo(curve elliptic.Curve, bx, by, b, k, N *big.Int) (xT *big.Int, xyT *big.Int, yyT *big.Int) {
	curveN := curve.Params().N

	// xT := 0
	// xyT, yyT := b * base
	xT = new(big.Int).Set(helpers.BigZero)
	xyT, yyT = curve.ScalarMult(bx, by, b.Bytes())

	// for i in 1..N:
	for i := new(big.Int).Set(helpers.BigZero); i.Cmp(N) < 0; i.Add(i, helpers.BigOne) {
		fVal := f(xyT, k, curveN)

		// xT := xT + f(xyT)
		xT.Add(xT, fVal)

		// xyT, yyT := (xyT, yyT) + (base * f(xyT))
		tmpX, tmpY := curve.ScalarMult(bx, by, fVal.Bytes())
		xyT, yyT = curve.Add(xyT, yyT, tmpX, tmpY)
	}

	return
}

// catchingWildKangaroo implements Pollard's method for catching kangaroos.
func catchingWildKangaroo(ctx context.Context, curve elliptic.Curve, bx, by, x, y, xT, xyT, yyT, k, a, b *big.Int) *big.Int {
	curveN := curve.Params().N

	// xW := 0
	// xyW, yyW := x, y
	xW := new(big.Int).Set(helpers.BigZero)
	xyW := new(big.Int).Set(x)
	yyW := new(big.Int).Set(y)

	tmp := new(big.Int)

	tmp.Sub(b, a).Add(tmp, xT)
	xWUpperBound := new(big.Int).Set(tmp) // xWUpperBound := b - a + xT

	// while xW < b - a + xT:
	for xW.Cmp(xWUpperBound) < 0 {
		fVal := f(xyW, k, curveN)

		// xW := xW + f(xyW)
		xW.Add(xW, fVal)

		// xyW, yyW := (xyW, yyW) + (base * f(xyW))
		tmpX, tmpY := curve.ScalarMult(bx, by, fVal.Bytes())
		xyW, yyW = curve.Add(xyW, yyW, tmpX, tmpY)

		// if yW = yT:
		if xyW.Cmp(xyT) == 0 && yyW.Cmp(yyT) == 0 {
			// b + xT - xW
			tmp.Add(b, xT).Sub(tmp, xW)
			fmt.Printf("Wild Kangaroo: xW = %d, xyW = %d, yyW = %d, (b + xT - xW) = %d\n", xW, xyW, yyW, tmp)
			return tmp
		}

		select {
		case <-ctx.Done():
			return nil
		default:
			// pass
		}
	}

	return nil
}

// ecdh performs DH on x128 curve with given public and private keys
func ecdh(publicKey *big.Int, privateKey []byte) []byte {
	ss := x128.ScalarMult(publicKey, privateKey)
	return oracle.MAC(ss.Bytes())
}

// checkDuplicate returns true if no duplicates were found
func checkDuplicate(reminders []*big.Int, modules []*big.Int, r *big.Int, m *big.Int) bool {
	if len(reminders) != len(modules) {
		panic("checkDuplicate: len(reminders) != len(modules)")
	}

	ok := true

	for i := 0; i < len(reminders); i++ {
		if reminders[i].Cmp(m) == 0 || modules[i].Cmp(r) == 0 {
			ok = false
			break
		}
	}

	return ok
}

// getRemaindersOfPrivateKey returns a set of equations of the form b = k mod p where
// b is privateKey, k is remainder of private key by modulo p
func getRemaindersOfPrivateKey(
	oracleECDH func(x *big.Int) []byte,
	points []twistPoint,
) (remainders []*big.Int, modules []*big.Int) {
	bruteFunc := func(
		ctx context.Context,
		ss []byte,
		point, order *big.Int,
		bruteFrom, bruteTo *big.Int,
		answer chan equation,
		wg *sync.WaitGroup,
	) {
		defer wg.Done()
		for k := bruteFrom; k.Cmp(bruteTo) < 0; k.Add(k, helpers.BigOne) {
			ss1 := ecdh(point, k.Bytes())
			if hmac.Equal(ss, ss1) {
				answer <- equation{
					reminder: k,
					module:   order,
				}
				return
			}

			select {
			case <-ctx.Done():
				return
			default:
				// pass
			}
		}
	}

	var wg sync.WaitGroup

	nWorkers := runtime.NumCPU()
	fmt.Println("Number of used threads =", nWorkers)

	step := new(big.Int)
	tailFrom := new(big.Int)
	border := new(big.Int)

	for _, point := range points {
		answer := make(chan equation, nWorkers)

		// step := point.order / (nWorkers - 1)
		step.SetUint64(uint64(nWorkers-1)).Div(point.order, step)

		// tailFrom := step * (nWorkers - 1)
		tailFrom.SetUint64(uint64(nWorkers-1)).Mul(tailFrom, step)

		ss := oracleECDH(point.point)

		ctx, cancel := context.WithCancel(context.Background())

		border.Set(helpers.BigZero)
		for ; border.Cmp(tailFrom) < 0; border.Add(border, step) {
			wg.Add(1)
			go bruteFunc(
				ctx, ss,
				point.point, point.order,
				new(big.Int).Set(border),
				new(big.Int).Add(border, step),
				answer,
				&wg,
			)
		}
		wg.Add(1)
		go bruteFunc(
			ctx, ss,
			point.point, point.order,
			new(big.Int).Set(tailFrom),
			new(big.Int).Add(point.order, helpers.BigOne),
			answer,
			&wg,
		)

		select {
		case e := <-answer:
			if checkDuplicate(remainders, modules, e.reminder, e.module) {
				remainders = append(remainders, e.reminder)
				modules = append(modules, e.module)

				cancel()
				break
			}
		}

		cancel()

		wg.Wait()
		close(answer)
	}

	return
}

// getCandidatesForPrivateKey returns a set of possible private keys by modulo r
func getCandidatesForPrivateKey(
	oracleECDH func(x *big.Int) []byte,
	twistOrder *big.Int,
	remainders []*big.Int,
	modules []*big.Int,
) (candidates []*big.Int, r *big.Int, err error) {
	r = new(big.Int).Set(helpers.BigOne)
	for _, module := range modules {
		r.Mul(r, module)
	}

	g := findTwistPoint(twistOrder, r)
	ss := oracleECDH(g)

	tmpReminders := make([]*big.Int, len(remainders))
	l := len(modules)
	pow := 1 << l

	for i := 0; i < pow; i++ {
		for j := 0; j < l; j++ {
			if (i>>j)&1 == 1 {
				tmpReminders[j] = new(big.Int).Sub(modules[j], remainders[j])
			} else {
				tmpReminders[j] = new(big.Int).Set(remainders[j])
			}
		}

		possibleKey, _, err := helpers.ChineseRemainderTheorem(tmpReminders, modules)
		if err != nil {
			return nil, nil, fmt.Errorf("chinese remainder theorem: %s", err.Error())
		}

		ss1 := ecdh(g, possibleKey.Bytes())
		if hmac.Equal(ss, ss1) {
			candidates = append(candidates, possibleKey)
		}
	}

	return candidates, r, nil
}

func InsecureTwistsAttack(
	oracleECDH func(x *big.Int) []byte,
	getPublicKey func() *big.Int,
	privateKeyOracle func(*big.Int) *big.Int,
) (privateKey *big.Int, err error) {
	twistOrder, points := findAllTwistPoints()
	remainders, modules := getRemaindersOfPrivateKey(oracleECDH, points)
	candidates, r, err := getCandidatesForPrivateKey(oracleECDH, twistOrder, remainders, modules)
	if err != nil {
		return nil, err
	}

	fmt.Println("remainders:", remainders)
	fmt.Println("modules:", modules)
	fmt.Println("Candidates for private key:", candidates)
	fmt.Println("r =", r)

	realPrivateKey := privateKeyOracle(r)
	fmt.Printf("Real private key x = n mod r: x %% %d = %d\n", r, realPrivateKey)

	p128 := elliptic.P128()

	// convert public key from montgomery form to weierstrass
	x128PublicKey := getPublicKey()
	pkP128x, pkP128y, err := convertToWeierstrass(x128PublicKey)
	if err != nil {
		return nil, fmt.Errorf("convert montgomery public key point to weierstrass form: %s", err.Error())
	}

	// g' = g^r
	newBaseX, newBaseY := p128.ScalarBaseMult(r.Bytes())

	// [a, b] = [0, (q-1)/r]
	a := helpers.BigZero
	b := new(big.Int).Sub(p128.Params().N, helpers.BigOne)
	b.Div(b, r)

	// calculate k and n parameters for catching wild kangaroo attack
	k := calcK(a, b)
	N := calcN(p128.Params().N, k)

	fmt.Println("k =", k)
	fmt.Println("N =", N)

	// run tame kangaroo
	xT, xyT, yyT := tameKangaroo(p128, newBaseX, newBaseY, b, k, N)
	fmt.Printf("Tame Kangaroo: xT = %d, xyT = %d, yyT = %d\n", xT, xyT, yyT)

	ch := make(chan *big.Int, len(candidates))

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// check candidates
	for _, candidate := range candidates {
		wg.Add(1)
		go func(n *big.Int) {
			defer wg.Done()

			// y' = y * g^-n
			newX, newY := p128.ScalarBaseMult(n.Bytes())
			newX, newY = elliptic.Inverse(p128, newX, newY)
			newX, newY = p128.Add(newX, newY, pkP128x, pkP128y)

			m := catchingWildKangaroo(ctx, p128, newBaseX, newBaseY, newX, newY, xT, xyT, yyT, k, a, b)
			if m == nil {
				ch <- nil
				return
			}

			cancel()

			x := new(big.Int).Mul(m, r)
			x.Add(x, n)

			ch <- x
		}(candidate)
	}

	wg.Wait()

	for len(ch) > 0 {
		if privateKey = <-ch; privateKey != nil {
			close(ch)
			return privateKey, nil
		}
	}

	close(ch)

	return nil, nil
}
