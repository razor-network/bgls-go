package dkg

import (
	"crypto/rand"
	"math/big"
	"testing"

	. "github.com/orbs-network/bgls/bgls"
	. "github.com/orbs-network/bgls/curves"
	"github.com/stretchr/testify/assert"
)

var curves = []CurveSystem{Altbn128}
var threshold = 14
var n = 22

func TestDKGHappyFlow(t *testing.T) {
	for _, curve := range curves {

		// == Commit phase ==
		skEncAll := make([]*big.Int, n)
		pkEncAll := make([]Point, n)

		// Generate sks and pks for all participants for encryption/decryption purposes
		for participant := 0; participant < n; participant++ {
			skEncAll[participant], pkEncAll[participant], _, _ = CoefficientGen(curve)
		}

		coefsAll := make([][]*big.Int, n)
		commitG1All := make([][]Point, n)
		commitG2All := make([][]Point, n)
		commitPrvAll := make([][]*big.Int, n)    // private commit of participant to all
		commitPrvAllEnc := make([][]*big.Int, n) // encrypted version of the above

		// Generate coefficients and public commitments for each participant
		for participant := 0; participant < n; participant++ {

			coefs := make([]*big.Int, threshold+1)
			commitG1 := make([]Point, threshold+1)
			commitG2 := make([]Point, threshold+1)
			commitPrv := make([]*big.Int, n)
			commitPrvEnc := make([]*big.Int, n)

			for i := 0; i < threshold+1; i++ {
				var err error
				coefs[i], commitG1[i], commitG2[i], err = CoefficientGen(curve)
				assert.Nil(t, err, "test data generation failed")
				assert.True(t, VerifyPublicCommitment(curve, commitG1[i], commitG2[i]), "commit G1 and G2 fail")
			}

			sk := skEncAll[participant]
			j := big.NewInt(1)
			for i := 0; i < n; i++ {
				commitPrv[i] = GetPrivateCommitment(curve, j, coefs)
				if i != participant { // skip own commitments
					commitPrvEnc[i] = Encrypt(curve, sk, pkEncAll[i], big.NewInt(0).Set(commitPrv[i]))
				}
				j.Add(j, big.NewInt(1))
			}

			coefsAll[participant] = coefs
			commitG1All[participant] = commitG1
			commitG2All[participant] = commitG2
			commitPrvAll[participant] = commitPrv
			commitPrvAllEnc[participant] = commitPrvEnc
		}

		// == Verify phase ==

		commitPrvAllDec := make([][]*big.Int, n)
		// First decrypt
		for committedParticipant := 0; committedParticipant < n; committedParticipant++ {
			pk := pkEncAll[committedParticipant]
			commitPrvDec := make([]*big.Int, n)
			for participant := 0; participant < n; participant++ {
				if committedParticipant != participant {
					sk := skEncAll[participant]
					enc := big.NewInt(0).Set(commitPrvAllEnc[committedParticipant][participant])
					commitPrvDec[participant] =
						Decrypt(curve, sk, pk, enc)
					assert.True(t,
						commitPrvDec[participant].Cmp(commitPrvAll[committedParticipant][participant]) == 0,
						"commitment is not the same after decryption")
				} else {
					commitPrvDec[participant] = commitPrvAll[committedParticipant][participant] // personal data
				}
			}
			commitPrvAllDec[committedParticipant] = commitPrvDec
		}

		j := big.NewInt(1)
		for participant := 0; participant < n; participant++ {
			for commitParticipant := 0; commitParticipant < n; commitParticipant++ {
				if participant != commitParticipant {
					prv := commitPrvAllDec[commitParticipant][participant]
					pub := commitG1All[commitParticipant]
					assert.True(t, VerifyPrivateCommitment(curve, j, prv, pub), "private commit doesnt match public commit")
				}
			}
			j.Add(j, big.NewInt(1))
		}

		// END OF DKG

		// == Calculate SK, Pks and group PK ==
		skAll := make([]*big.Int, n)
		pkAll := make([][]Point, n)
		pubCommitG2Zero := make([]Point, n)
		for participant := 0; participant < n; participant++ {
			pkAll[participant] = GetAllPublicKey(curve, threshold, commitG2All)
			pubCommitG2Zero[participant] = commitG2All[participant][0]
			prvCommit := make([]*big.Int, n)
			for commitParticipant := 0; commitParticipant < n; commitParticipant++ {
				prvCommit[commitParticipant] = commitPrvAllDec[commitParticipant][participant]
			}
			skAll[participant] = GetSecretKey(prvCommit)
		}

		//Verify pkAll are the same for all
		for participant := 0; participant < n; participant++ {
			pks := pkAll[participant]
			for otherParticipant := 0; otherParticipant < n; otherParticipant++ {
				assert.True(t, pks[participant].Equals(pkAll[otherParticipant][participant]),
					"pk for the same participant is different among other paricipants")
			}
		}

		groupPk := GetGroupPublicKey(curve, pubCommitG2Zero)
		//Verify the secret key matches the public key
		coefsZero := make([]*big.Int, n)
		for participant := 0; participant < n; participant++ {
			coefsZero[participant] = coefsAll[participant][0]
		}
		groupSk := GetPrivateCommitment(curve, big.NewInt(1), coefsZero)
		assert.True(t, groupPk.Equals(LoadPublicKey(curve, groupSk)),
			"groupPK doesnt match to groupSK")

		// == Sign and reconstruct ==
		d := make([]byte, 64)
		var err error
		_, err = rand.Read(d)
		assert.Nil(t, err, "msg data generation failed")
		sigs := make([]Point, n)
		for participant := 0; participant < n; participant++ {
			sigs[participant] = Sign(curve, skAll[participant], d)
			assert.True(t, VerifySingleSignature(curve, sigs[participant], pkAll[0][participant], d),
				"signature invalid")
		}

		indices := make([]*big.Int, n)
		index := big.NewInt(0)
		for participant := 0; participant < n; participant++ {
			index.Add(index, big.NewInt(1))
			indices[participant] = big.NewInt(0).Set(index)
		}

		groupSig1, err := SignatureReconstruction(
			curve, sigs[:threshold+1], indices[:threshold+1])
		assert.Nil(t, err, "group signature reconstruction fail")
		assert.True(t, VerifySingleSignature(curve, groupSig1, groupPk, d),
			"group signature invalid")

		groupSig2, err := SignatureReconstruction(
			curve, sigs[n-(threshold+1):], indices[n-(threshold+1):])
		assert.Nil(t, err, "group signature reconstruction fail")
		assert.True(t, VerifySingleSignature(curve, groupSig2, groupPk, d),
			"group signature invalid")
		assert.True(t, groupSig1.Equals(groupSig2), "group signatures are not equal")

		// TODO add all possible groups
	}
}

func TestEncryptionDecryption(t *testing.T) {
	for _, curve := range curves {

		skEnc, pkEnc, _, _ := CoefficientGen(curve)
		skDec, pkDec, _, _ := CoefficientGen(curve)
		// skEnc := big.NewInt(9163450)
		// skDec := big.NewInt(197435619)
		// pkEnc := LoadPublicKeyG1(curve, skEnc)
		// pkDec := LoadPublicKeyG1(curve, skDec)
		// fmt.Printf("pkEnc x:  %v\n", pkEnc.ToAffineCoords()[0])
		// fmt.Printf("pkEnc y:  %v\n", pkEnc.ToAffineCoords()[1])
		// fmt.Printf("pkEnc x:  %v\n", pkEnc.ToAffineCoords()[0].Text(16))
		// fmt.Printf("pkEnc y:  %v\n", pkEnc.ToAffineCoords()[1].Text(16))
		// fmt.Printf("pkDec x:  %v\n", pkDec.ToAffineCoords()[0])
		// fmt.Printf("pkDec y:  %v\n", pkDec.ToAffineCoords()[1])
		// fmt.Printf("pkDec x:  %v\n", pkDec.ToAffineCoords()[0].Text(16))
		// fmt.Printf("pkDec y:  %v\n", pkDec.ToAffineCoords()[1].Text(16))
		// coef := big.NewInt(102280324260302)
		// coef, _ := big.NewInt(0).SetString("1430352996282437468369", 10)
		coef, _ := rand.Int(rand.Reader, curve.GetG1Order())
		enc := Encrypt(curve, skEnc, pkDec, coef)
		// fmt.Printf("Enc data:  %v\n", enc.Text(16))
		dec := Decrypt(curve, skDec, pkEnc, enc)
		assert.True(t, dec.Cmp(coef) == 0, "decryption did not return the same encrypted data")
	}
}
