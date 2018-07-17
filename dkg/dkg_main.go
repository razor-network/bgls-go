package dkg

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"strings"

	"github.com/orbs-network/bgls/bgls"
	. "github.com/orbs-network/bgls/curves"
)

// Usage examples:
// ./dkgmain -func=cgen

var cmd string

const POINT_ELEMENTS = 4
const BIGINT_BASE = 16
const INTERNAL_DATA_FILE = "internal.json"

type DataForCommit struct {
	CoefficientsAll [][]*big.Int
	PubCommitG1All  [][]Point
	PubCommitG2All  [][]Point
	PrvCommitAll    [][]*big.Int
}

type JsonDataForCommit struct {
	CoefficientsAll [][]string
	PubCommitG1All  [][][]string
	PubCommitG2All  [][][]string
	PrvCommitAll    [][]string
}

//func (data *DataForCommit) MarshalJSON() ([]byte, error) {
//
//}

// Conversions between array of numbers and G1/G2 points:
//func (g1Point *altbn128Point1) ToAffineCoords() []*big.Int
// func (g1Point *altbn128Point2) ToAffineCoords() []*big.Int
// func (curve *altbn128) MakeG2Point(coords []*big.Int, check bool) (Point, bool)

func getPubCommitG1() {

}
func getPubCommitG2() {

}
func getPrCommit() {

}

func GetCommitDataForAllParticipants(curve CurveSystem, threshold int, n int) (*DataForCommit, error) {

	fmt.Printf("GetCommitDataForAllParticipants() called with threshold=%v n=%v\n", n, threshold)

	allData := new(DataForCommit)
	allData.CoefficientsAll = make([][]*big.Int, n)
	allData.PubCommitG1All = make([][]Point, n)
	allData.PubCommitG2All = make([][]Point, n)
	allData.PrvCommitAll = make([][]*big.Int, n)

	//coefsAll := make([][]*big.Int, n)
	//commitG1All := make([][]Point, n)
	//commitG2All := make([][]Point, n)
	//commitPrvAll := make([][]*big.Int, n) // private commit of participant to all
	// Generate coefficients and public commitments for each participant
	for participant := 0; participant < n; participant++ {

		coefs := make([]*big.Int, threshold+1)
		commitG1 := make([]Point, threshold+1)
		commitG2 := make([]Point, threshold+1)
		commitPrv := make([]*big.Int, n)
		for i := 0; i < threshold+1; i++ {
			var err error
			coefs[i], commitG1[i], commitG2[i], err = CoefficientGen(curve)
			if err != nil {
				return allData, err
			}
			verifyResult := VerifyPublicCommitment(curve, commitG1[i], commitG2[i])
			fmt.Printf("VerifyPublicCommitment() (p=%v i=%v) passed? %v\n", participant, i, verifyResult)
		}

		j := big.NewInt(1)
		for i := 0; i < n; i++ {
			commitPrv[i] = GetPrivateCommitment(curve, j, coefs)
			j.Add(j, big.NewInt(1))
		}
		allData.CoefficientsAll[participant] = coefs
		allData.PubCommitG1All[participant] = commitG1
		allData.PubCommitG2All[participant] = commitG2
		allData.PrvCommitAll[participant] = commitPrv
	}

	return allData, nil
}

// This is for the Complaint flow only - don't call it for now
func VerifyPrvCommitment(curve CurveSystem, threshold int, n int, data *DataForCommit) (bool, error) {

	// == Verify phase ==

	j := big.NewInt(1)
	for participant := 0; participant < n; participant++ {
		for commitParticipant := 0; commitParticipant < n; commitParticipant++ {
			prv := data.PrvCommitAll[commitParticipant][participant]
			pub := data.PubCommitG1All[commitParticipant]
			if res := VerifyPrivateCommitment(curve, j, prv, pub); !res {
				return false, fmt.Errorf("private commit doesn't match public commit")
			}
		}
		j.Add(j, big.NewInt(1))
	}

	return true, nil

}

func SignAndVerify(curve CurveSystem, threshold int, n int, data *DataForCommit) (bool, error) {

	// == Calculate SK, Pks and group PK ==
	// TODO Should be happen only once, after DKG flow is done, and not for every SignAndVerify()

	skAll := make([]*big.Int, n)
	pkAll := make([][]Point, n)
	pubCommitG2Zero := make([]Point, n)
	for participant := 0; participant < n; participant++ {
		pkAll[participant] = GetAllPublicKey(curve, threshold, data.PubCommitG2All)
		pubCommitG2Zero[participant] = data.PubCommitG2All[participant][0]
		prvCommit := make([]*big.Int, n)
		for commitParticipant := 0; commitParticipant < n; commitParticipant++ {
			prvCommit[commitParticipant] = data.PrvCommitAll[commitParticipant][participant]
		}
		skAll[participant] = GetSecretKey(prvCommit)
	}

	//pkOk := true

	////Verify pkAll are the same for all
	//for participant := 0; participant < n; participant++ {
	//pks := pkAll[participant]
	//for otherParticipant := 0; otherParticipant < n; otherParticipant++ {
	//  if pks[participant] != pkAll[otherParticipant][participant] {
	//	pkOk = false
	//	fmt.Println("pk for the same participant is different among other participants")
	//  }
	//}
	//}
	//
	//if !pkOk {
	//return false, fmt.Errorf("failed PK verification")
	//}
	//
	groupPk := GetGroupPublicKey(curve, pubCommitG2Zero)
	//Verify the secret key matches the public key

	//coefsZero := make([]*big.Int, n)
	//for participant := 0; participant < n; participant++ {
	//coefsZero[participant] = data.CoefficientsAll[participant][0]
	//}

	//groupSk := bglswrapper.GetPrivateCommitment(curve, big.NewInt(1), coefsZero)
	//if groupPk != bgls.LoadPublicKey(curve, groupSk) {
	//return false, fmt.Errorf("groupPK doesnt match to groupSK")
	//}

	// == Sign and reconstruct ==

	d := make([]byte, 64)
	var err error
	_, err = rand.Read(d)
	//assert.Nil(t, err, "msg data generation failed")
	sigs := make([]Point, n)
	for participant := 0; participant < n; participant++ {

		sigs[participant] = bgls.Sign(curve, skAll[participant], d)

		if !bgls.VerifySingleSignature(curve, sigs[participant], pkAll[0][participant], d) {
			return false, fmt.Errorf("signature invalid")
		}
	}

	indices := make([]*big.Int, n)
	index := big.NewInt(0)
	for participant := 0; participant < n; participant++ {
		index.Add(index, big.NewInt(1))
		indices[participant] = big.NewInt(0).Set(index)
	}

	groupSig1, err := SignatureReconstruction(
		curve, sigs[:threshold+1], indices[:threshold+1])
	if err != nil {
		return false, fmt.Errorf("group signature reconstruction fail")
	}
	if !bgls.VerifySingleSignature(curve, groupSig1, groupPk, d) {
		return false, fmt.Errorf("group signature invalid")
	}

	groupSig2, err := SignatureReconstruction(
		curve, sigs[n-(threshold+1):], indices[n-(threshold+1):])

	if err != nil {
		return false, fmt.Errorf("group signature reconstruction fail")
	}
	if !bgls.VerifySingleSignature(curve, groupSig2, groupPk, d) {
		return false, fmt.Errorf("group signatures are not equal")
	}

	return true, nil

}

// Returns pubCommitG1 (array of 2d points), pubCommitG2 (array of 4d points) and prvCommit (array of bigints)
// This is for
//func GetDataForCommit(curve CurveSystem, threshold int, clientsCount int) map[string]interface{} {
//
//  coefficients := make([]*big.Int, threshold+1)
//  pubCommitG1 := make([]Point, threshold+1)
//  pubCommitG2 := make([]Point, threshold+1)
//  prvCommit := make([]*big.Int, clientsCount)
//
//  for i := 0; i < threshold+1; i++ {
//	coefficients[i], pubCommitG1[i], pubCommitG2[i], _ = CoefficientGen(curve)
//	dkg.VerifyPublicCommitment(curve, pubCommitG1[i], pubCommitG2[i])
//  }
//
//  j := big.NewInt(1)
//  for i := 0; i < clientsCount; i++ {
//	prvCommit[i] = dkg.GetPrivateCommitment(curve, j, coefficients)
//	j.Add(j, big.NewInt(1))
//  }
//
//  return map[string]interface{}{"coefficients": coefficients, "pubCommitG1": pubCommitG1, "pubCommitG2": pubCommitG2, "prvCommit": prvCommit}
//
//  //return json.Marshal(1)
//}

func main() {
	Init()
	curve := Altbn128
	//fmt.Println(cmd)
	//fmt.Println(flag.Args())
	switch cmd {

	case "GetCommitDataForAllParticipants":
		threshold := toInt(flag.Arg(0))
		n := toInt(flag.Arg(1))
		exportDataFile := flag.Arg(2)

		commitData, err := GetCommitDataForAllParticipants(curve, threshold, n)
		if err != nil {
			fmt.Println("Error in GetCommitDataForallParticipants():", err)
		}
		//json, err := jsoniter.Marshal(commitData)
		json, err := marshal(commitData)
		if err != nil {
			fmt.Println("Error marshalling commit data", err)
		}
		os.Stdout.Write(json)
		err = ioutil.WriteFile(exportDataFile, json, 0644)
		if err != nil {
			panic(err)
		}
		//err = writeGob("./data.gob", commitData)
		if err != nil {
			panic(err)
		}

	case "SignAndVerify":
		threshold := toInt(flag.Arg(0))
		n := toInt(flag.Arg(1))
		dataFile := flag.Arg(2)
		var inBuf []byte
		var err error
		inBuf, err = ioutil.ReadFile(dataFile)
		var data = new(DataForCommit)
		//err = readGob("./data.gob", data)
		if err != nil {
			panic(err)
		}

		//inBuf2 := []byte(strings.Replace(string(inBuf), "\"", "", -1)) // remove all double-quotes
		//fmt.Printf("\ninBuf=%v\n\n", string(inBuf2))
		data, err = unmarshal(curve, inBuf)

		//err = json.Unmarshal(inBuf2, &data)
		//if err != nil {
		//  panic(err)
		//}
		isOk, err := SignAndVerify(curve, threshold, n, data)
		if err != nil {
			fmt.Println("Error in SignAndVerify():", err)
			return
		}
		fmt.Printf("SignAndVerify() ok? %v", isOk)

		/*
			  case "GetDataForCommit":
				threshold := toInt(flag.Args()[0])
				clientCount := toInt(flag.Args()[1])
				res := GetDataForCommit(curve, threshold, clientCount)
				json, err := json.Marshal(res)
				if err != nil {
				  fmt.Println("Error in json:", err)
				}
				//fmt.Printf("%T %v\n", res, res)
				fmt.Printf("%v", string(json))
			  case "CoefficientGen":
				// func CoefficientGen(curve CurveSystem) (*big.Int, Point, Point, error) {
				x, g1commit, g2commit, error := dkg.CoefficientGen(curve)
				fmt.Printf("%v %v %v %v\n", bigIntToStr(x), pointToStr(g1commit), pointToStr(g2commit), error)
			  case "LoadPublicKeyG1":
				// func LoadPublicKeyG1(curve CurveSystem, sk *big.Int) Point {
				sk := toBigInt(flag.Args()[0])
				point := dkg.LoadPublicKeyG1(curve, sk)
				fmt.Printf("%v\n", pointToStr(point))
			  case "GetPrivateCommitment":
				// func GetPrivateCommitment(curve CurveSystem, ind *big.Int, coefficients []*big.Int) *big.Int {
				ind := toBigInt(flag.Args()[0])
				coefficients := toBigInts(flag.Args()[1:])
				bigInt := dkg.GetPrivateCommitment(curve, ind, coefficients)
				fmt.Printf("%v\n", bigIntToStr(bigInt))
			  case "GetGroupPublicKey":
				// func GetGroupPublicKey(curve CurveSystem, pubCommitG2 []Point) Point {
				pubCommitG2 := toPoints(flag.Args())
				point := dkg.GetGroupPublicKey(curve, pubCommitG2)
				fmt.Printf("%v\n", pointToStr(point))
			  case "VerifyPublicCommitment":
				// func VerifyPublicCommitment(curve CurveSystem, pubCommitG1 Point, pubCommitG2 Point) bool
				pubCommitG1 := toPoint(flag.Args()[0:POINT_ELEMENTS])
				pubCommitG2 := toPoint(flag.Args()[POINT_ELEMENTS : POINT_ELEMENTS+POINT_ELEMENTS])
				boolRes := dkg.VerifyPublicCommitment(curve, pubCommitG1, pubCommitG2)
				fmt.Printf("%v\n", boolToStr(boolRes))
			  case "VerifyPrivateCommitment":
				// func VerifyPrivateCommitment(curve CurveSystem, myIndex *big.Int, prvCommit *big.Int, pubCommitG1 []Point) bool {
				myIndex := toBigInt(flag.Args()[0])
				prvCommit := toBigInt(flag.Args()[1])
				pubCommitG1 := toPoints(flag.Args()[2:])
				boolRes := dkg.VerifyPrivateCommitment(curve, myIndex, prvCommit, pubCommitG1)
				fmt.Printf("%v\n", boolToStr(boolRes))
			  case "CalculatePrivateCommitment":
				// func CalculatePrivateCommitment(curve CurveSystem, index *big.Int, pubCommit []Point) Point {
				index := toBigInt(flag.Args()[0])
				pubCommit := toPoints(flag.Args()[1:])
				point := dkg.CalculatePrivateCommitment(curve, index, pubCommit)
				fmt.Printf("%v\n", pointToStr(point))
			  case "GetSecretKey":
				// func GetSecretKey(prvCommits []*big.Int) *big.Int {
				prvCommits := toBigInts(flag.Args())
				bigInt := dkg.GetSecretKey(prvCommits)
				fmt.Printf("%v\n", bigIntToStr(bigInt))
			  case "GetSpecificPublicKey":
				// func GetSpecificPublicKey(curve CurveSystem, index *big.Int, threshold int, pubCommitG2 []Point) Point {
				index := toBigInt(flag.Args()[0])
				threshold := toInt(flag.Args()[1])
				pubCommitG2 := toPoints(flag.Args()[2:])
				pointRes := dkg.GetSpecificPublicKey(curve, index, threshold, pubCommitG2)
				fmt.Printf("%v\n", pointToStr(pointRes))
			  case "GetAllPublicKey":
				// func GetAllPublicKey(curve CurveSystem, threshold int, pubCommitG2 []Point) []Point {
				threshold := toInt(flag.Args()[0])
				pubCommitG2 := toPoints(flag.Args()[1:])
				pointsRes := dkg.GetAllPublicKey(curve, threshold, pubCommitG2)
				fmt.Printf("%v\n", pointsToStr(pointsRes))
			  case "SignatureReconstruction":
				// func SignatureReconstruction(curve CurveSystem, sigs []Point, signersIndices []*big.Int) (Point, error) {
				// We don't know in advance how many sigs there are so take a param for that,
				// multiply by how many array elements create a single point, then read the points, then read the next param
				sigsLen := toInt(flag.Args()[0])
				sigsElements := sigsLen * POINT_ELEMENTS
				sigs := toPoints(flag.Args()[1:sigsElements])
				signersIndices := toBigInts(flag.Args()[sigsElements:])
				point, err := dkg.SignatureReconstruction(curve, sigs, signersIndices)
				fmt.Printf("%v %v\n", pointToStr(point), err)
		*/
	}

}
func unmarshal(curve CurveSystem, bytes []byte) (*DataForCommit, error) {

	//fmt.Println("Start unmarshal")
	jsonData := new(JsonDataForCommit)
	if err := json.Unmarshal(bytes, jsonData); err != nil {
		return nil, err
	}
	n := len(jsonData.CoefficientsAll)
	commitData := new(DataForCommit)
	commitData.CoefficientsAll = make([][]*big.Int, n)
	commitData.PubCommitG1All = make([][]Point, n)
	commitData.PubCommitG2All = make([][]Point, n)
	commitData.PrvCommitAll = make([][]*big.Int, n)

	for i := 0; i < len(jsonData.CoefficientsAll); i++ {
		commitData.CoefficientsAll[i] = make([]*big.Int, len(jsonData.CoefficientsAll[i]))
		for j := 0; j < len(jsonData.CoefficientsAll[i]); j++ {
			commitData.CoefficientsAll[i][j] = toBigInt(jsonData.CoefficientsAll[i][j])
		}
	}

	for i := 0; i < len(jsonData.PubCommitG1All); i++ {
		commitData.PubCommitG1All[i] = make([]Point, len(jsonData.PubCommitG1All[i]))
		for j := 0; j < len(jsonData.PubCommitG1All[i]); j++ {

			coords := make([]*big.Int, len(jsonData.PubCommitG1All[i][j]))
			for k := 0; k < len(jsonData.PubCommitG1All[i][j]); k++ {
				coords[k] = toBigInt(jsonData.PubCommitG1All[i][j][k])
			}
			var isOk bool
			commitData.PubCommitG1All[i][j], isOk = curve.MakeG1Point(coords, true)
			if !isOk {
				panic(fmt.Errorf("Failed to make G1 point"))
			}
		}
	}

	for i := 0; i < len(jsonData.PubCommitG2All); i++ {
		commitData.PubCommitG2All[i] = make([]Point, len(jsonData.PubCommitG2All[i]))
		for j := 0; j < len(jsonData.PubCommitG2All[i]); j++ {

			coords := make([]*big.Int, len(jsonData.PubCommitG2All[i][j]))
			for k := 0; k < len(jsonData.PubCommitG2All[i][j]); k++ {
				coords[k] = toBigInt(jsonData.PubCommitG2All[i][j][k])
			}
			var isOk bool
			commitData.PubCommitG2All[i][j], isOk = curve.MakeG2Point(coords, true)
			if !isOk {
				panic(fmt.Errorf("Failed to make G2 point"))
				fmt.Println("G2 Point: ", commitData.PubCommitG2All[i][j])
			}
		}
	}

	for i := 0; i < len(jsonData.PrvCommitAll); i++ {
		commitData.PrvCommitAll[i] = make([]*big.Int, len(jsonData.PrvCommitAll[i]))
		for j := 0; j < len(jsonData.PrvCommitAll[i]); j++ {
			commitData.PrvCommitAll[i][j] = toBigInt(jsonData.PrvCommitAll[i][j])
		}
	}

	//fmt.Println("End unmarshal")
	return commitData, nil

}

func marshal(commitData *DataForCommit) ([]byte, error) {

	n := len(commitData.CoefficientsAll)
	jsonData := new(JsonDataForCommit)
	jsonData.CoefficientsAll = make([][]string, n)
	jsonData.PubCommitG1All = make([][][]string, n)
	jsonData.PubCommitG2All = make([][][]string, n)
	jsonData.PrvCommitAll = make([][]string, n)

	for i := 0; i < len(commitData.CoefficientsAll); i++ {
		jsonData.CoefficientsAll[i] = make([]string, len(commitData.CoefficientsAll[i]))
		for j := 0; j < len(commitData.CoefficientsAll[i]); j++ {
			jsonData.CoefficientsAll[i][j] = toHexBigInt(commitData.CoefficientsAll[i][j])
		}
	}

	for i := 0; i < len(commitData.PubCommitG1All); i++ {
		jsonData.PubCommitG1All[i] = make([][]string, len(commitData.PubCommitG1All[i]))
		for j := 0; j < len(commitData.PubCommitG1All[i]); j++ {
			coords := commitData.PubCommitG1All[i][j].ToAffineCoords()
			coordsStr := make([]string, len(coords))
			for k := 0; k < len(coords); k++ {
				coordsStr[k] = toHexBigInt(coords[k])
			}
			jsonData.PubCommitG1All[i][j] = coordsStr
		}
	}

	for i := 0; i < len(commitData.PubCommitG2All); i++ {
		jsonData.PubCommitG2All[i] = make([][]string, len(commitData.PubCommitG2All[i]))
		for j := 0; j < len(commitData.PubCommitG2All[i]); j++ {
			coords := commitData.PubCommitG2All[i][j].ToAffineCoords()
			coordsStr := make([]string, len(coords))
			for k := 0; k < len(coords); k++ {
				coordsStr[k] = toHexBigInt(coords[k])
			}
			jsonData.PubCommitG2All[i][j] = coordsStr
		}
	}

	for i := 0; i < len(commitData.PrvCommitAll); i++ {
		jsonData.PrvCommitAll[i] = make([]string, len(commitData.PrvCommitAll[i]))
		for j := 0; j < len(commitData.PrvCommitAll[i]); j++ {
			jsonData.PrvCommitAll[i][j] = toHexBigInt(commitData.PrvCommitAll[i][j])
		}
	}

	return json.MarshalIndent(jsonData, "", "  ")

}
func toHexBigInt(n *big.Int) string {
	return fmt.Sprintf("0x%x", n) // or %X or upper case
}

func toPoint(strings []string) Point {
	panic("Not implemented")
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
func toPoints(args []string) []Point {
	panic("Not implemented")
}

func toBigInts(strings []string) []*big.Int {
	bigInts := make([]*big.Int, len(strings))
	for i := 0; i < len(strings); i++ {
		bigInts[i] = toBigInt(strings[i])
	}
	return bigInts
}

func toBigInt(s string) *big.Int {
	bigInt := new(big.Int)
	bigInt, ok := bigInt.SetString(s, 0)
	if !ok {
		panic(fmt.Errorf("toBigInt() failed on string %v", s))
	}
	return bigInt
}

func boolToStr(boolRes bool) string {
	return fmt.Sprintf("%v", boolRes)
}

func bigIntToStr(bigInt *big.Int) string {
	return fmt.Sprintf("%v", bigInt)
}

func pointToStr(point Point) string {
	return fmt.Sprintf("%v", point)
}

func pointsToStr(points []Point) interface{} {
	pointsStr := make([]string, len(points))
	for i := 0; i < len(points); i++ {
		pointsStr[i] = pointToStr(points[i])
	}
	return strings.Join(pointsStr, " ")
}

func Init() {

	flag.StringVar(&cmd, "func", "", "Name of function")
	flag.Parse()

	fmt.Println("-- BGLSMAIN.GO -- ")

}
