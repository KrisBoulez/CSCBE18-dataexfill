package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var a_pos = make(map[string][]string) // Ascii to position mapping
var pos_a = make(map[string]string)   // position to Ascii mapping  (Value is a single ASCII char

func main() {
	// preload btc block files
	readBlockFiles()

	chunkSize := 13 // maximum chunk of text to be encrypted

	// text to be encrypted
	f, _ := os.Open("secret.txt")
	reader := bufio.NewReader(f)
	content, _ := ioutil.ReadAll(reader)
	st := string(content)
	st = strings.Replace(st, "\n", " ", -1) // replace newlines with a space
	r := regexp.MustCompile(` $`)
	st = r.ReplaceAllString(st, "") // and remove the final space (we might have added one too manuy)

	for i := 0; i < len(st); i += chunkSize {
		end := i + chunkSize
		if end > len(st) { // to not read past the end of the string
			end = len(st)
		}

		ct := encodeBTC(st[i:end]) // encode a text
		fmt.Println("ciphertext:", ct)

		//pt, _ := decodeBTC(ct) // decode the encrypted text
		//fmt.Println("plaintext: ", pt)
	}
}

func encodeBTC(pt string) string {

	// seed the random number generator
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	var ct string // cipher text
	// loop over each char of the plaintext (pt)
	for _, r := range pt {
		c := string(r)     // r is a rune
		l := len(a_pos[c]) // nr of possible encodings for this char
		i := r1.Intn(l)    // take one of the encodings

		//fmt.Printf("%s %s\n", c, a_pos[c][i])
		ct += a_pos[string(r)][i]
	}

	return ct
}

func decodeBTC(ct string) (pt string, rc int) {
	rc = 200 // return code (think HTTP status code) - default success

	// addresss is not a multiple of 6 hex chars
	if len(ct)%6 != 0 {
		rc = 500
		return pt, rc
	}

	for i := 0; i < len(ct); i += 6 {
		s := string(ct[i : i+6])
		//		fmt.Printf(" %s %v\n", s, pa[s])
		if v, ok := pos_a[s]; ok { // an entry exists for this hextet
			pt += v
		} else {
			rc = 400 // one or more hextets didn't decode
			pt += `|`
		}
	}

	return pt, rc

}

func readBlockFiles() {
	// input btc block file - stored in data/ subdir
	blockDir := "../webserver/data_flag3/"
	files, err := ioutil.ReadDir(blockDir)
	if err != nil {
		log.Fatal(err)
	}

	// only use a random subset of files
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	for k := 1; k <= 11; k++ {
		i := r1.Intn(len(files))
		f := files[i]
		//   JSON format, we do expect fixed ordering (server will just send the file)
		bf := blockDir + f.Name()
		// read the blcok files we use for decryption
		readBlockFile(bf)
	}

}

func readBlockFile(bf string) {
	file, err := os.Open(bf)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	fmt.Print("Reading ", bf, " ... ")

	scanner := bufio.NewScanner(file)

	// determine number of block
	re_blocknr := regexp.MustCompile(`\d(\d\d)\.json`) // we take last two digits for block number
	b := re_blocknr.FindStringSubmatch(bf)
	if len(b) <= 0 { // no match for Blockfile name
		err := errors.New("No match for Blockfile name")
		if err != nil {
			fmt.Print(err)
		}
	}
	n_block, _ := strconv.Atoi(b[1])

	re_hash := regexp.MustCompile(`^\s+"hash":"([0-9a-f]+)",\s*$`)
	re_27 := regexp.MustCompile(`[2-7]`)
	n_h := 0 // for counting the hash lines

	for scanner.Scan() {
		l := scanner.Text()
		h_l := re_hash.FindStringSubmatch(l) // only looking for lines containing "hash"
		if len(h_l) <= 0 {
			continue
		}
		n_h++

		// only store first 255 hashes, otherwise we cannot store the value in two hex digits
		if n_h > 255 {
			break
		}

		hash := h_l[1] // hash value is captured in second element of slice
		//fmt.Printf("%T %v\n", hash, hash)

		// look for ASCII values in de hash  ( 20 <= x <= 7E )

		for n_c, c := range hash { // loop over all chars in the hash (hex chars) and see if
			// two consecutive ones produce valid ASCII (20 - 7e)
			if n_c+1 == len(hash) { // skip last element, cannot have a following char
				break
			}
			d := string(c) // make a string of it
			if m := re_27.MatchString(d); !m {
				continue
			}
			hh := d + string(hash[n_c+1]) // concatenate the next char to it. Two hex values
			if hh == "7f" {               // 7F is the only non-ascii char
				continue
			}
			asc, _ := hex.DecodeString(hh)
			pos_hash := fmt.Sprintf("%02x%02x%02x", n_block, n_h, n_c)

			a_pos[string(asc)] = append(a_pos[string(asc)], pos_hash)

			pos_a[pos_hash] = string(asc)
			//                      fmt.Printf(" %d %v %v  %v %v %v\n", n_c, c, d, hh, string(asc), string(pos_hash))
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("done")
}

//  20: (space)  - 7E (~)
//          2 3 4 5 6 7       30 40 50 60 70 80 90 100 110 120
//        -------------      ---------------------------------
//       0:   0 @ P ` p     0:    (  2  <  F  P  Z  d   n   x
//       1: ! 1 A Q a q     1:    )  3  =  G  Q  [  e   o   y
//       2: " 2 B R b r     2:    *  4  >  H  R  \  f   p   z
//       3: # 3 C S c s     3: !  +  5  ?  I  S  ]  g   q   {
//       4: $ 4 D T d t     4: "  ,  6  @  J  T  ^  h   r   |
//       5: % 5 E U e u     5: #  -  7  A  K  U  _  i   s   }
//       6: & 6 F V f v     6: $  .  8  B  L  V  `  j   t   ~
//       7: ' 7 G W g w     7: %  /  9  C  M  W  a  k   u  DEL
//       8: ( 8 H X h x     8: &  0  :  D  N  X  b  l   v
//       9: ) 9 I Y i y     9: '  1  ;  E  O  Y  c  m   w
//       A: * : J Z j z
//       B: + ; K [ k {
//       C: , < L \ l |
//       D: - = M ] m }
//       E: . > N ^ n ~
//       F: / ? O _ o DEL
