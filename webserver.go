package main

import (
	"bufio"
	b64 "encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
)

var validPath = regexp.MustCompile("^/(block|address)/([a-fA-F0-9]+)$")
var a_pos = make(map[string][]string) // Ascii to position mapping
var pos_a = make(map[string]string)   // position to Ascii mapping  (Value is a single ASCII char
var addrRespFoot string               // footer for the address response

func decodeBTC(ct string) (pt string, rc int) {
	rc = 200 // return code (think HTTP status code) - default success

	// plaintext for the different flags
	ptFlag1 := "What is the CSCBE flag 1?"
	ptFlag2 := "gimme the second flag ..."
	ptFlag3 := "Dear 0r&cl# (what is Flag3)"

	// addresss is not a multiple of 6 hex chars
	if len(ct)%6 != 0 {
		rc = 500
		return pt, rc
	}

	for i := 0; i < len(ct); i += 6 {
		s := string(ct[i : i+6])
		//              fmt.Printf(" %s %v\n", s, pa[s])
		if v, ok := pos_a[s]; ok { // an entry exists for this hextet
			pt += v
		} else {
			rc = 400 // one or more hextets didn't decode
			pt += `|`
		}
	}

	fmt.Printf("--%s--\n--%s--\n", pt, ptFlag1)

	if pt == ptFlag1 {
		rc = 201
	} else if pt == ptFlag2 {
		rc = 202
	} else if pt == ptFlag3 {
		rc = 203
	}

	return pt, rc
}

func readARF(af string) {
	// Read the footer for the Address response body
	file, err := os.Open(af)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		addrRespFoot = addrRespFoot + scanner.Text() + "\n"
	}
}

func readBlockFiles() {
	// input btc block file - stored in data/ subdir
	blockDir := "data/"
	files, err := ioutil.ReadDir(blockDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
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

			//fmt.Printf("n_b:%d n_h:%d n_c:%d nr_ascii:%d %v\n", n_block, n_h, n_c, nr_ascii, string(pos_hash))
			//                      fmt.Printf(" %d %v %v  %v %v %v\n", n_c, c, d, hh, string(asc), string(pos_hash))
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("done")
}

func blockHandler(w http.ResponseWriter, r *http.Request, title string) {
	// The "title" is the number of the block.
	//   if this block exists in .json format, we will return it
	//   otherwise, we return Page not Found
	//
	blockDir := "data/"
	filename := blockDir + title + ".json"
	_, err := os.Stat(filename)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	body, err := ioutil.ReadFile(filename)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fmt.Fprintf(w, string(body))
}

func addressHandler(w http.ResponseWriter, r *http.Request, ct string) {
	body := "" // response body
	body += "{" + "\n"
	body += `    "hash160":"5cfb25c53220ec02913648a380e2b07fe0287ef2",` + "\n"
	body += `    "address":"19Ue2gkjFb7K3nodHSpz3DUqrVUNeNNkj2",` + "\n"

	// ct is the ciphertext we try to decode
	plain, rc := decodeBTC(ct)

	// if we get here there were no errors in decoding the address
	var b64Plain string

	if rc == 201 {
		plain = "FLag 1: CSCBE{DFHJKJ*&(*UYTG%#$243}"
	} else if rc == 202 {
		plain = "Flag 2: CSCBE{sdfIUerw893475#$&Y&#}"
	} else if rc == 203 {
		plain = "Flag 3: CSCBE{jz2h478dfg^#%%$%jdfj}"
	}

	if rc == 500 {
		b64Plain = ""
	} else {
		b64Plain = b64.StdEncoding.EncodeToString([]byte(plain)) // base64 encode the return_value to
		// make it at least somehwat difficult :-)
	}

	body += `    "return_code":` + string(strconv.Itoa(rc)) + "\n"
	body += `    "return_value":"` + b64Plain + `"` + "\n"

	fmt.Printf("ct: %s\npt: %s\nb64: %s\n", ct, plain, b64Plain)

	if rc == 201 || rc == 202 || rc == 203 { // just create short response, no footer added
		body += "}" + "\n"
	} else {
		// add footer (fixed part) to response body
		body += addrRespFoot
	}

	// output body to web page
	fmt.Fprintf(w, body)
}

func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := validPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		fn(w, r, m[2])
	}
}

func main() {
	// preload btc block files
	readBlockFiles()

	// preload the main part for the response to /address
	aRFFile := "address_response_footer"
	readARF(aRFFile)

	http.HandleFunc("/block/", makeHandler(blockHandler))
	http.HandleFunc("/address/", makeHandler(addressHandler))

	// We listen only on localhost, accessible via
	//   reverse proxy (rate limiting)
	http.ListenAndServe("127.0.0.1:8080", nil)
}
