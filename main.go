/*
HMAC uses a symmetric key that both sender/receiver share ahead of time.
The sender will generate a hash when wanting to transmit a message - this data is sent along with the payload.
The recipient will then sign the payload with the shared key again. And if the hash matches then the payload is assumed to be from the sender.
*/
package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/alexellis/hmac"
)

func main() {
	var inputVar string
	var secretVar string
	var modeVar string
	var digestVar string

	// go run main.go -message="my message" -secret="omo kabba"
	flag.StringVar(&inputVar, "message", "", "message to create a digest from")
	flag.StringVar(&secretVar, "secret", "", "secret for the digest")
	flag.StringVar(&modeVar, "mode", "generate", "mode for hmac operations")
	flag.StringVar(&digestVar, "digest", "", "digest for validation")

	flag.Parse()

	if len(strings.TrimSpace(secretVar)) == 0 {
		panic("--secret is required")
	}

	if modeVar == "generate" {
		fmt.Printf("Computing hash for: %q\nSecret: %q\n", inputVar, secretVar)
		digest := hmac.Sign([]byte(inputVar), []byte(secretVar))
		fmt.Printf("Digest: %x\n", digest)
		return
	} else if modeVar == "validate" {

		if len(strings.TrimSpace(digestVar)) == 0 {
			panic("--digest is required")
		}

		composeDigest := hmac.Sign([]byte(inputVar), []byte(secretVar))

		err := hmac.Validate([]byte(inputVar), fmt.Sprintf("sha1=%x", composeDigest), string(secretVar))

		if err != nil {
			panic(err)
		}

		fmt.Printf("Digest validated.\n")

		return

	}

	fmt.Printf("Unknown mode entered.\n")

	// fmt.Printf("Computing hash for: %q\nSecret: %q\n", inputVar, secretVar)

	// input := []byte(`input message from API`)
	// secret := []byte(`so secret`)

	// verify the digest

	// err := hmac.Validate(input, fmt.Sprintf("sha1=%x", digest), string(secret))

	// if err != nil {
	// 	panic(err)
	// }

}

/*
The digest 17074131772d763bc4a360a6e4cb1a5ad1a98764 was printed which is a hash that can be sent with the original input.
Any user with the secret can compute another hash and if they match, that user will know the message was from us.

   Sender:
   	1. signs the payload with a secret (secret is shared before hand with the receiver)
	2. adds the digest to the request
	3. makes the request
    Receiver:
	1. Receives the request
	2. Sign the payload with the same secret as the sender
	3. compare the digest with the digest in the request payload
	4. if it matches, then the request is validate else
	5. bin
*/
