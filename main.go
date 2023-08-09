/*
HMAC uses a symmetric key that both sender/receiver share ahead of time.
The sender will generate a hash when wanting to transmit a message - this data is sent along with the payload.
The recipient will then sign the payload with the shared key again. And if the hash matches then the payload is assumed to be from the sender.
*/
package main

import (
	"fmt"

	"github.com/alexellis/hmac"
)

func main() {
	input := []byte(`input message from API`)
	secret := []byte(`so secret`)

	digest := hmac.Sign(input, secret)

	fmt.Printf("Digest: %x\n", digest)
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
