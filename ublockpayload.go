/**
 * Go uBlock
 *
 *    Copyright 2021 Tenta, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For any questions, please contact developer@tenta.io
 */

package ublock

import (
	"fmt"
	"regexp"
	"strconv"

	graph "github.com/tenta-browser/go-graph"
)

var charOffset = "0"[0]

/// ublock specific payload definition and interface implementation
type ubPayload struct {
	flags  int
	suffix string
}

// Encode -- encodes the ublock specific payload. returns a string([]byte),
// in which the flags are added as plaintext characters (number + ord('a')).
// This keeps byte num lower (2^6 - 1 = 63 ~> 2bytes + 1byte for declaring the length of the length-encode)
// and the overall sequence has much better compressability
func (p *ubPayload) Encode() []byte {
	retString := strconv.Itoa(p.flags)
	fl := strconv.Itoa(len(retString))
	retString = fl + retString + p.suffix
	return []byte(retString)
}

// Decode -- follows the logic (inversely) laid out in Encode()
func (p *ubPayload) Decode(enc []byte) (graph.NodePayload, error) {
	in := string(enc)
	l := in[0] - charOffset
	flags, e := strconv.Atoi(in[1 : 1+l])
	if e != nil {
		return nil, e
	}
	ret := &ubPayload{flags: flags, suffix: in[1+l:]}
	return ret, nil
}

// String -- string representation of the payload
func (p *ubPayload) String() string {
	return fmt.Sprintf("[%s][%s]", formatFlags(p.flags), p.suffix)
}

// Evaluate -- evaluates the remainder from an uncertain match. True means a match is made, false means no match
func (p *ubPayload) Evaluate(remainder string) bool {
	re, e := regexp.Compile(p.suffix)
	if e != nil {
		return false
	}
	return re.MatchString(remainder)
}

/// ublock specific debugging payload (contains filter info)
type ubDebugPayload struct {
	*ubPayload
	list, original string
}

// String -- string representation of payload with debug information
func (p *ubDebugPayload) String() string {
	return fmt.Sprintf("[%s][%s][%s][%s]", formatFlags(p.flags), p.suffix, p.original, p.list)
}
