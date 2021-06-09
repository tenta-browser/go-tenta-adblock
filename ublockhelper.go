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
	"errors"
	"fmt"
	"sync"

	graph "github.com/tenta-browser/go-graph"
)

// UBlockHelper -- object to use in superior layers.
type UBlockHelper struct {
	m sync.Mutex
	d *graph.Dawg
}

// Deserialize -- Deserializes the graph
func Deserialize(enc []byte) (*UBlockHelper, error) {
	localCopy := make([]byte, len(enc))
	copy(localCopy, enc)

	u := &UBlockHelper{}
	u.m.Lock()
	defer u.m.Unlock()

	u.d = graph.Deserialize(localCopy, nil, &ubPayload{})
	if u.d == nil {
		return nil, errors.New("unable to deserialize")
	}

	return u, nil
}

// Search -- returns true if networking should block request, false otherwise
func (u *UBlockHelper) Search(URL string) (bool, error) {
	u.m.Lock()
	defer u.m.Unlock()

	if u.d == nil {
		return false, fmt.Errorf("graph is not initialized")
	}

	proposedRet := false
	for i := range URL {
		result := u.d.ExactLookupWithPayload(URL[i:])
		if result.MatchStatus == graph.MatchNotFound {
			continue
		}
		/// verify the result
		/// no payload -> no constraint over match, return true
		if result.Payload == nil {
			//return true, nil
			proposedRet = true
			continue
		}
		/// evaluate the payload
		log("We have a loaded match with [%s][%s]\n", result.Remainder, result.Payload.(*ubPayload).String())
		if !result.Payload.(*ubPayload).Evaluate(result.Remainder) {
			//log("Reminder not evaluated.\n")
			continue
		}

		flg := result.Payload.(*ubPayload).flags
		/// exception -> permitting access
		if flg&flagException > 0 {
			//log("Exception -> false")
			return false, nil
		}
		/// check flag constraints vs match
		/// absolute start/end of URL
		if (flg&flagPipeStart > 0 && i != 0) || (flg&flagPipeEnd > 0 && result.Remainder != "") {
			//log("cannot match pipes vs remainder\n")
			continue
		}
		/// domain name start
		if flg&flagDoublePipe > 0 {
			if !pProtocolSubdomain.MatchString(URL[:i]) {
				continue
			}
		}
		/// no constrain stuck, no choice but to return true
		//log("")
		proposedRet = true
		continue
	}

	return proposedRet, nil
}
