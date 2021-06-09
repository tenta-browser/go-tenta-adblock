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

/// graph unit flags
const (
	flagException  = 1 << iota
	flagPipeStart  = 1 << iota
	flagPipeEnd    = 1 << iota
	flagDoublePipe = 1 << iota
	flagSeparator  = 1 << iota
	flagWildCard   = 1 << iota
	flagNum        = 6
)

var flagToString = map[int]string{
	flagException:  "Exception",
	flagPipeStart:  "Start anchor",
	flagPipeEnd:    "End anchor",
	flagDoublePipe: "Domain name anchor",
	flagSeparator:  "Separator",
	flagWildCard:   "Wildcard",
}

func formatFlags(flags int) (s string) {
	s += "FLAGS:"
	for i := uint(0); i < flagNum; i++ {
		if flgStr, ok := flagToString[flags&(1<<i)]; ok {
			s += " " + flgStr
		}
	}
	return
}
