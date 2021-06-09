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
	"strings"
)

/* regex capture groups
 0 - full match
 1 - comment
 2 - exception
 3 - host entry
 4 - regex entry
 5 - domain entry
 6 - pipe start
 7 - url part entry
 8 - pipe end
 9 - filter options
10 - dom/css filter options
*/

/// regex classes
const (
	/// regex defining legal chars in url part describing classes, or eats up justdomain type of lists too
	///                                                [\|]* -- removed
	reURLPart = `(?:[\w\.\-\:\/\+\&\=\?\*\;\,\~\%\^\@]+[\w\.\-\:\/\+\&\=\?\*\;\,\~\!\]\[\^\@]*)*`
	/// three types of comments occuring in adblock plus filter definitions
	reCommentGroup = `((?:\[[\w .]+\])|(?:\#.*)|(?:\!.*))`
	/// exact address type filter
	reFreeFormEntry = `(?:(` + reURLPart + `))`
	/// fixed start and/or end type filter
	reStartEndDefined = `(?:(\|)?(` + reURLPart + `)(\|)?)`
	/// domain filter
	reDomain = `(?:\|\|(` + reURLPart + `))`
	/// host format
	reHost = `[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[\s]+([\w\.\-]+)`
	/// regular expression filters (this one is ugly, it basically hangs on the idea of the regex having at least one char class)
	reRegex = `\/((?:[\w\.\-\:\+\&\=\?\*\|\;\,\{\}\$\^\\\/\(\)]*[\[\]]*[\w\.\-\:\+\&\=\?\*\|\;\,\{\}\$\\\/\(\)]*)+)\/`
	/// filtering parameters -- aggregated form, v0.1 can't handle these
	reFilterParams = `(?:\$(.+))?`
	/// exception token catcher
	reException     = `(\@\@)?`
	reDOMFilter     = `(\#\#.*|\#\?\#.*|\#\@\#.*)?`                       /// android/other will receive this as tokens[10] which it will ignore
	reDOMFilterIOS  = `(?:\#\#(.*))?(?:\#\@\#(.*))?(|\#\?\#.*|\#\$\#.*)?` /// for iOS (JSON content filtering) we capture CSS selectors and CSS selector exceptions
	reArgumentGroup = `(?:` + reHost + `|` + reRegex + `|` + reDomain + `|` + reStartEndDefined + `)`
	reEntry         = `^` + reCommentGroup + `|` + reException + reArgumentGroup + reFilterParams + reDOMFilter + `$`
	reEntryIOS      = `^` + reCommentGroup + `|` + reException + reArgumentGroup + reFilterParams + reDOMFilterIOS + `$`
	/// regex for protocol+subdomain parsing from URL (used in double pipe case)
	reProtocolSubdomain = `^(?:[\w-+.]+://)?(?:(?:` + reURLPart + `)\.)*$`
)

const (
	separatorExpansion = `:/?=&`
	separatorCharClass = "[" + separatorExpansion + "]+"
)

var (
	pEntry    = regexp.MustCompile(reEntry)
	pEntryIOS = regexp.MustCompile(reEntryIOS)
)

type rawGraphElement struct {
	token                   string
	suffix                  string
	flags                   int
	original                string
	filter                  string
	opts                    *filterOptions
	domfilter, domexception string
}

func parseLine(line string, foriOS bool) (r *rawGraphElement, e error) {
	var tokens []string
	if foriOS {
		tokens = pEntryIOS.FindStringSubmatch(line)
	} else {
		tokens = pEntry.FindStringSubmatch(line)
	}

	/// check for full match, as in the whole pattern is matched, aka use only the formats supported
	if tokens == nil {
		return nil, fmt.Errorf("unrecognized format [%s]", line)
	}
	if tokens[0] == "" {
		return nil, fmt.Errorf("unhandled format [%s]", line)
	}

	r = &rawGraphElement{}
	var err error
	/// can't handle fine grained filters as of yet
	if tokens[9] != "" {
		if foriOS {
			//log("Options: [%s]\n", tokens[9])
			if r.opts, err = newFilterOptions(tokens[9]); err != nil {
				//log("Aborting construction of element due to Opts error: [%s]\n", err.Error())
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("cannot handle options [%s]", tokens[9])
		}
	}

	if tokens[10] != "" {
		if foriOS {
			//log("CSS selectors: [%s]\n", tokens[10])
			r.domfilter = tokens[10]
		} else {
			return nil, fmt.Errorf("cannot handle DOM alteration")
		}
	}

	if foriOS && tokens[11] != "" {
		//log("CSS exception selectors: [%s]\n", tokens[10])
		r.domexception = tokens[11]
	}

	if foriOS && tokens[12] != "" {
		return nil, fmt.Errorf("cannot handle exntended/ABP css selectors")
	}

	if tokens[2] != "" {
		r.flags |= flagException
	}
	/// host entry
	if tokens[3] != "" {
		r.token = tokens[3]
		r.flags |= flagDoublePipe
	} else
	/// fixed domain
	if tokens[5] != "" {
		r.token = tokens[5]
		// DANGER DANGER!!!!!
		r.flags |= flagDoublePipe
	}
	/// url part or fixed end/start
	if tokens[7] != "" {
		if tokens[6] != "" {
			r.flags |= flagPipeStart
		}
		if tokens[8] != "" {
			r.flags |= flagPipeEnd
		}
		r.token = tokens[7]
	}

	if strings.Contains(r.token, "*") {
		r.flags |= flagWildCard
	}
	if strings.Contains(r.token, "^") {
		r.flags |= flagSeparator
	}
	r.original = r.token

	//log("LINE::[%v]\n", tokens)

	return r, nil
}

// determine end of line sequence and split the
// content into multiple lines
func splitIntoLines(content string) []string {
	le := "\n"
	if strings.Contains(content, "\r\n") {
		le = "\r\n"
	}

	return strings.Split(content, le)
}
