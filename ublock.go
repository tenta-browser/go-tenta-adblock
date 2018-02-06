/**
 * Go uBlock
 *
 *    Copyright 2018 Tenta, LLC
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
 *
 * ublock.go: Go uBlock implementation
 */
package ublock

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	graph "github.com/tenta-browser/go-graph"
)

const (
	uBlockAssets      = "https://raw.githubusercontent.com/gorhill/uBlock/master/assets/assets.json"
	compileDebugAsset = false
	cacheValidity     = 24 * time.Hour
)

type assetItem struct {
	Content, Title, SupportURL, Group string
	ContentURL                        interface{}
	UpdateAfter                       float64
	Off                               bool
}

type assetListItem struct {
	name, content, group, contentURL string
}

type rawGraphElement struct {
	token    string
	suffix   string
	flags    int
	original string
	filter   string
}

type sortableGraphInput []*rawGraphElement

/// ublock specific payload definition and interface implementation
type ubPayload struct {
	flags  int
	suffix string
}

/// ublock specific debugging payload (contains filter info)
type ubDebugPayload struct {
	*ubPayload
	list, original string
}

/// package-wide logging flag
var loggingEnabled = true

// SetLoggingEnabled -- toggle logging for package
func SetLoggingEnabled(b bool) {
	loggingEnabled = b
}

func log(format string, args ...interface{}) {
	if loggingEnabled == true {
		fmt.Printf(format, args...)
	}
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

// String -- string representation of payload with debug information
func (p *ubDebugPayload) String() string {
	return fmt.Sprintf("[%s][%s][%s][%s]", formatFlags(p.flags), p.suffix, p.original, p.list)
}

// Evaluate -- evaluates the remainder from an uncertain match. True means a match is made, false means no match
func (p *ubPayload) Evaluate(remainder string) bool {
	re, e := regexp.Compile(p.suffix)
	if e != nil {
		return false
	}
	return re.MatchString(remainder)
}

var assetList = make([]*assetListItem, 0)
var downloadedBytes, readBytes int64
var cachedAssets = make(map[string]string, 0)
var charOffset = "0"[0]

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
	reURLPart = `(?:[\w\.\-\:\/\+\&\=\?\*\;\,\~\%\^\@]+[\|]*[\w\.\-\:\/\+\&\=\?\*\;\,\~\!\]\[\^\@]*)*`
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
	reRegex = `\/((?:[\w\.\-\:\+\&\=\?\*\|\;\,\{\}\$\\\/\(\)]*[\[\]]+[\w\.\-\:\+\&\=\?\*\|\;\,\{\}\$\\\/\(\)]*)+)\/`
	/// filtering parameters -- aggregated form, v0.1 can't handle these
	reFilterParams = `(?:\$(.+))?`
	/// exception token catcher
	reException     = `(\@\@)?`
	reDOMFilter     = `(\#\#.*|\#\?\#.*|\#\@\#.*)?`
	reArgumentGroup = `(?:` + reHost + `|` + reRegex + `|` + reDomain + `|` + reStartEndDefined + `)`
	reEntry         = `^` + reCommentGroup + `|` + reException + reArgumentGroup + reFilterParams + reDOMFilter + `$`
	/// regex for protocol+subdomain parsing from URL (used in double pipe case)
	reProtocolSubdomain = `^(?:[\w-+.]+://)?(?:(?:` + reURLPart + `)\.)*$`
)

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

var flagToString = map[int]string{flagException: "Exception", flagPipeStart: "Start anchor", flagPipeEnd: "End anchor",
	flagDoublePipe: "Domain name anchor", flagSeparator: "Separator", flagWildCard: "Wildcard"}

var (
	pEntry             = regexp.MustCompile(reEntry)
	pProtocolSubdomain = regexp.MustCompile(reProtocolSubdomain)
)

var (
	vaultDir      string
	assetFilename string
)

// UBlockHelper -- object to use in superior layers.
type UBlockHelper struct {
	m sync.Mutex
	d *graph.Dawg
}

/// UBlockHelper convenience exports

// Deserialize -- Deserializes the graph
func (u *UBlockHelper) Deserialize(enc []byte) *UBlockHelper {
	go func() {
		u.m.Lock()
		defer u.m.Unlock()
		u.d = graph.Deserialize(enc, nil, &ubPayload{})
		if u.d == nil {
			/// log the error
		}
	}()

	return u
}

// Search -- returns true if networking should block request, false otherwise
func (u *UBlockHelper) Search(URL string) (bool, error) {
	u.m.Lock()
	defer u.m.Unlock()
	if u.d == nil {
		return false, fmt.Errorf("graph is not initialized")
	}
	for i := range URL {
		result := u.d.ExactLookupWithPayloadAndSeparator(URL[i:])
		if result.MatchStatus == graph.MatchNotFound {
			continue
		}
		/// verify the result
		/// no payload -> no constraint over match, return true
		if result.Payload == nil {
			return true, nil
		}
		/// evaluate the payload
		log("We have a loaded match with [%s][%s]\n", result.Remainder, result.Payload.(*ubPayload).String())
		if !result.Payload.(*ubPayload).Evaluate(result.Remainder) {
			continue
		}

		flg := result.Payload.(*ubPayload).flags
		/// exception -> permitting access
		if flg&flagException > 0 {
			return false, nil
		}
		/// check flag constraints vs match
		/// absolute start/end of URL
		if (flg&flagPipeStart > 0 && i != 0) || (flg&flagPipeEnd > 0 && result.Remainder != "") {
			continue
		}
		/// domain name start
		if flg&flagDoublePipe > 0 {
			if pProtocolSubdomain.MatchString(URL[:i]) == false {
				continue
			}
		}
		/// no constrain stuck, no choice but to return true
		return true, nil
	}
	return false, nil
}

/// search, using debug payloads (TODO: add interface type checking to UBlockHelper functions, and ubDebugPayload encode/decode implementation)
func plainSearch(d *graph.Dawg, URL string) (bool, error) {
	if d == nil {
		return false, fmt.Errorf("Graph is not initialized.")
	}
	for i := range URL {
		result := d.ExactLookupWithPayloadAndSeparator(URL[i:])
		if result.MatchStatus == graph.MatchNotFound {
			continue
		}
		/// verify the result
		/// no payload -> no constraint over match, return true
		if result.Payload == nil {
			return true, nil
		}
		/// evaluate the payload
		log("We have a loaded match with [%s][%s]\n", result.Remainder, result.Payload.(*ubDebugPayload).String())
		if !result.Payload.(*ubDebugPayload).Evaluate(result.Remainder) {
			continue
		}

		flg := result.Payload.(*ubDebugPayload).flags
		/// exception -> permitting access
		if flg&flagException > 0 {
			return false, nil
		}
		/// check flag constraints vs match
		/// absolute start/end of URL
		if (flg&flagPipeStart > 0 && i != 0) || (flg&flagPipeEnd > 0 && result.Remainder != "") {
			continue
		}
		/// domain name start
		if flg&flagDoublePipe > 0 {
			// log("Matching regex [%s] to [%s] => [%v] [%v]\n", pProtocolSubdomain.String(), URL[:i], pProtocolSubdomain.MatchString(URL[:i]), pProtocolSubdomain.FindStringSubmatch(URL[:i]))
			if dom := pProtocolSubdomain.FindStringSubmatch(URL[:i]); dom != nil && len(dom) > 0 && strings.Compare(dom[0], URL[:i]) == 0 {
				continue
			}
		}
		/// no constrain stuck, no choice but to return true
		return true, nil
	}
	return false, nil
}

/// implement sort functions for graph input
func (s sortableGraphInput) Len() int {
	return len(s)
}

func (s sortableGraphInput) Less(i, j int) bool {
	if s[i].token < s[j].token {
		return true
	}
	return false
}

func (s sortableGraphInput) Swap(i, j int) {
	temp := s[i]
	s[i] = s[j]
	s[j] = temp
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

// Init - initialize for the export side of operations, do not use in client application (for filtering)
func Init(filterCacheDir, assetName string) error {
	if filterCacheDir == "" || assetName == "" {
		return fmt.Errorf("unable to work with empty files or directories")
	}

	vaultDir = filterCacheDir
	assetFilename = assetName
	log("Using regex [%s]\n\n", pEntry.String())
	fil, e := ioutil.ReadDir(vaultDir)
	if e != nil {
		log("readdir err [%s]", e.Error())
		return e
	}
	/// read cached files
	for _, fi := range fil {
		if fi.IsDir() == true {
			continue
		}
		if time.Now().Sub(fi.ModTime()) > cacheValidity {
			//os.Remove(vaultDir + fi.Name())
			continue
		}
		fileContent, e := ioutil.ReadFile(vaultDir + fi.Name())
		if e != nil {
			log("Error reading file [%s] -- [%s]\n", fi.Name(), e.Error())
			continue
		}
		cachedAssets[fi.Name()] = string(fileContent)
	}
	return nil
}

/// fetches (cache/network) a filter file
func fetchText(url string) (string, error) {
	fnameURL := strings.Replace(url, "/", "_", -1)
	fnameURL = strings.Replace(fnameURL, ":", "_", -1)
	if content, ok := cachedAssets[fnameURL]; ok {
		// log("Returning from cache for [%s].\n", url)
		readBytes += int64(len(content))
		return content, nil
	}
	// log("Downloading asset for [%s].\n", url)
	r, e := http.Get(url)
	if e != nil {
		return "", fmt.Errorf("cannot GET [%s]", e.Error())
	}
	downloadedBytes += r.ContentLength
	readBytes += r.ContentLength
	defer r.Body.Close()
	text, e := ioutil.ReadAll(r.Body)
	if e != nil {
		return "", fmt.Errorf("cannot read response [%s]", e.Error())
	}
	if e := ioutil.WriteFile(vaultDir+fnameURL, text, 0755); e != nil {
		log("Cannot cache entry [%s] -- [%s]\n", url, e.Error())
	}
	return string(text), nil
}

func constructAssetList() error {
	assetsJSON, e := fetchText(uBlockAssets)
	if e != nil {
		return e
	}
	assets := make(map[string]assetItem)
	if e := json.Unmarshal([]byte(assetsJSON), &assets); e != nil {
		return fmt.Errorf("cannot unmarshal json [%s]", e.Error())
	}
	for name, a := range assets {
		/// read everything except internal assets, and region specific assets
		if a.Content != "filters" || a.Group == "regions" {
			continue
		}

		// log("\t[%s]-[%s][%s][%s][%s]\n", name, a.Title, a.Content, a.Group, a.ContentURL)
		if ustrslice, ok := a.ContentURL.([]interface{}); ok {
			for _, u := range ustrslice {
				/// use only https links
				if ustr, ok := u.(string); ok && strings.HasPrefix(ustr, "https://") {
					al := &assetListItem{name: name, content: a.Content, group: a.Group, contentURL: ustr}
					assetList = append(assetList, al)
				}
			}
		}
	}

	return nil
}

func parseLine(line string) (r *rawGraphElement, e error) {
	tokens := pEntry.FindStringSubmatch(line)

	/// check for full match, as in the whole pattern is matched, aka use only the formats supported
	if tokens == nil {
		return nil, fmt.Errorf("unrecognized format [%s]", line)
	}
	if tokens[0] == "" {
		return nil, fmt.Errorf("unhandled format [%s]", line)
	}

	/// can't handle fine grained filters as of yet
	if tokens[9] != "" {
		return nil, fmt.Errorf("cannot handle options [%s]", tokens[9])
	}

	if tokens[10] != "" {
		return nil, fmt.Errorf("cannot handle DOM alteration")
	}

	r = &rawGraphElement{}

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
	return r, nil
}

func constructFilter() (ret sortableGraphInput, e error) {
	assetText := ""
	var lineEndToken string
	var g *rawGraphElement
	ret = make(sortableGraphInput, 0)
	for _, a := range assetList {
		lineEndToken = "\n"
		log("Loading ASSET [%s][%s]\n", a.name, a.contentURL)
		if assetText, e = fetchText(a.contentURL); e != nil {
			log("Cannot load asset [%s] - [%s]\n", a.name, e.Error())
			continue
		}
		if strings.Contains(assetText, "\r\n") {
			lineEndToken = "\r\n"
		}
		lines := strings.Split(assetText, lineEndToken)
		//log("[%s][%s][%s]\n\t[%s]\n", a.name, a.content, a.contentURL, lines[0])
		for i, l := range lines {
			if len(l) == 0 {
				continue
			}
			if g, e = parseLine(l); e != nil && g != nil && !strings.HasPrefix(e.Error(), "cannot handle options") {
				log("Parse error :: [%s:%s][%d] `%s`\n", a.name, a.contentURL, i+1, e.Error())
				continue
			}

			if g != nil && g.token != "" {
				if g.flags&flagWildCard > 0 {
					temp := strings.Split(g.token, "*")
					if len(temp) >= 2 {
						g.token = temp[0]
						g.suffix = strings.Join(temp[1:], "*")
					}
				}
				g.filter = a.name
				ret = append(ret, g)
			}
		}
	}

	hackyDeduplicator := map[string]*rawGraphElement{}

	for _, e := range ret {
		hackyDeduplicator[e.token] = e
	}

	uniqueRet := sortableGraphInput{}
	charCount, wcCount := 0, 0
	for _, v := range hackyDeduplicator {
		uniqueRet = append(uniqueRet, v)
		charCount += len(v.token)
		wcCount += len(v.suffix)
	}

	log("Overall downloaded [%d]KB of data.\n", downloadedBytes/1024)
	log("Filter set is [%d]KB.\n", readBytes/1024)
	log("Sorting tokens for graph input.\n")
	sort.Sort(uniqueRet)

	for _, elem := range uniqueRet {
		if elem.suffix == "" {
			continue
		}
		/// escape meta chars
		elem.suffix = regexp.QuoteMeta(elem.suffix)
		elem.suffix = strings.Replace(elem.suffix, "/", "\\/", -1)
		/// if there's a wildcard, expand it into it's regex form (* -> .*)
		if ind := strings.Index(elem.suffix, "*"); ind != -1 {
			elem.suffix = strings.Replace(elem.suffix, "\\*", ".*", -1)
		}

		/// expand the separator into it's regex form (^ -> [\/:?=&])
		if elem.flags&flagSeparator > 0 {
			elem.suffix = strings.Replace(elem.suffix, "\\^", `[\/:?=&]`, -1)
		}
	}

	log("Okay. Trying to construct word graph. Stand by.\n")
	d := graph.NewDawg()
	for _, input := range uniqueRet {
		if compileDebugAsset {
			d.Insert(input.token, &ubDebugPayload{ubPayload: &ubPayload{flags: input.flags, suffix: input.suffix}, list: input.filter, original: input.original})
		} else if input.flags != 0 {
			d.Insert(input.token, &ubPayload{flags: input.flags, suffix: input.suffix})
		} else {
			d.Insert(input.token, nil)
		}
	}
	d.Finish()
	log("Constructed. [%d] and [%d] are the stats, out of [%d]/[%d] characters\n", d.EdgeCount(), d.NodeCount(), charCount, wcCount)
	log("Flushing graph asset to %s\n", assetFilename)
	c := d.Serialize(assetFilename)

	test := UBlockHelper{}
	test.Deserialize(c)
	time.Sleep(2 * time.Second)
	tests := []string{
		"&ctxId=",
		"&ctxId=asd&pubId=qwe&objId=zxc",
		"shoudntmmatch",
		".com/js/ga-123qweasd^.js"}
	for _, t := range tests {
		st := time.Now()
		ret, _ := test.Search(t)
		log("Test is [%v] -- [%v] [%s]\n", time.Now().Sub(st), ret, t) //graph.MatchStatusToString[res.MatchStatus], res.Remainder, res.Payload)
	}

	return uniqueRet, nil
}

// AssembleRuleDatabase - called construction-time on an initialized package to construct, and export uBlock graph asset
func AssembleRuleDatabase() (e error) {
	if e = constructAssetList(); e != nil {
		return e
	}
	_, e = constructFilter()
	if e != nil {
		return e
	}
	return nil
}
