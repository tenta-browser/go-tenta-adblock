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

package main

import (
	"flag"
	"fmt"

	adblock "github.com/tenta-browser/go-tenta-adblock"
)

var (
	fVault          = flag.String("vault", "./ubvault/", "Vault folder for intermediary filter list downloads")
	fCustomUpstream = flag.String("customurl", "", "custom url from where an easylist can be downloaded for compile")
	fOutput         = flag.String("output", "./ublock.bin", "Output name and path of the asset")
	fIOS            = flag.Bool("ios", false, "Export in iOS Content Filter JSON format")
)

func main() {
	flag.Parse()

	cfg := adblock.DefaultConfig()
	if len(*fCustomUpstream) > 0 {
		cfg.SetCustomUrl(*fCustomUpstream)
	}

	if e := adblock.Init(*fVault, cfg); e != nil {
		fmt.Printf("build failed.: %s\n", e.Error())
	}

	if e := adblock.Build(*fOutput, *fIOS); e != nil {
		fmt.Printf("build failed.: %s\n", e.Error())
	}
}
