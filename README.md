Go uBlock
=========

[![GoDoc](https://godoc.org/github.com/tenta-browser/go-ublock?status.svg)](https://godoc.org/github.com/tenta-browser/go-ublock)

[uBlock](https://github.com/gorhill/uBlock) implementation in Golang.

Composes of asset construction, filtering, and compression/decompression primitives.
Currently supporting filter definitions without options, host files.

Support for options and cosmetic filters, DOM alteration is underway.

Contact: developer@tenta.io

Installation
============

1. `go get github.com/tenta-browser/go-ublock`

API
===

Asset generation
----------------
* `Init()`: Initialize parser
* `AssembleRuleDatabase()`: Download and parse filters, generate embeddable uBlock asset

Runtime filtering (using `UBlockHelper` struct)
-----------------
* `Deserialize()`: Reconstruct binary encoded asset into memory
* `Search()`: Search for a token (URL) for appartenance to the filtering lists

License
=======

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

For any questions, please contact developer@tenta.io

Contributing
============

We welcome contributions, feedback and plain old complaining. Feel free to open
an issue or shoot us a message to developer@tenta.io. If you'd like to contribute,
please open a pull request and send us an email to sign a contributor agreement.

About Tenta
===========

This HTTPS Everywhere Library is brought to you by Team Tenta. Tenta is your [private, encrypted browser](https://tenta.com) that protects your data instead of selling it. We're building a next-generation browser that combines all the privacy tools you need, including built-in OpenVPN. Everything is encrypted by default. That means your bookmarks, saved tabs, web history, web traffic, downloaded files, IP address and DNS. A truly incognito browser that's fast and easy.
