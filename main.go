package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	plistModDateFormat = "2006-01-02T15:04:05Z"

	nonContentRegex    = regexp.MustCompile(`[^a-zA-Z0-9\+\/=]*`)
	whitespaceReplacer = strings.NewReplacer("\t", "", "\n", "", " ", "", "\r", "")

	flagDirectory = flag.String("directory", "./examples/", "Directory of files to parse")
)

// Generated with github.com/gnewton/chidley
//
// chidley -X after2 >> main.go

type ChiChidleyRoot314159 struct {
	Chiplist *Chiplist `xml:"plist,omitempty" json:"plist,omitempty"`
}

type Chiplist struct {
	Attrversion string`xml:"version,attr"  json:",omitempty"`
	Chidict []*Chidict `xml:"dict,omitempty" json:"dict,omitempty"`
}

type Chidict struct {
	Chiarray *Chiarray `xml:"array,omitempty" json:"array,omitempty"`
	Chidata []*Chidata `xml:"data,omitempty" json:"data,omitempty"`
	Chidate *Chidate `xml:"date,omitempty" json:"date,omitempty"`
	Chidict []*Chidict `xml:"dict,omitempty" json:"dict,omitempty"`
	Chiinteger []*Chiinteger `xml:"integer,omitempty" json:"integer,omitempty"`
	Chikey []*Chikey `xml:"key,omitempty" json:"key,omitempty"`
	Chistring *Chistring `xml:"string,omitempty" json:"string,omitempty"`
}

type Chikey struct {
	Text string `xml:",chardata" json:",omitempty"`
}

type Chidata struct {
	Text string `xml:",chardata" json:",omitempty"`
}

type Chidate struct {
	Text string `xml:",chardata" json:",omitempty"`
}

type Chiarray struct {
	Chidict []*Chidict `xml:"dict,omitempty" json:"dict,omitempty"`
}

type Chiinteger struct {
	Text string `xml:",chardata" json:",omitempty"`
}

type Chistring struct {
	Text string `xml:",chardata" json:",omitempty"`
}

func main() {
	fds, err := ioutil.ReadDir(*flagDirectory)
	if err != nil {
		panic(err)
	}

	for i := range fds {
		parse(filepath.Join(*flagDirectory, fds[i].Name()))
	}
}

func parse(where string) {
	fmt.Printf("parsing %s\n", where)

	bs, err := ioutil.ReadFile(where)
	if err != nil {
		panic(err)
	}

	plist := Chiplist{}
	err = xml.Unmarshal(bs, &plist)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+#v\n", plist)
	for i := range plist.Chidict {
		fmt.Println("key")
		if plist.Chidict[i].Chikey != nil {
			for j := range plist.Chidict[i].Chikey {
				fmt.Printf("  %s\n", plist.Chidict[i].Chikey[j].Text)
			}
		}
		fmt.Println("dict")

		// <key>02FAF3E291435468607857694DF5E45B68851868</key>
		// <dict>
		//   ...
		// </dict>
		hashes := plist.Chidict[i].Chidict[0].Chikey
		fmt.Printf("found %d hashes\n", len(hashes))

		for j := range plist.Chidict[i].Chidict {
			hash := hashes[j]
			fmt.Printf("hash=%#v\n", hash.Text)
			dict := plist.Chidict[i].Chidict[j].Chidict
			for k := range dict {

				// <key>issuerName</key>
				// <data>
				// MG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRUcnVzdCBBQjEm
				// MCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx
				// IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3Q=
				// </data>
				if dict[k].Chikey[0].Text == "issuerName" {
					raw := whitespaceReplacer.Replace(nonContentRegex.ReplaceAllString(dict[k].Chidata[0].Text, ""))
					data, _ := base64.StdEncoding.DecodeString(raw)

					// The issuerName's <data></data> block is only under asn1 encoding for the
					// issuerName field from 4.1.2.4 (https://tools.ietf.org/rfc/rfc5280)
					name := pkix.Name{}
					var issuer pkix.RDNSequence
					_, err := asn1.Unmarshal(data, &issuer)
					if err == nil {
						name.FillFromRDNSequence(&issuer)
					}
					fmt.Printf("Issuer: %s\n", name)
				}

				// <key>modDate</key>
				// <date>2018-02-20T02:13:51Z</date>
				if dict[k].Chikey[1].Text == "modDate" {
					raw := dict[k].Chidate.Text // e.g. <date>2018-02-20T02:11:28Z</date>
					t, err := time.ParseInLocation(plistModDateFormat, raw, time.UTC)
					if err != nil {
						panic(err)
					}
					fmt.Printf("modDate: %v\n", t)
				}

				// <key>serialNumber</key>
				// <data>
				// AQ==
				// </data>
				if dict[k].Chikey[2].Text == "serialNumber" {
					raw := whitespaceReplacer.Replace(nonContentRegex.ReplaceAllString(dict[k].Chidata[1].Text, ""))
					data, _ := base64.StdEncoding.DecodeString(raw)

					serial := big.NewInt(0)
					serial.SetBytes(data)

					fmt.Printf("serialNumber: %v\n", serial)
				}

				// <key>trustSettings</key>
				// <array>
				//     <dict>
				// 	<key>kSecTrustSettingsResult</key>
				// 	<integer>4</integer>
				//     </dict>
				// </array>
				if len(dict) > k &&
					len(dict[k].Chikey) > 3 &&
					dict[k].Chikey[3].Text == "trustSettings" {
					for l := range dict[k].Chiarray.Chidict {
						// fmt.Println(dict[k].Chiarray.Chidict[l].Chikey[0].Text)
						if key := dict[k].Chiarray.Chidict[l].Chikey[0].Text; key == "kSecTrustSettingsResult" {
							if len(dict[k].Chiarray.Chidict) >= l+1 {
								value := dict[k].Chiarray.Chidict[l].Chiinteger[0].Text
								fmt.Printf("%s = %v\n", key, value)
							}
						}

						if len(dict[k].Chiarray.Chidict[l].Chikey) >= 3 {
							if key := dict[k].Chiarray.Chidict[l].Chikey[2].Text; key == "kSecTrustSettingsPolicyName" {
								if len(dict[k].Chiarray.Chidict) >= l+1 {
									value := dict[k].Chiarray.Chidict[l].Chistring.Text
									fmt.Printf("%s = %v\n", key, value)
								}
							}
						}
					}
				}

				fmt.Printf("\n")
			}
		}
	}
}
