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

type plist struct {
	Dict []*Dict `xml:"dict,omitempty"`
}

type Dict struct {
	Array *Array `xml:"array,omitempty"`
	Data []*Data `xml:"data,omitempty"`
	Date *Date `xml:"date,omitempty"`
	Dict []*Dict `xml:"dict,omitempty"`
	Integer []*Integer `xml:"integer,omitempty"`
	Key []*Key `xml:"key,omitempty"`
	String *String `xml:"string,omitempty"`
}

type Key struct {
	Text string `xml:",chardata"`
}

type Data struct {
	Text string `xml:",chardata"`
}

type Date struct {
	Text string `xml:",chardata"`
}

type Array struct {
	Dict []*Dict `xml:"dict,omitempty"`
}

type Integer struct {
	Text string `xml:",chardata"`
}

type String struct {
	Text string `xml:",chardata"`
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

type certTrust struct {
	hash string

	issuer *pkix.Name
	modDate time.Time
	serialNumber *big.Int
	trustSettings map[string]string
}
func (c *certTrust) String() string {
	return fmt.Sprintf(`hash=%v issuer=%q modDate=%q serialNumber=%d
  trustSettings=%#v`, c.hash[:8], c.issuer, c.modDate, c.serialNumber, c.trustSettings)
}

func parse(where string) {
	fmt.Printf("parsing %s\n", where)

	bs, err := ioutil.ReadFile(where)
	if err != nil {
		panic(err)
	}

	plist := plist{}
	err = xml.Unmarshal(bs, &plist)
	if err != nil {
		panic(err)
	}

	var items []*certTrust
	for i := range plist.Dict {
		// <key>02FAF3E291435468607857694DF5E45B68851868</key>
		// <dict>
		//   ...
		// </dict>
		hashes := plist.Dict[i].Dict[0].Key

		for j := range plist.Dict[i].Dict {
			dict := plist.Dict[i].Dict[j].Dict
			for k := range dict {
				item := &certTrust{
					hash: hashes[j].Text,
					trustSettings: make(map[string]string, 0),
				}
				items = append(items, item)

				// <key>issuerName</key>
				// <data>
				// MG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRUcnVzdCBBQjEm
				// MCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx
				// IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3Q=
				// </data>
				if dict[k].Key[0].Text == "issuerName" {
					raw := whitespaceReplacer.Replace(nonContentRegex.ReplaceAllString(dict[k].Data[0].Text, ""))
					data, _ := base64.StdEncoding.DecodeString(raw)

					// The issuerName's <data></data> block is only under asn1 encoding for the
					// issuerName field from 4.1.2.4 (https://tools.ietf.org/rfc/rfc5280)
					name := pkix.Name{}
					var issuer pkix.RDNSequence
					_, err := asn1.Unmarshal(data, &issuer)
					if err == nil {
						name.FillFromRDNSequence(&issuer)
					}
					// fmt.Printf("Issuer: %s\n", name)
					item.issuer = &name
				}

				// <key>modDate</key>
				// <date>2018-02-20T02:13:51Z</date>
				if dict[k].Key[1].Text == "modDate" {
					raw := dict[k].Date.Text // e.g. <date>2018-02-20T02:11:28Z</date>
					t, err := time.ParseInLocation(plistModDateFormat, raw, time.UTC)
					if err != nil {
						panic(err)
					}
					// fmt.Printf("modDate: %v\n", t)
					item.modDate = t
				}

				// <key>serialNumber</key>
				// <data>
				// AQ==
				// </data>
				if dict[k].Key[2].Text == "serialNumber" {
					raw := whitespaceReplacer.Replace(nonContentRegex.ReplaceAllString(dict[k].Data[1].Text, ""))
					data, _ := base64.StdEncoding.DecodeString(raw)

					serial := big.NewInt(0)
					serial.SetBytes(data)

					// fmt.Printf("serialNumber: %v\n", serial)
					item.serialNumber = serial
				}

				// <key>trustSettings</key>
				// <array>
				//     <dict>
				// 	<key>kSecTrustSettingsResult</key>
				// 	<integer>4</integer>
				//     </dict>
				// </array>
				if len(dict) > k &&
					len(dict[k].Key) > 3 &&
					dict[k].Key[3].Text == "trustSettings" {
					for l := range dict[k].Array.Dict {
						if key := dict[k].Array.Dict[l].Key[0].Text; key == "kSecTrustSettingsResult" {
							if len(dict[k].Array.Dict) >= l+1 {
								value := dict[k].Array.Dict[l].Integer[0].Text
								// fmt.Printf("%s = %v\n", key, value)
								item.trustSettings[key] = value
							}
						}

						if len(dict[k].Array.Dict[l].Key) >= 3 {
							if key := dict[k].Array.Dict[l].Key[2].Text; key == "kSecTrustSettingsPolicyName" {
								if len(dict[k].Array.Dict) >= l+1 {
									value := dict[k].Array.Dict[l].String.Text
									// fmt.Printf("%s = %v\n", key, value)
									item.trustSettings[key] = value
								}
							}
						}
					}
				}

				fmt.Printf("%s\n\n", item.String())
			}
		}
	}
	fmt.Printf("found %d items\n", len(items))
}
