package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
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

	issuer *pkix.RDNSequence
	trustSettings map[string]string
}
func (c *certTrust) String() string {
	return fmt.Sprintf(`hash=%v issuer=%q trustSettings=%#v`, c.hash[:8], c.issuer, c.trustSettings)
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
			for k := range plist.Dict[i].Dict[j].Dict {
				dict := plist.Dict[i].Dict[j].Dict[k]

				item := &certTrust{
					hash: hashes[j].Text,
					trustSettings: make(map[string]string, 0),
				}
				items = append(items, item)

				for l := range dict.Key {
					switch dict.Key[l].Text {

					case "issuerName":
						issuer, err := parseIssuerName(dict.Data[0].Text)
						if err != nil {
							panic(err)
						}
						item.issuer = issuer

					case "trustSettings":
						err := parseTrustSettings(item, dict)
						if err != nil {
							panic(err)
						}
					}
				}
				fmt.Printf("%s\n\n", item.String())
			}
		}
	}
	fmt.Printf("found %d items\n", len(items))
}

// <key>issuerName</key>
// <data>
// MG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRUcnVzdCBBQjEm
// MCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx
// IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3Q=
// </data>
func parseIssuerName(value string) (*pkix.RDNSequence, error) {
	raw := whitespaceReplacer.Replace(nonContentRegex.ReplaceAllString(value, ""))
	data, _ := base64.StdEncoding.DecodeString(raw)

	// The issuerName's <data></data> block is only under asn1 encoding for the
	// issuerName field from 4.1.2.4 (https://tools.ietf.org/rfc/rfc5280)
	name := pkix.Name{}
	var issuer pkix.RDNSequence
	_, err := asn1.Unmarshal(data, &issuer)
	if err == nil {
		name.FillFromRDNSequence(&issuer)
	}
	return &issuer, err
}

// <key>trustSettings</key>
// <array>
//     <dict>
// 	<key>kSecTrustSettingsResult</key>
// 	<integer>4</integer>
//     </dict>
// </array>
func parseTrustSettings(item *certTrust, dict *Dict) error {
	for l := range dict.Array.Dict {
		for m := range dict.Array.Dict[l].Key {
			key := dict.Array.Dict[l].Key[m].Text
			switch key {
			case "kSecTrustSettingsResult":
				if len(dict.Array.Dict) >= l+1 {
					value := dict.Array.Dict[l].Integer[0].Text
					item.trustSettings[key] = value
				}

			case "kSecTrustSettingsPolicyName":
				if len(dict.Array.Dict) >= l+1 {
					value := dict.Array.Dict[l].String.Text
					item.trustSettings[key] = value
				}
			}
		}
	}
	return nil
}
