package main

// Generated with github.com/gnewton/chidley
//
// chidley -X after2 >> main.go

type ChiChidleyRoot314159 struct {
	Chiplist *Chiplist `xml:"plist,omitempty" json:"plist,omitempty"`   // ZZmaxLength=0
}

type Chiplist struct {
	Attrversion string`xml:"version,attr"  json:",omitempty"`  // maxLength=3
	Chidict []*Chidict `xml:"dict,omitempty" json:"dict,omitempty"`   // ZZmaxLength=0
}

type Chidict struct {
	Chiarray *Chiarray `xml:"array,omitempty" json:"array,omitempty"`   // ZZmaxLength=0
	Chidata []*Chidata `xml:"data,omitempty" json:"data,omitempty"`   // ZZmaxLength=0
	Chidate *Chidate `xml:"date,omitempty" json:"date,omitempty"`   // ZZmaxLength=0
	Chidict []*Chidict `xml:"dict,omitempty" json:"dict,omitempty"`   // ZZmaxLength=0
	Chiinteger []*Chiinteger `xml:"integer,omitempty" json:"integer,omitempty"`   // ZZmaxLength=0
	Chikey []*Chikey `xml:"key,omitempty" json:"key,omitempty"`   // ZZmaxLength=0
	Chistring *Chistring `xml:"string,omitempty" json:"string,omitempty"`   // ZZmaxLength=0
}

type Chikey struct {
	Text string `xml:",chardata" json:",omitempty"`   // maxLength=40
}

type Chidata struct {
	Text string `xml:",chardata" json:",omitempty"`   // maxLength=440
}

type Chidate struct {
	Text string `xml:",chardata" json:",omitempty"`   // maxLength=20
}

type Chiarray struct {
	Chidict []*Chidict `xml:"dict,omitempty" json:"dict,omitempty"`   // ZZmaxLength=0
}

type Chiinteger struct {
	Text string `xml:",chardata" json:",omitempty"`   // maxLength=11
}

type Chistring struct {
	Text string `xml:",chardata" json:",omitempty"`   // maxLength=17
}
