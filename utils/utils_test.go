package utils

import "testing"

type CopyStruct struct {
	A int    `json:"a"`
	B string `json:"b"`
}

func TestCopy(t *testing.T) {
	testInput := []CopyStruct{
		CopyStruct{A: 100, B: "hello"},
		CopyStruct{B: "hello"},
	}
	for _, c := range testInput {
		output := CopyStruct{}
		err := Copy(&output, c)
		if err != nil {
			t.Errorf("Copy error %v", err)
		}
		if output.A != c.A || output.B != c.B {
			t.Errorf("Expect %v , but got %v", c, output)
		}
	}
}
