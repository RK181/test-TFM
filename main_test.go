package main

import (
	"test/utils"
	"testing"
)

func TestMain(t *testing.T) {
	expected := "hello world"
	result := utils.HelloWorld()

	if result != expected {
		t.Errorf("Expected %q, but got %q", expected, result)
	}
}