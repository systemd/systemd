package main

/*
#include <stdint.h>
struct DemoStruct {
    uint8_t A;
    int32_t B;
};
*/

import (
	"C"
	"fmt"
	"runtime/debug"
)

func main() {}

//export GoBuildVersion
func GoBuildVersion() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	fmt.Printf("Version: %s\n", bi.Main.Version)
}
