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

	rcconf "github.com/systemd/systemd/src/go/rc-conf"
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

//export GenerateRCConf
func GenerateRCConf() {
	config := rcconf.ParseConfig()
	rcconf.Enable(&config)
}
