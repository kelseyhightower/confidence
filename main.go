package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	flag.Parse()

	config := NewConfig()

	c, err := ConfigFromFile("config.json")
	if err != nil {
		log.Fatal(err)
	}
	config.Override(c)

	config.Override(ConfigFromEnv())
	config.Override(ConfigFromFlags())

	c, err = ConfigFromEtcd(config.EtcdAddr)
	if err != nil {
		log.Fatal(err)
	}
	config.Override(c)

	c, err = ConfigFromVault(config.VaultAddr, config.VaultToken)
	if err != nil {
		log.Fatal(err)
	}
	config.Override(c)

	fmt.Println("Current Config")
	fmt.Println(config)
}
