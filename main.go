package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/helper/pluginutil"
)

func main() {
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	if err := Run(apiClientMeta.GetTLSConfig()); err != nil {
		log.Fatalln(err)
	}
}
