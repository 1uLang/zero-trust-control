package logs

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func Init() {

	if viper.GetBool("debug") {
		log.SetLevel(log.DebugLevel)
	}
}
