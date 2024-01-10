// Copyright © 2024 The Endverse Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"os"

	"github.com/endverse/log/log"

	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use: "evctl",
		Run: func(cmd *cobra.Command, args []string) {
			// 2. Init Logger
			logger := log.InitLogger()
			defer logger.Sync()

			run()
		},
	}

	// 1. Set Global Flags
	log.AddGlobalFlags(cmd.PersistentFlags(), cmd.Name())

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run() {
	// 3. use default logger
	log.Debug("debug")

	// log with filed
	loggerwithuid := log.WithField("uid", "123")
	loggerwithuid.Info("hello")
	loggerwithuid.Infof("hello %s", "zhangsan")

	loggerwithname := loggerwithuid.WithField("name", "zhangsan")
	loggerwithname.Info("endverse")
}
