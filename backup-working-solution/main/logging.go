package main

import (
	"k8s.io/klog/v2"
)

type LoggingConfig struct{}

func NewLoggingConfig() *LoggingConfig {
	return &LoggingConfig{}
}

func (l *LoggingConfig) Apply() error {
	klog.InitFlags(nil)
	return nil
}
