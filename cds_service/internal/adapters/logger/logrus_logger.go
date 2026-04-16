/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package logger

import (
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Logrus struct{ l *logrus.Entry }

func New() *Logrus {
	base := logrus.New()
	base.SetFormatter(&logrus.JSONFormatter{})

	// Log level via env (default: info)
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		base.SetLevel(logrus.DebugLevel)
	case "warn", "warning":
		base.SetLevel(logrus.WarnLevel)
	case "error":
		base.SetLevel(logrus.ErrorLevel)
	default:
		base.SetLevel(logrus.InfoLevel)
	}

	// Default: stdout (best for containers)
	var out io.Writer = os.Stdout

	// Optional: also log to a file if LOG_FILE is set and writable
	if path := strings.TrimSpace(os.Getenv("LOG_FILE")); path != "" {
		rot := &lumberjack.Logger{
			Filename:   path,
			MaxSize:    50,
			MaxBackups: 3,
			MaxAge:     14,
			Compress:   true,
		}
		out = io.MultiWriter(os.Stdout, rot)
	}

	base.SetOutput(out)
	return &Logrus{l: logrus.NewEntry(base)}
}

func (l *Logrus) Infof(f string, a ...any)  { l.l.Infof(f, a...) }
func (l *Logrus) Errorf(f string, a ...any) { l.l.Errorf(f, a...) }
func (l *Logrus) WithField(k string, v any) *Logrus {
	return &Logrus{l: l.l.WithField(k, v)}
}

