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

package log

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/natefinch/lumberjack"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	defaultFilename   = "./gcp.log"
	defaultMaxSize    = 10
	defaultMaxBackups = 5
	defaultMaxAge     = 30
	defaultCompress   = false
	defaultLevel      = "info"
	defaultFormat     = "string"
	defaultOutput     = ""
)

var sugaredLogger *Logger
var once sync.Once

var logLevel = zap.NewAtomicLevel()

// Logger is a wrapper for the uber/zap logging library.
type Logger struct {
	logger *zap.SugaredLogger

	// Filename is the log file path.
	Filename string `fig:"filename"`

	// MaxSize is maximum size of the log file, in MB.
	MaxSize int `fig:"maxSize"`

	// MaxBackups is maximum number of log file backups.
	MaxBackups int `fig:"maxBackups"`

	// MaxAge is maximum retention time for log files, in days.
	MaxAge int `fig:"maxAge"`

	// If true, compress log file. Default false.
	Compress bool `fig:"compress"`

	// Log level. Support 'debug', 'info', 'warn', 'error'.
	Level string `fig:"level"`

	// Log format. Support 'json', 'string'.
	Format string `fig:"format"`

	// Output method.
	// If set to file, logs will be output to a file.
	// If set to file, the Filename cannot be empty.
	Output string `fig:"output"`
}

func (l *Logger) Sync() {
	l.logger.Sync()
}

func (l *Logger) WithField(key, val string) *Logger {
	logger := l.logger.With(zap.String(key, val))

	return &Logger{logger: logger}
}

func (l *Logger) Debug(args ...interface{}) {
	l.logger.Debug(args...)
}

func (l *Logger) Debugf(template string, args ...interface{}) {
	l.logger.Debugf(template, args...)
}

func (l *Logger) Debugw(msg string, args ...interface{}) {
	l.logger.Debugw(msg, args...)
}

func (l *Logger) Info(args ...interface{}) {
	l.logger.Info(args...)
}

func (l *Logger) Infof(template string, args ...interface{}) {
	l.logger.Infof(template, args...)
}

func (l *Logger) Infow(msg string, args ...interface{}) {
	l.logger.Infow(msg, args...)
}

func (l *Logger) Warn(args ...interface{}) {
	l.logger.Warn(args...)
}

func (l *Logger) Warnf(template string, args ...interface{}) {
	l.logger.Warnf(template, args...)
}

func (l *Logger) Warnw(msg string, args ...interface{}) {
	l.logger.Warnw(msg, args...)
}

func (l *Logger) Error(args ...interface{}) {
	l.logger.Error(args...)
}

func (l *Logger) Errorf(template string, args ...interface{}) {
	l.logger.Errorf(template, args...)
}

func (l *Logger) Errorw(msg string, args ...interface{}) {
	l.logger.Errorw(msg, args...)
}

func (l *Logger) Fatal(args ...interface{}) {
	l.logger.Fatal(args...)
}

func (l *Logger) Fatalf(template string, args ...interface{}) {
	l.logger.Fatalf(template, args...)
}

func (l *Logger) Fatalw(msg string, args ...interface{}) {
	l.logger.Fatalw(msg, args...)
}

func (l *Logger) SetFormat(format string) {
	l.Format = format
	l.setZapLogger()
}

func (l *Logger) initLogger() {
	l.setDefaultValues()
	l.setLevel()
	l.setZapLogger()
}

func (l *Logger) setZapLogger() {
	writeSyncer := l.getLogWriter()
	encoder := l.getEncoder()
	core := zapcore.NewCore(encoder, writeSyncer, logLevel)

	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	l.logger = logger.Sugar()
}

func (l *Logger) setDefaultValues() {
	l.Filename = defaultFilename
	l.MaxSize = defaultMaxSize
	l.MaxBackups = defaultMaxBackups
	l.MaxAge = defaultMaxAge
	l.Compress = defaultCompress
	l.Level = defaultLevel
	l.Format = defaultFormat
	l.Output = defaultOutput
}

func (l *Logger) setLevel() {
	switch l.Level {
	case "debug":
		logLevel.SetLevel(zapcore.Level(zapcore.DebugLevel))
	case "info":
		logLevel.SetLevel(zapcore.Level(zapcore.InfoLevel))
	case "warn":
		logLevel.SetLevel(zapcore.Level(zapcore.WarnLevel))
	case "error":
		logLevel.SetLevel(zapcore.Level(zapcore.ErrorLevel))
	default:
		logLevel.SetLevel(zapcore.Level(zapcore.InfoLevel))
	}
}

func (l *Logger) getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	if l.Format == "json" {
		return zapcore.NewJSONEncoder(encoderConfig)
	}
	return zapcore.NewConsoleEncoder(encoderConfig)
}

func (l *Logger) getLogWriter() zapcore.WriteSyncer {
	if l.Output == "file" {
		lumberJackLogger := &lumberjack.Logger{
			Filename:   l.Filename,
			MaxSize:    l.MaxSize,
			MaxBackups: l.MaxBackups,
			MaxAge:     l.MaxAge,
			Compress:   l.Compress,
		}
		return zapcore.AddSync(lumberJackLogger)
	}

	return zapcore.AddSync(zapcore.Lock(os.Stdout))
}

func AddGlobalFlags(fs *pflag.FlagSet, name string) {
	// set flags
	addLoggerFlags(fs)

	fs.BoolP("help", "h", false, fmt.Sprintf("help for %s", name))
}

// InitLogger: Initializes the sugaredLogger.
// Usage:
// Call in the main function as follows:
//
// logger := log.InitLogger()
// defer logger.Sync()
func InitLogger() *Logger {
	sugaredLogger = initLogger()

	sugaredLogger.logger.Debugf("sugaredLogger: %#v\n", sugaredLogger)

	return sugaredLogger
}

func initLogger() *Logger {
	sugaredLogger.setLevel()

	writeSyncer := sugaredLogger.getLogWriter()
	encoder := sugaredLogger.getEncoder()
	core := zapcore.NewCore(encoder, writeSyncer, logLevel)

	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	sugaredLogger.logger = logger.Sugar()

	return sugaredLogger
}

// addKlogFlags adds flags from logger
func addLoggerFlags(fs *pflag.FlagSet) {
	local := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	initFlags(local)
	normalizeFunc := fs.GetNormalizeFunc()
	local.VisitAll(func(fl *flag.Flag) {
		fl.Name = string(normalizeFunc(fs, fl.Name))
		fs.AddGoFlag(fl)
	})
}

func initFlags(flagset *flag.FlagSet) {
	if flagset == nil {
		flagset = flag.CommandLine
	}

	flagset.StringVar(&sugaredLogger.Filename, "log-filename", sugaredLogger.Filename, "Filename is the log file path.")
	flagset.IntVar(&sugaredLogger.MaxSize, "log-max-size", sugaredLogger.MaxSize, "MaxSize is maximum size of the log file, in MB.")
	flagset.IntVar(&sugaredLogger.MaxBackups, "log-max-backups", sugaredLogger.MaxBackups, "MaxBackups is maximum number of log file backups.")
	flagset.IntVar(&sugaredLogger.MaxAge, "log-max-age", sugaredLogger.MaxAge, "MaxAge is maximum retention time for log files, in days.")
	flagset.BoolVar(&sugaredLogger.Compress, "log-compress", sugaredLogger.Compress, "If true, compress log file. Default false.")
	flagset.StringVar(&sugaredLogger.Level, "log-level", sugaredLogger.Level, "Log level. Support 'debug', 'info', 'warn', 'error'.")
	flagset.StringVar(&sugaredLogger.Format, "log-format", sugaredLogger.Format, "Log format. Support 'json', 'string'.")
	flagset.StringVar(&sugaredLogger.Output, "log-output", sugaredLogger.Output, "Log output method. If set `file`, output in file, or output os.Stdout.")
}

func WithField(key, val string) *Logger {
	logger := sugaredLogger.logger.With(zap.String(key, val))

	return &Logger{logger: logger}
}

func Debug(args ...interface{}) {
	sugaredLogger.logger.Debug(args...)
}

func Debugf(template string, args ...interface{}) {
	sugaredLogger.logger.Debugf(template, args...)
}

func Debugw(msg string, args ...interface{}) {
	sugaredLogger.logger.Debugw(msg, args...)
}

func Info(args ...interface{}) {
	sugaredLogger.logger.Info(args...)
}

func Infof(template string, args ...interface{}) {
	sugaredLogger.logger.Infof(template, args...)
}

func Infow(msg string, args ...interface{}) {
	sugaredLogger.logger.Infow(msg, args...)
}

func Warn(args ...interface{}) {
	sugaredLogger.logger.Warn(args...)
}

func Warnf(template string, args ...interface{}) {
	sugaredLogger.logger.Warnf(template, args...)
}

func Warnw(msg string, args ...interface{}) {
	sugaredLogger.logger.Warnw(msg, args...)
}

func Error(args ...interface{}) {
	sugaredLogger.logger.Error(args...)
}

func Errorf(template string, args ...interface{}) {
	sugaredLogger.logger.Errorf(template, args...)
}

func Errorw(msg string, args ...interface{}) {
	sugaredLogger.logger.Errorw(msg, args...)
}

func Fatal(args ...interface{}) {
	sugaredLogger.logger.Fatal(args...)
}

func Fatalf(template string, args ...interface{}) {
	sugaredLogger.logger.Fatalf(template, args...)
}

func Fatalw(msg string, args ...interface{}) {
	sugaredLogger.logger.Fatalw(msg, args...)
}

func GlobalLogger() *Logger {
	return sugaredLogger
}

func SetFormat(format string) {
	sugaredLogger.Format = format
	sugaredLogger.setZapLogger()
}

func init() {
	once.Do(func() {
		sugaredLogger = &Logger{}
		sugaredLogger.initLogger()
	})
}
