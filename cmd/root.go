package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ECYCloud/XrayR/panel"
)

// currentLogWriter 保存当前的 lumberjack 实例，用于热重载时关闭旧实例和进程退出时刷盘。
var currentLogWriter *lumberjack.Logger

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use: "XrayR",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(); err != nil {
				log.Fatal(err)
			}
		},
	}
)

func init() {
	// Configure global logger time format.
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006/01/02 15:04:05.000000",
	})

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file for XrayR.")
}

func getConfig() *viper.Viper {
	config := viper.New()

	// Set custom path and name
	if cfgFile != "" {
		configName := path.Base(cfgFile)
		configFileExt := path.Ext(cfgFile)
		configNameOnly := strings.TrimSuffix(configName, configFileExt)
		configPath := path.Dir(cfgFile)
		config.SetConfigName(configNameOnly)
		config.SetConfigType(strings.TrimPrefix(configFileExt, "."))
		config.AddConfigPath(configPath)
		// Set ASSET Path and Config Path for XrayR
		os.Setenv("XRAY_LOCATION_ASSET", configPath)
		os.Setenv("XRAY_LOCATION_CONFIG", configPath)
	} else {
		// Set default config path
		config.SetConfigName("config")
		config.SetConfigType("yml")
		config.AddConfigPath(".")

	}

	if err := config.ReadInConfig(); err != nil {
		log.Panicf("Config file error: %s \n", err)
	}

	config.WatchConfig() // Watch the config

	return config
}

func run() error {
	showVersion()

	config := getConfig()
	panelConfig := &panel.Config{}
	if err := config.Unmarshal(panelConfig); err != nil {
		return fmt.Errorf("Parse config file %v failed: %s \n", cfgFile, err)
	}

	if panelConfig.LogConfig != nil && panelConfig.LogConfig.Level == "debug" {
		log.SetReportCaller(true)
	}

	// 配置日志输出到文件并自动轮转
	setupLogOutput(panelConfig)
	defer closeLogWriter()

	// Create initial panel instance.
	p := panel.New(panelConfig)
	lastTime := time.Now()

	config.OnConfigChange(func(e fsnotify.Event) {
		// Discarding event received within a short period of time after receiving an event.
		if !time.Now().After(lastTime.Add(3 * time.Second)) {
			return
		}

		// Hot reload function
		log.Infof("Config file changed: %s", e.Name)

		// 为了避免因为临时写入/语法错误导致的“空配置”把正在运行的服务全部停掉，
		// 这里先用一个全新的 viper 实例完整读取并解析最新的配置文件，只在解析
		// 成功且包含有效 Nodes 时才切换面板实例。
		newPanelConfig := &panel.Config{}
		newViper := viper.New()
		if e.Name != "" {
			newViper.SetConfigFile(e.Name)
		} else if cfgFile != "" {
			newViper.SetConfigFile(cfgFile)
		} else {
			// 退回到与 getConfig 相同的查找逻辑
			newViper.SetConfigName("config")
			newViper.SetConfigType("yml")
			newViper.AddConfigPath(".")
		}

		if err := newViper.ReadInConfig(); err != nil {
			log.Errorf("Hot reload: failed to read new config file %s: %v; keeping existing configuration", e.Name, err)
			return
		}
		if err := newViper.Unmarshal(newPanelConfig); err != nil {
			log.Errorf("Hot reload: failed to parse new config file %s: %v; keeping existing configuration", e.Name, err)
			return
		}
		if len(newPanelConfig.NodesConfig) == 0 {
			log.Warnf("Hot reload: new config file %s contains no Nodes; ignoring reload to avoid stopping running services", e.Name)
			return
		}

		// 到这里说明新配置已经成功解析，且包含有效的节点；再关闭旧实例并切换。
		p.Close()
		// Delete old instance and trigger GC
		runtime.GC()

		if newPanelConfig.LogConfig != nil && newPanelConfig.LogConfig.Level == "debug" {
			log.SetReportCaller(true)
		} else {
			log.SetReportCaller(false)
		}

		// 热重载时更新日志输出配置
		setupLogOutput(newPanelConfig)

		// Swap to the new config and panel instance.
		panelConfig = newPanelConfig
		p = panel.New(panelConfig)

		p.Start()
		lastTime = time.Now()
	})

	p.Start()
	defer p.Close()

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()
	// Running backend
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
	<-osSignals

	return nil
}

func Execute() error {
	return rootCmd.Execute()
}

// setupLogOutput 根据配置将 logrus 输出到文件并启用自动轮转。
// 如果 LogPath 为空，则保持默认的 stdout 输出。
// 该函数可安全地被多次调用（热重载），会自动关闭旧的 lumberjack 实例。
func setupLogOutput(panelConfig *panel.Config) {
	if panelConfig.LogConfig == nil || panelConfig.LogConfig.LogPath == "" {
		// LogPath 为空时回退到 stdout（兼容旧配置）
		if currentLogWriter != nil {
			log.SetOutput(os.Stdout)
			currentLogWriter.Close()
			currentLogWriter = nil
			log.Info("LogPath is empty, log output reset to stdout")
		}
		return
	}

	logPath := panelConfig.LogConfig.LogPath

	// 确保日志目录存在
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Errorf("Failed to create log directory %s: %v, falling back to stdout", logDir, err)
		return
	}

	// 默认值
	maxSize := panelConfig.LogConfig.MaxSize
	if maxSize <= 0 {
		maxSize = 100 // 默认单个日志文件最大 100MB
	}
	maxDays := panelConfig.LogConfig.MaxDays
	if maxDays <= 0 {
		maxDays = 3 // 默认保留 3 天
	}
	maxBackups := panelConfig.LogConfig.MaxBackups
	if maxBackups <= 0 {
		maxBackups = 3 // 默认保留 3 个备份
	}

	newWriter := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    maxSize,
		MaxAge:     maxDays,
		MaxBackups: maxBackups,
		LocalTime:  true,
		Compress:   true,
	}

	// 验证日志文件可写
	if _, err := newWriter.Write(nil); err != nil {
		log.Errorf("Failed to open log file %s: %v, falling back to stdout", logPath, err)
		newWriter.Close() // 避免文件句柄泄漏
		return
	}

	// 关闭旧的 lumberjack 实例（热重载场景）
	if currentLogWriter != nil {
		currentLogWriter.Close()
	}

	// 只写文件，不再写 stdout。
	// 这是解决 syslog 爆盘的关键：stdout → systemd → syslog 的链路被切断。
	log.SetOutput(newWriter)
	currentLogWriter = newWriter

	log.Infof("Log output to file: %s (maxSize=%dMB, maxDays=%d, maxBackups=%d)", logPath, maxSize, maxDays, maxBackups)
}

// closeLogWriter 关闭当前的 lumberjack 实例，确保日志刷盘。
// 应在进程退出时通过 defer 调用。
func closeLogWriter() {
	if currentLogWriter != nil {
		currentLogWriter.Close()
		currentLogWriter = nil
	}
}
