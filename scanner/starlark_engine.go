package scanner

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
)

type StarlarkPlugin struct {
	Name      string
	Thread    *starlark.Thread
	ProcessFn starlark.Callable
	ErrorFn   starlark.Callable
}

type StarlarkEngine struct {
	plugins []StarlarkPlugin
}

// LoadPlugins reads an entire directory and instantiates all .star scripts.
func LoadPlugins(pluginDir string) (*StarlarkEngine, error) {
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		log.Printf("Plugin directory '%s' not found. Skipping plugins.", pluginDir)
		return &StarlarkEngine{}, nil
	}

	engine := &StarlarkEngine{}
	
	err := filepath.Walk(pluginDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".star") {
			plugin, err := loadSinglePlugin(path, info.Name())
			if err != nil {
				log.Printf("[!] Failed to load plugin '%s': %v", info.Name(), err)
			} else {
				engine.plugins = append(engine.plugins, *plugin)
				log.Printf("[+] Loaded Plugin: %s", info.Name())
			}
		}
		return nil
	})

	return engine, err
}

func loadSinglePlugin(scriptPath, name string) (*StarlarkPlugin, error) {
	thread := &starlark.Thread{
		Name: name,
		Print: func(_ *starlark.Thread, msg string) {
			log.Printf("[PLUGIN:%s] %s", name, msg)
		},
	}

	globals, err := starlark.ExecFile(thread, scriptPath, nil, nil)
	if err != nil {
		return nil, err
	}

	p := &StarlarkPlugin{
		Name:   name,
		Thread: thread,
	}

	if processVal, ok := globals["process_packet"]; ok {
		if fn, isCallable := processVal.(starlark.Callable); isCallable {
			p.ProcessFn = fn
		}
	}

	if errVal, ok := globals["on_malformed_packet"]; ok {
		if fn, isCallable := errVal.(starlark.Callable); isCallable {
			p.ErrorFn = fn
		}
	}

	return p, nil
}

func (se *StarlarkEngine) EvalPassiveHost(host PassiveHost) {
	if len(se.plugins) == 0 {
		return
	}

	dict := starlark.NewDict(4)
	dict.SetKey(starlark.String("ip"), starlark.String(host.IP))
	dict.SetKey(starlark.String("mac"), starlark.String(host.MAC))
	dict.SetKey(starlark.String("os"), starlark.String(host.InferredOS))
	
	protocolsList := starlark.NewList(nil)
	for _, p := range host.L7Protocols {
		protocolsList.Append(starlark.String(p))
	}
	dict.SetKey(starlark.String("protocols"), protocolsList)

	hostnamesList := starlark.NewList(nil)
	for _, h := range host.Hostnames {
		hostnamesList.Append(starlark.String(h))
	}
	dict.SetKey(starlark.String("hostnames"), hostnamesList)

	args := starlark.Tuple{dict}
	
	for _, p := range se.plugins {
		if p.ProcessFn != nil {
			if _, err := starlark.Call(p.Thread, p.ProcessFn, args, nil); err != nil {
				log.Printf("[!] Plugin '%s' process error: %v", p.Name, err)
			}
		}
	}
}

func (se *StarlarkEngine) EvalMalformed(ip string, mac string, errorReason string) {
	if len(se.plugins) == 0 {
		return
	}

	dict := starlark.NewDict(2)
	dict.SetKey(starlark.String("ip"), starlark.String(ip))
	if mac != "" {
		dict.SetKey(starlark.String("mac"), starlark.String(mac))
	}

	args := starlark.Tuple{dict, starlark.String(errorReason)}

	for _, p := range se.plugins {
		if p.ErrorFn != nil {
			if _, err := starlark.Call(p.Thread, p.ErrorFn, args, nil); err != nil {
				log.Printf("[!] Plugin '%s' malformed error: %v", p.Name, err)
			}
		}
	}
}
