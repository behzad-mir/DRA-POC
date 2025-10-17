	// ✅ Ensure kubelet can access the socket
	if err := os.Chmod(PluginSocketPath, 0777); err != nil {
		log.Printf("[DRASecondaryNIC] warn: failed to chmod socket: %v", err)
	}

	// ✅ Fallback symlink for kubelet bug in v1.33 (raw endpoint interpretation)
	fallbackDir := "/dra-secondarynic"
	fallbackSock := fallbackDir + "/plugin.sock"
	if err := os.MkdirAll(fallbackDir, 0755); err == nil {
		_ = os.Remove(fallbackSock)
		if err := os.Symlink(PluginSocketPath, fallbackSock); err != nil {
			log.Printf("[DRASecondaryNIC] warn: failed to create fallback symlink: %v", err)
		} else {
			log.Printf("[DRASecondaryNIC] created fallback symlink at %s", fallbackSock)
		}
	}