// Jetson (Orin) specifics are handled through AgentConfig.extra_docker_args (e.g., "--gpus all").
// RK3588 can override this to "--device /dev/dri:/dev/dri" etc.
// ESP32 would not compile this TU; you'd build a tiny C/Arduino agent that speaks the same API.
