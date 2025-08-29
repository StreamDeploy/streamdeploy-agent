#pragma once
#include <string>

// Placeholder for future board-specific HALs.
// For Orin and RK3588 we run containers; for ESP32 this would implement OTA partition write.
struct HalHints {
    // For SBCs: additional docker args (e.g., RK3588 DRI device pass-through)
    std::string dockerArgs;
};
