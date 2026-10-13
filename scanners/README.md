# SentinelSec Scanners (Isolated Placeholder)

## Architecture Notice

In accordance with Phase 0 and Phase 1 specifications, this directory acts as an isolated placeholder for future tool integrations.

**Important Security Constraints for Phase 0/1:**
1. **No External Execution:** This service does not install, expose, or execute scanning utilities, exploit engines, or network probes.
2. **Inert Data:** Target records ingested in Phase 1 remain strictly inert database records.
3. **Network Isolation:** Any future tool container must be isolated in its own network sandbox with no direct external access or command injection paths.
4. **Current Status:** Placeholder service running in a minimal alpine container with no active scanner binaries.
