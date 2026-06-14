# Changelog

All notable changes to AgentGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
semantic versioning after the first public release.

## Unreleased

### Added

- Core deny-by-default policy engine.
- Guard decorator for raw tool dispatchers.
- In-memory and JSONL audit logging.
- Reusable policy presets for common argument-level constraints.
- CLI helpers for checking policy decisions and inspecting JSONL audit logs.
- Prompt-injection containment and transfer-limit demos.
- GitHub Actions CI.

### Changed

- Removed unused system-prompt locking API surface before release.
