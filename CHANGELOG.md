# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## 2.2.0 - 2026-07-23

### Added

- Show temporary block expiration [(#691)](https://github.com/wultra/powerauth-cmd-tool/issues/691)
- Added the `fetch-config` method to fetch the secure configuration over end-to-end encryption in the application or activation scope [(#694)](https://github.com/wultra/powerauth-cmd-tool/issues/694)
- Allow specifying authentication code type for activation remove [(#679)](https://github.com/wultra/powerauth-cmd-tool/issues/679)

### Changed

- Migrated to Spring Boot 4 and Jackson 3 [(#683)](https://github.com/wultra/powerauth-cmd-tool/issues/683)
- Added Lombok annotation processor to enable compilation on Java 23+ [(#685)](https://github.com/wultra/powerauth-cmd-tool/issues/685)
- Updated Spring Boot version [(#698)](https://github.com/wultra/powerauth-cmd-tool/issues/698)

### Fixed

- Command line tool does not indent steps in JSON logger [(#689)](https://github.com/wultra/powerauth-cmd-tool/issues/689)
- JCE cannot authenticate the provider BC [(#681)](https://github.com/wultra/powerauth-cmd-tool/issues/681)
