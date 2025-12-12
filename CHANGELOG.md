# Changelog

All notable changes to LogInspector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2025-12-12

### Added
- **Bot Detection Cache**: Implemented caching mechanism for `detectBot()` function to significantly improve performance on large log files with repeated User-Agent strings
- Additional Bot Detection

### Changed
- **Code Quality**: Replaced magic strings with named constants

## [0.3.0] - 2025-12-11

### Added
- **Enhanced IP Filtering**: Added `-ip` flag to filter logs by specific IP address(es) with comma-separated support
- **IP Exclusion**: Added `-exclude-ip` flag to exclude specific IP address(es) from analysis
- **Multiple Bot Filtering**: Extended `-bot` flag to support comma-separated list of bot names
- **Bot Exclusion**: Added `-exclude-bot` flag to exclude specific bots from analysis
- **Multiple Method Filtering**: Extended `-method` flag to support comma-separated list of HTTP methods
- **Method Exclusion**: Added `-exclude-method` flag to exclude specific HTTP methods
- **Multiple User-Agent Filtering**: Extended `-user-agent` flag to support comma-separated list of user agents
- **User-Agent Exclusion**: Added `-exclude-user-agent` flag to exclude specific user agents
- **Mutual Exclusivity Validation**: Added validation to prevent simultaneous use of include and exclude filters for the same parameter
- **Additional Bot Detection**

## [0.2.0] - 2025-12-10

## [0.1.0] - 2025-12-09
