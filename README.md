# Nobl9 Data Source Migrator v1.0

A Python script for managing Service Level Objectives (SLOs) in Nobl9, enabling data source migration and SLO management across your monitoring infrastructure.

## Features

- **Data Source Discovery**: Lists all data sources in your Nobl9 instance with SLO counts, project, and kind information
- **SLO Grouping**: View SLOs organized by project and service for selected data sources
- **Data Source Migration**: Migrate SLOs between different data sources (agents and directs)
- **Comprehensive Logging**: Detailed audit trail of all migrations and operations
- **Cross-Platform Support**: Works on Windows, macOS, and Linux systems
- **Context Management**: Automatically saves and restores your sloctl context

## Prerequisites

- Python 3.7 or higher
- `sloctl` CLI tool installed and configured
- **Nobl9 admin account** (recommended for full access to all data sources and SLOs)
- Valid Nobl9 configuration file

**Note**: Running as a Nobl9 admin ensures you have access to all data sources and SLOs across all projects. Limited permissions may restrict which data sources and SLOs are visible to the script.

## Installation

1. Clone or download this repository
2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

The script automatically detects your Nobl9 configuration from standard locations:

- **Unix/Linux/macOS**: `~/.config/nobl9/config.toml`
- **Windows**: `%APPDATA%\nobl9\config.toml`
- **Custom**: Set `NOBL9_CONFIG_PATH` environment variable

## Usage

### Basic Workflow

1. **Run the script**:
   ```bash
   python3 data_source_migrator.py
   ```

2. **Select Nobl9 context** from available configurations

3. **Choose source data source** to migrate SLOs from

4. **Select SLOs** for migration (all, by project, by service, or individual)

5. **Choose target data source** for migration

6. **Review and confirm** the migration

### Output Files

The script generates two types of output files in the `slo_yaml_files/` directory:

- **Original SLOs**: Selected SLOs before migration
- **Updated SLOs**: Selected SLOs after migration

Files are named using the pattern: `YYYYMMDD_HHMMSS_source_destination_type.yaml`

**Note**: Full SLO snapshots are not exported in v1.0 to focus on migration-specific files.

## File Structure

```
.
├── data_source_migrator.py      # Main script
├── requirements.txt             # Python dependencies
├── README.md                   # This file
├── LICENSE                     # MIT License
├── .gitignore                  # Git ignore rules
├── data_source_logs/           # Operation logs (auto-created)
└── slo_yaml_files/            # Output files (auto-created)
```

## Dependencies

- `colorama`: Cross-platform colored terminal output
- `toml`: TOML configuration file parsing
- `requests`: HTTP requests for authentication
- `PyYAML`: YAML file processing

## Error Handling

The script includes comprehensive error handling for:
- Missing dependencies
- Configuration file issues
- Authentication failures
- Network connectivity problems
- Invalid user input

## Logging

All operations are logged to timestamped files in `data_source_logs/` with:
- INFO level: Normal operations and migrations
- WARNING level: Non-critical issues
- ERROR level: Critical failures
- SUCCESS level: Completed operations

## Security

- Credentials are read from your existing Nobl9 configuration
- No sensitive data is stored in output files
- Access tokens are acquired securely via OAuth2
- All operations respect your existing Nobl9 permissions

## Troubleshooting

### Common Issues

1. **sloctl not found**: Ensure sloctl is installed and in your PATH
2. **Configuration not found**: Check your Nobl9 config file location
3. **Authentication failed**: Verify your credentials and organization
4. **Permission denied**: Ensure your account has appropriate Nobl9 permissions
5. **Limited data sources visible**: Run as Nobl9 admin for full access to all data sources and SLOs

### Getting Help

- Check the log files in `data_source_logs/` for detailed error information
- Verify your Nobl9 configuration with `sloctl config current-context`
- Ensure you have the required permissions for the operations you're attempting
- **For best results**: Use a Nobl9 admin account to ensure access to all data sources and SLOs

## Contributing

This is a v1.0 release. For bug reports or feature requests, please:
1. Check existing issues
2. Provide detailed error logs
3. Include your environment details

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For Nobl9-specific issues, refer to the [Nobl9 documentation](https://docs.nobl9.com/).

For script-specific issues, check the log files and ensure all prerequisites are met. 