# PostgreSQL Backup Tool

A robust F# application for creating and managing PostgreSQL database backups with optional Backblaze B2 cloud storage integration.

## Features

- **Automated PostgreSQL Backups**: Creates compressed backups of PostgreSQL databases using `pg_dump`
- **Multiple Database Support**: Back up multiple databases in a single operation
- **Local Backup Management**: Configurable retention policy for local backups
- **Cloud Storage Integration**: Optional backup upload to Backblaze B2 cloud storage
- **Comprehensive Logging**: Detailed logging with configurable levels

## Requirements

- .NET 6.0 or higher
- PostgreSQL client tools (specifically `pg_dump`)
- Backblaze B2 account (optional, only if cloud storage is desired)

## Installation

### From Source

1. Clone this repository
2. Navigate to the project directory
3. Build the project:

```bash
# Build as a self-contained executable (for Linux)
dotnet publish -c Release -r linux-x64 --self-contained true /p:PublishSingleFile=true /p:PublishTrimmed=true

# For Windows
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:PublishTrimmed=true

# For macOS
dotnet publish -c Release -r osx-x64 --self-contained true /p:PublishSingleFile=true /p:PublishTrimmed=true
```

## Configuration

Create a `config.json` file in the same directory as the executable:

```json
{
    "Database": {
        "Host": "localhost",
        "Port": 5432,
        "Username": "postgres",
        "Password": "your_password",
        "Databases": ["db1", "db2", "db3"],  // List of databases to back up
        "PgDumpPath": "/usr/bin/pg_dump"     // Path to pg_dump executable
    },
    "Backup": {
        "LocalDirectory": "./backups",       // Directory to store backups
        "RetentionDays": 30                  // How many days to keep backups
    },
    "Backblaze": {
        "Enabled": false,                    // Set to true to enable Backblaze B2 uploads
        "KeyId": "your_backblaze_key_id",
        "ApplicationKey": "your_backblaze_application_key",
        "BucketName": "postgres-backups",
        "BucketId": "your_backblaze_bucket_id"
    },
    "Logging": {
        "LogLevel": "Information",           // Trace, Debug, Information, Warning, Error, Critical
        "LogDirectory": "./logs"             // Directory to store log files
    }
}
```

### Legacy Configuration Support

The tool also supports a legacy configuration format with a single database:

```json
{
    "Database": {
        "Host": "localhost",
        "Port": 5432,
        "Username": "postgres",
        "Password": "your_password",
        "Database": "your_database",         // Single database to back up (legacy format)
        "PgDumpPath": "/usr/bin/pg_dump"
    },
    ...
}
```

## Usage

Run the tool with:

```bash
./PostgreSQLBackup [path_to_config.json]
```

If no configuration file is specified, the tool will look for `config.json` in the current directory.

## How It Works

1. The tool reads the configuration file to determine which databases to back up
2. For each database:
   - Creates a compressed backup using `pg_dump` with timestamp in the filename
   - If Backblaze B2 is enabled, authenticates and uploads the backup file
3. Cleans up old backup files based on the retention policy

## Running on a Schedule

### Linux (using cron)

Edit your crontab with `crontab -e` and add:

```
# Run backup daily at 2 AM
0 2 * * * /path/to/PostgreSQLBackup /path/to/config.json
```

### Windows (using Task Scheduler)

1. Open Task Scheduler
2. Create a new task
3. Set a trigger (e.g., daily at 2 AM)
4. Add a new action:
   - Program/script: `C:\path\to\PostgreSQLBackup.exe`
   - Arguments: `C:\path\to\config.json`

## Troubleshooting

### Common Issues

1. **pg_dump not found**: Ensure the `PgDumpPath` in the configuration points to the correct location
2. **Permission denied**: Ensure the user running the tool has write permissions to the backup directory
3. **Authentication failed**: Verify database credentials or Backblaze credentials

### Checking Logs

Check the log files in the configured log directory for detailed error information.

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.