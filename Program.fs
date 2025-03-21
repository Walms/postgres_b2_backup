module PostgreSQLBackup

open System
open System.IO
open System.Diagnostics
open System.Net.Http
open System.Text
open System.Text.Json
open System.Security.Cryptography
open System.Threading.Tasks
open Microsoft.Extensions.Logging

// Configuration type
type DatabaseConfig = {
    Host: string
    Port: int
    Username: string
    Password: string
    Database: string
    PgDumpPath: string
}

type BackupConfig = {
    LocalDirectory: string
    RetentionDays: int
}

type BackblazeConfig = {
    Enabled: bool
    KeyId: string
    ApplicationKey: string
    BucketName: string
    BucketId: string
}

type LogConfig = {
    LogLevel: string
    LogDirectory: string
}

type Configuration = {
    Database: DatabaseConfig
    Backup: BackupConfig
    Backblaze: BackblazeConfig
    Logging: LogConfig
}

// Logger factory
let createLogger (config: LogConfig) =
    let logLevel =
        match config.LogLevel.ToLower() with
        | "trace" -> LogLevel.Trace
        | "debug" -> LogLevel.Debug
        | "information" | "info" -> LogLevel.Information
        | "warning" | "warn" -> LogLevel.Warning
        | "error" -> LogLevel.Error
        | "critical" -> LogLevel.Critical
        | _ -> LogLevel.Information

    let loggerFactory = LoggerFactory.Create(fun builder ->
        builder.AddConsole() |> ignore
        builder.AddFile(Path.Combine(config.LogDirectory, "postgres-backup-{Date}.log")) |> ignore
        builder.SetMinimumLevel(logLevel) |> ignore
    )

    loggerFactory.CreateLogger("PostgreSQLBackup")

// Load configuration from file
let loadConfiguration (configPath: string) =
    if not (File.Exists configPath) then
        failwith $"Configuration file not found: {configPath}"

    let configJson = File.ReadAllText configPath
    JsonSerializer.Deserialize<Configuration>(configJson)

// Create backup file name with timestamp
let createBackupFileName (databaseName: string) =
    let timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss")
    $"{databaseName}_{timestamp}.dump"

// Run pg_dump to create backup
let createBackup (config: DatabaseConfig) (backupPath: string) (logger: ILogger) =
    logger.LogInformation("Starting database backup...")

    // Create process to run pg_dump
    let startInfo = ProcessStartInfo()
    startInfo.FileName <- config.PgDumpPath
    startInfo.Arguments <- $"-h {config.Host} -p {config.Port} -U {config.Username} -F c -f \"{backupPath}\" {config.Database}"
    startInfo.RedirectStandardOutput <- true
    startInfo.RedirectStandardError <- true
    startInfo.UseShellExecute <- false
    startInfo.CreateNoWindow <- true

    // Set PGPASSWORD environment variable
    startInfo.EnvironmentVariables.["PGPASSWORD"] <- config.Password

    // Start process
    let pgDumpProcess = Process.Start(startInfo)
    let output = pgDumpProcess.StandardOutput.ReadToEnd()
    let error = pgDumpProcess.StandardError.ReadToEnd()
    pgDumpProcess.WaitForExit()

    // Check for errors
    if pgDumpProcess.ExitCode <> 0 then
        logger.LogError($"pg_dump failed with exit code {pgDumpProcess.ExitCode}: {error}")
        Error error
    else
        logger.LogInformation($"Backup created successfully: {backupPath}")
        if not (String.IsNullOrEmpty output) then
            logger.LogDebug($"pg_dump output: {output}")
        Ok backupPath

// Delete old backups
let cleanupOldBackups (directory: string) (retentionDays: int) (logger: ILogger) =
    logger.LogInformation($"Cleaning up backups older than {retentionDays} days...")

    try
        let cutoffDate = DateTime.Now.AddDays(float -retentionDays)
        let files = Directory.GetFiles(directory, "*.dump")

        let deletedCount =
            files
            |> Array.filter (fun file -> File.GetCreationTime(file) < cutoffDate)
            |> Array.map (fun file ->
                try
                    File.Delete(file)
                    logger.LogInformation($"Deleted old backup: {file}")
                    1
                with ex ->
                    logger.LogError(ex, $"Failed to delete old backup: {file}")
                    0
            )
            |> Array.sum

        logger.LogInformation($"Cleanup complete. Deleted {deletedCount} old backups.")
        Ok deletedCount
    with ex ->
        logger.LogError(ex, "Error during backup cleanup")
        Error ex.Message

// Backblaze B2 API functions
type BackblazeAuthResponse = {
    authorizationToken: string
    apiUrl: string
    downloadUrl: string
}

type BackblazeUploadUrlResponse = {
    uploadUrl: string
    authorizationToken: string
}

let getBackblazeAuth (keyId: string) (appKey: string) (logger: ILogger) = async {
    logger.LogInformation("Authenticating with Backblaze B2...")

    use client = new HttpClient()
    let auth = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{keyId}:{appKey}"))
    client.DefaultRequestHeaders.Add("Authorization", $"Basic {auth}")

    try
        let! response = client.GetStringAsync("https://api.backblazeb2.com/b2api/v2/b2_authorize_account") |> Async.AwaitTask
        let authResponse = JsonSerializer.Deserialize<BackblazeAuthResponse>(response)
        logger.LogInformation("Successfully authenticated with Backblaze B2")
        return Ok authResponse
    with ex ->
        logger.LogError(ex, "Failed to authenticate with Backblaze B2")
        return Error ex.Message
}

let getBackblazeUploadUrl (authToken: string) (apiUrl: string) (bucketId: string) (logger: ILogger) = async {
    logger.LogInformation("Getting Backblaze B2 upload URL...")

    use client = new HttpClient()
    client.DefaultRequestHeaders.Add("Authorization", authToken)

    let content = new StringContent($"{{\"bucketId\":\"{bucketId}\"}}", Encoding.UTF8, "application/json")

    try
        let! response = client.PostAsync($"{apiUrl}/b2api/v2/b2_get_upload_url", content) |> Async.AwaitTask
        let! responseBody = response.Content.ReadAsStringAsync() |> Async.AwaitTask

        if not response.IsSuccessStatusCode then
            logger.LogError($"Failed to get upload URL: {responseBody}")
            return Error responseBody
        else
            let uploadUrlResponse = JsonSerializer.Deserialize<BackblazeUploadUrlResponse>(responseBody)
            logger.LogInformation("Successfully got Backblaze B2 upload URL")
            return Ok uploadUrlResponse
    with ex ->
        logger.LogError(ex, "Failed to get Backblaze B2 upload URL")
        return Error ex.Message
}

let uploadToBackblaze (uploadUrl: string) (authToken: string) (filePath: string) (fileName: string) (logger: ILogger) = async {
    logger.LogInformation($"Uploading backup to Backblaze B2: {fileName}")

    use client = new HttpClient()
    client.DefaultRequestHeaders.Add("Authorization", authToken)

    // Calculate SHA1 hash of file
    use fileStream = File.OpenRead(filePath)
    let sha1 = SHA1.Create()
    let hashBytes = sha1.ComputeHash(fileStream)
    let hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower()

    // Reset stream position for upload
    fileStream.Position <- 0

    // Set required headers
    client.DefaultRequestHeaders.Add("X-Bz-File-Name", Uri.EscapeDataString(fileName))
    client.DefaultRequestHeaders.Add("X-Bz-Content-Sha1", hash)
    client.DefaultRequestHeaders.Add("Content-Type", "application/octet-stream")

    try
        // Create content from file stream
        let content = new StreamContent(fileStream)

        // Upload file
        let! response = client.PostAsync(uploadUrl, content) |> Async.AwaitTask
        let! responseBody = response.Content.ReadAsStringAsync() |> Async.AwaitTask

        if not response.IsSuccessStatusCode then
            logger.LogError($"Failed to upload backup: {responseBody}")
            return Error responseBody
        else
            logger.LogInformation($"Successfully uploaded backup to Backblaze B2: {fileName}")
            return Ok responseBody
    with ex ->
        logger.LogError(ex, $"Failed to upload backup: {fileName}")
        return Error ex.Message
}

// Main backup process
let performBackup (config: Configuration) =
    // Create logger
    let logger = createLogger config.Logging

    logger.LogInformation("PostgreSQL Backup process started")

    // Ensure backup directory exists
    if not (Directory.Exists config.Backup.LocalDirectory) then
        Directory.CreateDirectory(config.Backup.LocalDirectory) |> ignore
        logger.LogInformation($"Created backup directory: {config.Backup.LocalDirectory}")

    // Create backup file name
    let backupFileName = createBackupFileName config.Database.Database
    let backupPath = Path.Combine(config.Backup.LocalDirectory, backupFileName)

    // Create backup
    let backupResult = createBackup config.Database backupPath logger

    match backupResult with
    | Error err ->
        logger.LogError($"Backup failed: {err}")
        1 // Return error code
    | Ok path ->
        // Upload to Backblaze if enabled
        if config.Backblaze.Enabled then
            async {
                // Authenticate with Backblaze
                let! authResult = getBackblazeAuth config.Backblaze.KeyId config.Backblaze.ApplicationKey logger

                match authResult with
                | Error err ->
                    logger.LogError($"Backblaze authentication failed: {err}")
                    return 1
                | Ok auth ->
                    // Get upload URL
                    let! uploadUrlResult = getBackblazeUploadUrl auth.authorizationToken auth.apiUrl config.Backblaze.BucketId logger

                    match uploadUrlResult with
                    | Error err ->
                        logger.LogError($"Failed to get Backblaze upload URL: {err}")
                        return 1
                    | Ok uploadUrl ->
                        // Upload file
                        let! uploadResult = uploadToBackblaze uploadUrl.uploadUrl uploadUrl.authorizationToken path backupFileName logger

                        match uploadResult with
                        | Error err ->
                            logger.LogError($"Backblaze upload failed: {err}")
                            return 1
                        | Ok _ ->
                            // Clean up old backups
                            let cleanupResult = cleanupOldBackups config.Backup.LocalDirectory config.Backup.RetentionDays logger

                            match cleanupResult with
                            | Error err ->
                                logger.LogError($"Backup cleanup failed: {err}")
                                return 1
                            | Ok _ ->
                                logger.LogInformation("Backup process completed successfully")
                                return 0
            } |> Async.RunSynchronously
        else
            // Clean up old backups
            let cleanupResult = cleanupOldBackups config.Backup.LocalDirectory config.Backup.RetentionDays logger

            match cleanupResult with
            | Error err ->
                logger.LogError($"Backup cleanup failed: {err}")
                1
            | Ok _ ->
                logger.LogInformation("Backup process completed successfully")
                0

[<EntryPoint>]
let main argv =
    try
        let configPath =
            if argv.Length > 0 then argv.[0]
            else "config.json"

        let config = loadConfiguration configPath
        performBackup config
    with ex ->
        Console.Error.WriteLine($"Error: {ex.Message}")
        1