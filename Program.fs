module PostgreSQLBackup

open System
open System.IO
open System.Diagnostics
open System.Net.Http
open System.Text
open System.Text.Json
open System.Text.Json.Serialization
open System.Security.Cryptography
open System.Threading.Tasks
open Microsoft.Extensions.Logging

// Configuration types
[<CLIMutable>]
type DatabaseConfig = {
    Host: string
    Port: int
    Username: string
    Password: string
    // Now we'll have a list of database names instead of a single one
    Databases: string list
    PgDumpPath: string
}

[<CLIMutable>]
type BackupConfig = {
    LocalDirectory: string
    RetentionDays: int
}

[<CLIMutable>]
type BackblazeConfig = {
    Enabled: bool
    KeyId: string
    ApplicationKey: string
    BucketName: string
    BucketId: string
}

[<CLIMutable>]
type LogConfig = {
    LogLevel: string
    LogDirectory: string
}

[<CLIMutable>]
type Configuration = {
    Database: DatabaseConfig
    Backup: BackupConfig
    Backblaze: BackblazeConfig
    Logging: LogConfig
}

// Backblaze B2 API response types
[<CLIMutable>]
type BackblazeAuthResponse = {
    authorizationToken: string
    apiUrl: string
    downloadUrl: string
}

[<CLIMutable>]
type BackblazeUploadUrlResponse = {
    uploadUrl: string
    authorizationToken: string
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

// Parse a JSON array into a list of strings
let parseStringArray (element: JsonElement) =
    if element.ValueKind = JsonValueKind.Array then
        [| for i in 0 .. element.GetArrayLength() - 1 -> element[i].GetString() |]
        |> Array.toList
    else
        // Handle the case where a single string is provided instead of an array
        // This provides backward compatibility with old config files
        [element.GetString()]

// Use the JsonDocument API to manually parse the configuration
let loadConfiguration (configPath: string) =
    if not (File.Exists configPath) then
        failwith $"Configuration file not found: {configPath}"

    // Parse the JSON content without using reflection-based serialization
    try
        let configJson = File.ReadAllText configPath
        let rootJson = JsonDocument.Parse(configJson).RootElement

        // Parse Database config
        let dbElement = rootJson.GetProperty("Database")
        let databases =
            // Try to access the properties without using TryGetProperty with out parameters
            try
                // Try new format with array of databases first
                parseStringArray (dbElement.GetProperty("Databases"))
            with _ ->
                try
                    // Fall back to legacy format with single database
                    [dbElement.GetProperty("Database").GetString()]
                with _ ->
                    failwith "Configuration error: No databases specified"

        let database = {
            Host = dbElement.GetProperty("Host").GetString()
            Port = dbElement.GetProperty("Port").GetInt32()
            Username = dbElement.GetProperty("Username").GetString()
            Password = dbElement.GetProperty("Password").GetString()
            Databases = databases
            PgDumpPath = dbElement.GetProperty("PgDumpPath").GetString()
        }

        // Parse Backup config
        let backupElement = rootJson.GetProperty("Backup")
        let backup = {
            LocalDirectory = backupElement.GetProperty("LocalDirectory").GetString()
            RetentionDays = backupElement.GetProperty("RetentionDays").GetInt32()
        }

        // Parse Backblaze config
        let backblazeElement = rootJson.GetProperty("Backblaze")
        let backblaze = {
            Enabled = backblazeElement.GetProperty("Enabled").GetBoolean()
            KeyId = backblazeElement.GetProperty("KeyId").GetString()
            ApplicationKey = backblazeElement.GetProperty("ApplicationKey").GetString()
            BucketName = backblazeElement.GetProperty("BucketName").GetString()
            BucketId = backblazeElement.GetProperty("BucketId").GetString()
        }

        // Parse Logging config
        let loggingElement = rootJson.GetProperty("Logging")
        let logging = {
            LogLevel = loggingElement.GetProperty("LogLevel").GetString()
            LogDirectory = loggingElement.GetProperty("LogDirectory").GetString()
        }

        // Create the full configuration object
        {
            Database = database
            Backup = backup
            Backblaze = backblaze
            Logging = logging
        }
    with ex ->
        failwith $"Failed to parse configuration: {ex.Message}"

// Create backup file name with timestamp
let createBackupFileName (databaseName: string) =
    let timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss")
    $"{databaseName}_{timestamp}.dump"

// Run pg_dump to create backup for a single database
let createBackup (config: DatabaseConfig) (databaseName: string) (backupPath: string) (logger: ILogger) =
    logger.LogInformation($"Starting backup of database: {databaseName}...")

    // Create process to run pg_dump
    let startInfo = ProcessStartInfo()
    startInfo.FileName <- config.PgDumpPath
    startInfo.Arguments <- $"-h {config.Host} -p {config.Port} -U {config.Username} -F c -f \"{backupPath}\" {databaseName}"
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
        logger.LogError($"pg_dump failed for database {databaseName} with exit code {pgDumpProcess.ExitCode}: {error}")
        Error error
    else
        logger.LogInformation($"Backup created successfully for database {databaseName}: {backupPath}")
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

// Updated Backblaze functions with fixed string interpolation

// The parseBackblazeAuthResponse function needs to preserve the exact token format
let parseBackblazeAuthResponse (json: string) =
    try
        let doc = JsonDocument.Parse(json)
        let root = doc.RootElement

        {
            authorizationToken = root.GetProperty("authorizationToken").GetString()
            apiUrl = root.GetProperty("apiUrl").GetString()
            downloadUrl = root.GetProperty("downloadUrl").GetString()
        }
    with ex ->
        failwith (sprintf "Failed to parse Backblaze auth response: %s" ex.Message)

// The parseBackblazeUploadUrlResponse function needs to preserve the exact token format
let parseBackblazeUploadUrlResponse (json: string) =
    try
        let doc = JsonDocument.Parse(json)
        let root = doc.RootElement

        {
            uploadUrl = root.GetProperty("uploadUrl").GetString()
            authorizationToken = root.GetProperty("authorizationToken").GetString()
        }
    with ex ->
        failwith (sprintf "Failed to parse Backblaze upload URL response: %s" ex.Message)

// Fix for the Backblaze authentication and upload process

// The issue is in the authorization header handling.
// We need to modify these three functions to properly handle the token format.

// Fixed Backblaze B2 API functions

let getBackblazeAuth (keyId: string) (appKey: string) (logger: ILogger) = async {
    logger.LogInformation("Authenticating with Backblaze B2...")

    use client = new HttpClient()

    // Set authorization header for initial auth
    let auth = Convert.ToBase64String(Encoding.ASCII.GetBytes(sprintf "%s:%s" keyId appKey))
    client.DefaultRequestHeaders.Clear()
    client.DefaultRequestHeaders.Add("Authorization", sprintf "Basic %s" auth)
    client.Timeout <- TimeSpan.FromMinutes(5)  // Increase timeout

    try
        let! response = client.GetStringAsync("https://api.backblazeb2.com/b2api/v2/b2_authorize_account") |> Async.AwaitTask

        // Parse the auth response
        let authResponse = parseBackblazeAuthResponse response
        logger.LogInformation("Successfully authenticated with Backblaze B2")

        return Ok authResponse
    with ex ->
        logger.LogError(ex, "Failed to authenticate with Backblaze B2")
        return Error ex.Message
}

let getBackblazeUploadUrl (authToken: string) (apiUrl: string) (bucketId: string) (logger: ILogger) = async {
    logger.LogInformation("Getting Backblaze B2 upload URL...")
    logger.LogDebug(sprintf "Using API URL: %s" apiUrl)

    // Create a new HttpClient for each request to avoid header issues
    use client = new HttpClient()
    client.Timeout <- TimeSpan.FromMinutes(5)  // Increase timeout

    // Set headers for the request - use TryAddWithoutValidation to avoid format issues
    client.DefaultRequestHeaders.Clear()
    client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", authToken) |> ignore

    let requestBody = sprintf "{\"bucketId\":\"%s\"}" bucketId
    let content = new StringContent(requestBody, Encoding.UTF8, "application/json")

    try
        // Send the request
        let! response = client.PostAsync(sprintf "%s/b2api/v2/b2_get_upload_url" apiUrl, content) |> Async.AwaitTask
        let! responseBody = response.Content.ReadAsStringAsync() |> Async.AwaitTask

        if not response.IsSuccessStatusCode then
            logger.LogError(sprintf "Failed to get upload URL: %s" responseBody)
            return Error responseBody
        else
            // Parse upload URL response
            let uploadUrlResponse = parseBackblazeUploadUrlResponse responseBody
            logger.LogInformation("Successfully got Backblaze B2 upload URL")
            return Ok uploadUrlResponse
    with ex ->
        logger.LogError(ex, sprintf "Failed to get Backblaze B2 upload URL: %s" ex.Message)
        return Error ex.Message
}

let uploadToBackblaze (uploadUrl: string) (authToken: string) (filePath: string) (fileName: string) (logger: ILogger) = async {
    logger.LogInformation(sprintf "Uploading backup to Backblaze B2: %s" fileName)

    // Create a new HttpClient for upload
    use client = new HttpClient()
    client.Timeout <- TimeSpan.FromMinutes(30)  // Long timeout for large files

    // Clear all headers first
    client.DefaultRequestHeaders.Clear()

    // Add the authorization header without validation to avoid format issues
    client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", authToken) |> ignore

    // Calculate SHA1 hash of file
    use hashFileStream = File.OpenRead(filePath)
    let sha1 = SHA1.Create()
    let hashBytes = sha1.ComputeHash(hashFileStream)
    let hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower()
    hashFileStream.Close()

    // Get file info for logging
    let fileInfo = FileInfo(filePath)
    logger.LogDebug(sprintf "File size: %d bytes, SHA1: %s" fileInfo.Length hash)

    // Add required B2 headers without validation
    client.DefaultRequestHeaders.TryAddWithoutValidation("X-Bz-File-Name", Uri.EscapeDataString(fileName)) |> ignore
    client.DefaultRequestHeaders.TryAddWithoutValidation("X-Bz-Content-Sha1", hash) |> ignore

    try
        // Open the file stream again for the actual upload
        use fileStream = File.OpenRead(filePath)

        // Create content from file stream and set Content-Type explicitly
        // This is the critical fix - setting Content-Type on the content, not in the headers
        use content = new StreamContent(fileStream)
        content.Headers.ContentType <- new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream")

        // Upload file
        let! response = client.PostAsync(uploadUrl, content) |> Async.AwaitTask
        let! responseBody = response.Content.ReadAsStringAsync() |> Async.AwaitTask

        logger.LogDebug(sprintf "Upload response status: %A" response.StatusCode)

        if not response.IsSuccessStatusCode then
            logger.LogError(sprintf "Failed to upload backup: %s" responseBody)
            return Error responseBody
        else
            logger.LogInformation(sprintf "Successfully uploaded backup to Backblaze B2: %s" fileName)
            return Ok responseBody
    with ex ->
        logger.LogError(ex, sprintf "Exception during upload of %s: %s" fileName ex.Message)
        return Error ex.Message
}

// Backup a single database and upload to Backblaze if enabled
let backupDatabase (config: Configuration) (databaseName: string) (logger: ILogger) = async {
    logger.LogInformation($"Starting backup process for database: {databaseName}")

    // Create backup file name
    let backupFileName = createBackupFileName databaseName
    let backupPath = Path.Combine(config.Backup.LocalDirectory, backupFileName)

    // Create backup
    let backupResult = createBackup config.Database databaseName backupPath logger

    match backupResult with
    | Error err ->
        logger.LogError($"Backup failed for database {databaseName}: {err}")
        return Error err
    | Ok path ->
        // Upload to Backblaze if enabled
        if config.Backblaze.Enabled then
            // Authenticate with Backblaze
            let! authResult = getBackblazeAuth config.Backblaze.KeyId config.Backblaze.ApplicationKey logger

            match authResult with
            | Error err ->
                logger.LogError($"Backblaze authentication failed: {err}")
                return Error err
            | Ok auth ->
                // Get upload URL
                let! uploadUrlResult = getBackblazeUploadUrl auth.authorizationToken auth.apiUrl config.Backblaze.BucketId logger

                match uploadUrlResult with
                | Error err ->
                    logger.LogError($"Failed to get Backblaze upload URL: {err}")
                    return Error err
                | Ok uploadUrl ->
                    // Upload file
                    let! uploadResult = uploadToBackblaze uploadUrl.uploadUrl uploadUrl.authorizationToken path backupFileName logger

                    match uploadResult with
                    | Error err ->
                        logger.LogError($"Backblaze upload failed for database {databaseName}: {err}")
                        return Error err
                    | Ok _ ->
                        logger.LogInformation($"Backup process completed successfully for database {databaseName}")
                        return Ok path
        else
            logger.LogInformation($"Backup process completed successfully for database {databaseName}")
            return Ok path
}

// Main backup process for all databases
let performBackup (config: Configuration) =
    // Create logger
    let logger = createLogger config.Logging

    logger.LogInformation("PostgreSQL Backup process started")

    // Ensure backup directory exists
    if not (Directory.Exists config.Backup.LocalDirectory) then
        Directory.CreateDirectory(config.Backup.LocalDirectory) |> ignore
        logger.LogInformation($"Created backup directory: {config.Backup.LocalDirectory}")

    // Process all databases in parallel
    let backupTasks =
        config.Database.Databases
        |> List.map (fun db -> backupDatabase config db logger)
        |> List.toArray
        |> Array.map Async.StartAsTask

    let allBackups = Task.WhenAll(backupTasks).Result |> Array.toList

    // Count success and failures
    let successCount = allBackups |> List.filter (fun r -> match r with Ok _ -> true | _ -> false) |> List.length
    let failureCount = allBackups.Length - successCount

    logger.LogInformation($"Database backups completed. Successful: {successCount}, Failed: {failureCount}")

    // Clean up old backups
    let cleanupResult = cleanupOldBackups config.Backup.LocalDirectory config.Backup.RetentionDays logger

    match cleanupResult with
    | Error err ->
        logger.LogError($"Backup cleanup failed: {err}")
        1
    | Ok _ ->
        if failureCount > 0 then
            logger.LogWarning("Some database backups failed. Check the logs for details.")
            1
        else
            logger.LogInformation("All database backups completed successfully")
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