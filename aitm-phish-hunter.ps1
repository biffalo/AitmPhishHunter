# Parses Chrome and Edge (chromium based) history (for all users) and favicon db to hunt for potential AiTM phishing pages (Evilginx etc)
# Only last 14 days of history is scanned and common legit domains/strings are excluded to cutdown on false positives#
#!!This tool is under active development and is meant to aid in threat hunting or investigating Business Email Compromises (BEC). It is NOT a subsitution for thorough investigation.
#Write-Host @"
# _____  ____  _____         ___  _ ________  ___  _   _             _            
#|____ |/ ___||  ___|       / _ \(_)_   _|  \/  | | | | |           | |           
#    / / /___ |___ \ ______/ /_\ \_  | | | .  . | | |_| |_   _ _ __ | |_ ___ _ __ 
#    \ \ ___ \    \ \______|  _  | | | | | |\/| | |  _  | | | | '_ \| __/ _ \ '__|
#.___/ / \_/ |/\__/ /      | | | | | | | | |  | | | | | | |_| | | | | ||  __/ |   
#\____/\_____/\____/       \_| |_/_| \_/ \_|  |_/ \_| |_/\__,_|_| |_|\__\___|_|
#"@ -ForegroundColor White -BackgroundColor DarkBlue
#Write-Host @"
#Parses Chrome and Edge (chromium based) history and favicon db to hunt for potential 
#AiTM phishing pages like Evilginx by checking for Microsoft favicon on non-microsoft pages!
#"@ -ForegroundColor White -BackgroundColor DarkGreen

# Set Output dir
$destinationPath = "C:\temp"

# URLs for sqllite DLLs. We'll need these to query the sqllite databases for chrome and edge
Invoke-WebRequest -Uri "https://system.data.sqlite.org/blobs/1.0.119.0/sqlite-netFx46-static-binary-x64-2015-1.0.119.0.zip" -OutFile "$destinationPath\sqlite.zip" -ErrorAction SilentlyContinue; Expand-Archive -Path "$destinationPath\sqlite.zip" -DestinationPath "$destinationPath" -Force -ErrorAction SilentlyContinue

# Verify the DLL exists
$assemblyPath = "$destinationPath\System.Data.SQLite.dll"
if (-not (Test-Path $assemblyPath)) {
    Write-Host "System.Data.SQLite.dll was not downloaded correctly. Please check the URLs or extraction process."
    exit
}

# Load the System.Data.SQLite assembly
Add-Type -Path $assemblyPath

# Get the current date and time
$date = (Get-Date -Format "yyyyMMdd_HHmmss")

# Get the list of user profiles excluding default system profiles to reduce heavy lift. Service accounts can also be added here though I'm not sure why you would want to exclude them?
$userProfiles = Get-ChildItem -Path 'C:\Users' -Directory | Where-Object {
    $_.Name -notin @("Default", "All Users", "Default User", "Public", "defaultuser0")
} | Select-Object -ExpandProperty Name

# Function to convert WebKit time to DateTime
function Convert-WebkitTimeToDateTime($webkitTime) {
    # WebKit time is microseconds since Jan 1, 1601 (UTC)
    $epoch = [DateTime]::ParseExact("1601-01-01 00:00:00","yyyy-MM-dd HH:mm:ss",$null)
    $dateTime = $epoch.AddSeconds($webkitTime / 1000000)
    return $dateTime
}

# Function to check if a URL should be excluded
function IsExcludedUrl($url) {
    try {
        $uri = [System.Uri]::new($url)
        $hostname = $uri.Host.ToLower()
        $path = $uri.AbsolutePath.ToLower()
        $query = $uri.Query.ToLower()

        # List of domains/subdomains to exclude. Needed for excluding MOST of the legit services that use the favicon from login.microsoft.com (generally SSO or redirects) Without this there would a lot of noise.
        # !!DOMAINS!! Add domains to this list at your own peril. Be sure you know what you are doing and have validated the safety of domain
        $excludedDomains = @(
            "microsoftonline.com", # Microsoft/365/Azure
            "outlook.com", # Microsoft/365/Azure
            "service-now.com", # ServiceNow SSO
            "microsoft.ai", # Microsoft AI TLD
            "protect.checkpoint.com", #Link scanner - we want final url so skipping
            "microsoft.mcas-gov.ms", #Govcloud SSO
            "microsoftstream.com", # Microsoft Stream
            "zendesk.com", #Zendesk/ticketing SSO
            "windowsazure.us", # Microsoft/365/Azuzre
            "microsoft.us", # Microsoft/365/Azure
            "word.new", # Microsoft/365/Azure
            "msdn.com", # MSDN SSO
            "urldefense.proofpoint.com", # URL scanning. If final url is phishing then we'll catch that. So we are skipping redirect noise here
            "mimecastprotect.com", # Mimecast URL scanning. If final url is phishing then we'll catch that. So we are skipping redirect noise here
            "mycurricula.com", # Huntress Managed SAT SSO
            "iis.net", # IIS landing page uses same icon for some reason
            "1drv.ms", # OneDrive links. These can be lures but the final landing page for AiTM phishes won't be so we exclude the noise
            "outlook.com", # Microsoft/365/Azure
            "ciamlogin.com", # Microsoft/365/Azure
            "sharepoint.us", # Microsoft/365/Azure
            "powerapps.com", # Microsoft/365/Azure
		    "microsoftemail.com", # Microsoft/365/Azure
            "powerbi.com", # Microsoft/365/Azure
            "microsoftvolumelicensing.com", # Microsoft/365/Azure
            "bungie.net", # Microsoft/365/Azure
            "office365.com", # Microsoft/365/Azure
            "office365.us", # Microsoft/365/Azure
            "microsoft365.com", # Microsoft/365/Azure
            "microsoft.com", # Microsoft/365/Azure
            "live.com", # Microsoft/365/Azure
            "live.net", # Microsoft/365/Azure
            "yammer.com", # Microsoft/365/Azure
            "dynamics.com", # Microsoft/365/Azure
            "azure.us", # Microsoft/365/Azure
            "microsoftstore.com", # Microsoft/365/Azure
            "keepersecurity.com", # Keeper SSO
            "amazoncognito.com", # Amazon SSO
            "bing.com", # Microsoft/365/Azure
            "services.adobe.com", # Adobe SSO
            "virtru.com", # Virtru SSO
            "safelink.emails.azure.net", # Microsoft/365/Azure
            "azure.status.microsoft", # Microsoft/365/Azure
            "app.powerbi.com", # Microsoft/365/Azure
            "office.com", # Microsoft/365/Azure
            "azure.com", # Microsoft/365/Azure
            "office.net", # Microsoft/365/Azure
            "sharepoint.com", # Microsoft/365/Azure
            "onedrive.com", # Microsoft/365/Azure
            "edgeservices.bing.com", # Microsoft/365/Azure
            "login.windows.net", # Microsoft/365/Azure       
            "collections.microsoftadvertising.com", # Microsoft/365/Azure
            "xbox.com", # Microsoft/365/Azure
            "login.microsoftonline.us", # Microsoft/365/Azure
            "hotmail.com", # Microsoft/365/Azure
            "outlook.co", # Microsoft has a lot of domains huh?
            "skype.com", # Microsoft has a lot of domains huh?
            "cloud.microsoft", # Microsoft/365/Azure
            "m365.microsoft.cloud", # Microsoft/365/Azure
            "teams.com", # Microsoft/365/Azure
            "linkedin.com", # Microsoft/365/Azure
            "aka.ms", # Microsoft/365/Azure
            "google.com", # Google SSO
            "edgeservices.bing.com", # Microsoft/365/Azure
            "windowsazure.com", # Microsoft/365/Azure
            "mcas.ms", # Microsoft/365/Azure
            "mcas-gov.us", # Microsoft/365/Azure
            "apps.mil", # Microsoft/365/Azure (GCC HIGH)
            "state.gov", # Microsoft/365/Azure (GCC HIGH)
            "va.gov", # Microsoft/365/Azure (GCC HIGH)
            "sharepoint-mil.us", # Microsoft/365/Azure (GCC HIGH)
            "trendmicro.com", # Trend Micro SSO
            "microsoftteams.com", # Microsoft/365/Azure
		    "services.marylandcomptroller.gov", # govt site
			"microsoftpersonalcontent.com",  # Microsoft/365/Azure
			"azuremaps.com", # azure
			"marketplace.visualstudio.com", # Microsoft/Visual Studio/Market Place
			"excel.new", # microsoft url
			"msn.com", #MSN
			"m365.microsoft.cloud", #Microsoft
			"visualstudio.com", #microsoft
			"clickdimensions.com", # Microsoft Dynamics intergrated CRM
			"cjpalhdlnbpafiamejdnhcphjbkeiagm", # chrome-extension://cjpalhdlnbpafiamejdnhcphjbkeiagm/document is ublock origin
			"msft.sng.link", # Microsoft redirect tracker
			"homail.com", # microsoft domain
			"tinyurl.com", #link shortener
			"usaf.dps.mil", # air force
            "access.mcas-gov.ms", # Gov Cloud SSO
			"techsoup.org", # tech soup
			"powerautomate.com" # Microsoft
        )

        # Check if the hostname matches any of the excluded domains (including subdomains)
        foreach ($domain in $excludedDomains) {
            if ($hostname -like "*.$domain" -or $hostname -eq $domain) {
                return $true
            }
        }

        # List of URL path patterns (regex patterns) to exclude that are common for SSO auth flows. Phishing URLs are often single URL in webserver root. If subdirectories are used (this is uncommon), then they are generally random less than 10 character lures for phishing tooling
        #!!EXCLUDED PATHS!! Careful adding stuff to this section as it could result in false negatives
        $excludedPathPatterns = @(
            ".*/xauth/.*",
            ".*/orgid/.*",
            ".*/browsersso/.*",
            ".*/courses/.*",
            ".*/idp/.*",
            ".*/citrix/.*",
            ".*/secure/.*",
            ".*/calendar/.*",
            ".*/adfs/.*",
            ".*/accounts.*",
            ".*/work/web/.*", # for that panitch site that keeps triggering
            ".*/identity.*"
        )

        # Check if the path matches any of the excluded patterns
        foreach ($pattern in $excludedPathPatterns) {
            if ($path -match $pattern) {
                return $true
            }
        }

        # Check if the query contains known OAuth2 parameters. Phishing URLs are not using normal saml/oath type urls so we exclude these to reasonably reduce false positives even further
        #!!EXCLUDED QUERIES!! DO NOT ADD THINGS HERE
        $excludedQueryParams = @(
            "client_id",
            "scope",
            "state",
            "code_challenge",
            "code_challenge_method",
            "code"
        )

        foreach ($param in $excludedQueryParams) {
            if ($query -match [regex]::Escape($param)) {
                return $true
            }
        }

        # If none of the exclusions matched
        return $false
    } catch {
        # If URL parsing failed, exclude it to be safe
        return $true
    }
}

# Function to process browser history
function Process-BrowserHistory($historyPath, $faviconsPath, $browserName) {
    if (-not (Test-Path $historyPath) -or -not (Test-Path $faviconsPath)) {
        # Suppress error messages
        return @()
    }

    # Copy the files to temp to avoid file locks
    $historyCopy = "$env:TEMP\$browserName-History-" + [System.IO.Path]::GetRandomFileName() + ".db"
    $faviconsCopy = "$env:TEMP\$browserName-Favicons-" + [System.IO.Path]::GetRandomFileName() + ".db"

    Copy-Item $historyPath -Destination $historyCopy -ErrorAction SilentlyContinue
    Copy-Item $faviconsPath -Destination $faviconsCopy -ErrorAction SilentlyContinue

    if (-not (Test-Path $historyCopy) -or -not (Test-Path $faviconsCopy)) {
        # Suppress error messages
        return @()
    }

    # Open connections to databases
    $historyConnString = "Data Source=$historyCopy;Version=3;"
    $faviconsConnString = "Data Source=$faviconsCopy;Version=3;"

    $historyConn = New-Object System.Data.SQLite.SQLiteConnection($historyConnString)
    $faviconsConn = New-Object System.Data.SQLite.SQLiteConnection($faviconsConnString)

    try {
        $historyConn.Open()
        $faviconsConn.Open()
    } catch {
        # Suppress error
        return @()
    }

    # Get the cutoff date in WebKit time (microseconds since Jan 1, 1601)
    $epoch = [DateTime]::ParseExact("1601-01-01 00:00:00","yyyy-MM-dd HH:mm:ss",$null)
    $cutoffDate = (Get-Date).AddDays(-14)
    $webkitCutoff = [int64](($cutoffDate - $epoch).TotalSeconds * 1000000)

    # Get URLs and visit times within the last 90 days
    $query = @"
SELECT urls.url, visits.visit_time
FROM urls
JOIN visits ON urls.id = visits.url
WHERE visits.visit_time >= $webkitCutoff
"@

    try {
        $cmd = $historyConn.CreateCommand()
        $cmd.CommandText = $query
        $reader = $cmd.ExecuteReader()
    } catch {
        # Suppress error
        $historyConn.Close()
        $faviconsConn.Close()
        return @()
    }

    $output = @()

    try {
        while ($reader.Read()) {
            $url = $reader["url"]
            $visit_time = $reader["visit_time"]
            $dateTime = Convert-WebkitTimeToDateTime $visit_time

            # Get the icon_id
            $escapedUrl = $url.Replace("'", "''")
            $iconQuery = "SELECT icon_id FROM icon_mapping WHERE page_url = '$escapedUrl'"
            $iconCmd = $faviconsConn.CreateCommand()
            $iconCmd.CommandText = $iconQuery

            try {
                $iconResult = $iconCmd.ExecuteScalar()
            } catch {
                continue
            }

            if ($iconResult) {
                $icon_id = $iconResult

                # Get the largest favicon bitmap
                $bitmapQuery = "SELECT image_data FROM favicon_bitmaps WHERE icon_id = $icon_id ORDER BY width DESC LIMIT 1"
                $bitmapCmd = $faviconsConn.CreateCommand()
                $bitmapCmd.CommandText = $bitmapQuery

                try {
                    $bitmapReader = $bitmapCmd.ExecuteReader()
                    if ($bitmapReader.Read()) {
                        $imageData = $bitmapReader["image_data"]

                        # Compute the SHA1 hash of the image_data
                        $sha1 = [System.Security.Cryptography.SHA1]::Create()
                        $hashBytes = $sha1.ComputeHash($imageData)
                        $hash = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()

                        # Check if the URL should be excluded
                        if ($hash -eq "2153f0aa2e30bf0940b6589b1e2fb78f8b337f27" -and -not (IsExcludedUrl $url)) {
                            # Prepare the output object if conditions are met
                            $outputObj = [PSCustomObject]@{
                                URL          = $url
                                VisitTime    = $dateTime
                                FaviconHash  = $hash
                            }

                            $output += $outputObj
                        }
                    }
                    $bitmapReader.Close()
                } catch {
                    continue
                }
            }
        }
    } catch {
        # Suppress error
    } finally {
        $reader.Close()
        $historyConn.Close()
        $faviconsConn.Close()
    }

    Remove-Item $historyCopy -ErrorAction SilentlyContinue
    Remove-Item $faviconsCopy -ErrorAction SilentlyContinue

    return $output
}

# Process browser histories for each user
foreach ($username in $userProfiles) {
    Write-Host "`nProcessing user: $username" -ForegroundColor Cyan

    # Define paths for Chrome history and favicons databases
    $chromeHistoryPath = "C:\Users\$username\AppData\Local\Google\Chrome\User Data\Default\History"
    $chromeFaviconsPath = "C:\Users\$username\AppData\Local\Google\Chrome\User Data\Default\Favicons"

    # If Chrome has a second profile
    if (-not (Test-Path $chromeHistoryPath) -or -not (Test-Path $chromeFaviconsPath)) {
        # Update variables to use 'Profile 1' directories if 'Default' doesn't exist
        $chromeHistoryPath = "C:\Users\$username\AppData\Local\Google\Chrome\User Data\Profile 1\History"
        $chromeFaviconsPath = "C:\Users\$username\AppData\Local\Google\Chrome\User Data\Profile 1\Favicons"
    }

    # Define initial paths for Edge history and favicons databases
    $edgeHistoryPath = "C:\Users\$username\AppData\Local\Microsoft\Edge\User Data\Default\History"
    $edgeFaviconsPath = "C:\Users\$username\AppData\Local\Microsoft\Edge\User Data\Default\Favicons"

    # If Edge has a second profile
    if (-not (Test-Path $edgeHistoryPath) -or -not (Test-Path $edgeFaviconsPath)) {
        # Update variables to use 'Profile 1' directories if 'Default' doesn't exist
        $edgeHistoryPath = "C:\Users\$username\AppData\Local\Microsoft\Edge\User Data\Profile 1\History"
        $edgeFaviconsPath = "C:\Users\$username\AppData\Local\Microsoft\Edge\User Data\Profile 1\Favicons"
    }

    # Process Chrome and Edge histories
    $chromeOutput = Process-BrowserHistory -historyPath $chromeHistoryPath -faviconsPath $chromeFaviconsPath -browserName "Chrome"
    $edgeOutput = Process-BrowserHistory -historyPath $edgeHistoryPath -faviconsPath $edgeFaviconsPath -browserName "Edge"

    # Combine outputs
    $allOutput = @()
    $allOutput += $chromeOutput
    $allOutput += $edgeOutput

    # Display the output as a table in the console
    if ($allOutput.Count -gt 0) {
        Write-Host "Potential AiTM URLs were found for user $username" -ForegroundColor Red -BackgroundColor White
        Write-Host "=============================="
        $allOutput | Sort-Object VisitTime | Select-Object @{Name="URL"; Expression={($_.URL.Substring(0, [Math]::Min(60, $_.URL.Length)))}}, VisitTime | Format-Table -AutoSize

        Write-Host "=============================="
        # Export to CSV
        $csvPath = "$destinationPath\BrowsingHistory-$username-$date.csv"
        $allOutput | Sort-Object VisitTime | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "Potential AiTM URLs for user $username exported to $csvPath"
    } else {
        Write-Host "No suspected AiTM URLs were found for user $username."
    }
}
