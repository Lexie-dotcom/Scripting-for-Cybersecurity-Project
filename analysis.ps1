<# Gathers info about processes runnnig on the system. #>
## Adam Lamont
function findProcesses {
    # Scans for suspicious processes running on the system.
    $result = Get-Process | Where-Object CPU -gt 5 # Assuming > 5 could be suspicious.
    return $result
}

function findNetworkConnections {
    # Gets tcp connections made by suspect processes.
   param($processes)
   $processes = $processes | Select-Object ID # Get-NetTcpConnection needs process id as input.
   try{
   # This has to be done as multiple lines (filtering localhost addresses)
   $tcp_connections = Get-NetTcpConnection | 
        Where-Object { 
            ($processes.Id -contains $_.OwningProcess) -and 
            ($_.RemoteAddress -ne '::') -and 
            ($_.RemoteAddress -ne '::1') -and 
            ($_.RemoteAddress -ne '0.0.0.0') -and
            ($_.RemoteAddress -ne '127.0.0.1') 
        } | 
        Select-Object OwningProcess, RemoteAddress
   } catch {
    Write-Output "An error occured, $_ ." # $_ is error variable.
   }
   return $tcp_connections # Returns the object.

}

function hashExecutable {
    param($directories) # Input findProcesses ouput here.
    try{
        $hashes = Get-FileHash $directories -Algorithm SHA256 | Select-Object Path, Hash; # Gets sha256 hash of all files.
        return $hashes;
    } catch{
        "Error: $_ ."
    }

}

$process_output = findProcesses # Ensures no additional processes are added/removed during execution within the custom object.
try{
# Custom object to store data to be converted into json. Runs functions and filters out certain data from them.
$collected_data = [PSCustomObject]@{
    processes = $process_output | Select-Object ID, Name, Path, FileName, MainModule, StartTime, TotalProcessorTime
    hashes = hashExecutable($process_output | Select-Object -ExpandProperty Path) # Expand property makes it a single array which the function needs.
    network = findNetworkConnections($process_output)
}

$collected_data | ConvertTo-Json -Depth 4 | Out-File ps_output.json # Dumping output as json file. Python component is used to iterate through this json.
} catch {
Write-Output "Error. $_"; # Error in case something else in the pipeline doesn't work.
}
