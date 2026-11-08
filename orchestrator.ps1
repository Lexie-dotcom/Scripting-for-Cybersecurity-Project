# orchestrator.ps1
# This is the file that the end user should run to run all scripts.
## Adam

param(
    # Defining paths of scripts.
    [string]$PS1Path = ".\analysis.ps1",
    [string]$PyPath = "lookup.py"
)

try {
    Write-Output "Running scripts..";
    Write-Output "Running Powershell script..";
    & $PS1Path; # Runs powershell component.
    Write-Output "Running python script.."; # Running python component.
    $pyOutput = & "python" $PyPath;
    Write-Output $pyOutput > finalOutput.md; # Using powershell to output python output to a markdown file. 
    Write-Output "Successfully saved result to finalOutput.md";
} catch {
    Write-Error "An error occurred: $_" # Error handling in case of error.
    exit 1
}
