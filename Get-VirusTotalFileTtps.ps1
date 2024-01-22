function Get-VirusTotalFileTtps {
    <#
    .SYNOPSIS
        Lookup TTPs associated with a known file on VirusTotal
    .DESCRIPTION
        Lookup TTPs associated with a known file on VirusTotal
    .PARAMETER Hash
        The hash of the file that that you wish to look up on VirusTotal. This can be a MD5, SHA, or SHA256 hash
    .NOTES
        Author: Joel Ashman
        v0.1 - (2024-01-17) Initial version
    .EXAMPLE
        Get-VirusTotalFileTtps -Hash eaad989098815cc44e3bcb21167c7ada72c585fc
    #>
    #requires -version 5

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Hash,
        [switch]$Report
    )
    
    # Not a secure way to store this.  Need a better way
    $ApiKey = "<API Key here>"
    # Build the authentication header
    $Header = @{"x-apikey" = $ApiKey}
    # Base URL for VirusTotal API endpoint
    $HashCheckTtpUrl = "https://www.virustotal.com/api/v3/files/$($Hash)/behaviour_mitre_trees"

    try{\
        # Query the API for any available analyses
        $Analyses = ((Invoke-RestMethod -Method Get -Uri $HashCheckTtpUrl -Headers $Header).data)
        # If there is a result in the VT DB, but no tactics data present, we need to count the number of analyses to determine no result
        if (@($Analyses.psobject.Properties).count -eq 0){Write-Host -ForegroundColor Red "No TTPs found, exiting"}
        # Otherwise, get the results
        else{
            # Get the names of the sandboxes used to analyse this file
            $SandboxesUsed = ($Analyses.PsObject.Members | Where-Object membertype -like 'noteproperty').name
            if ($Report){ # If the -Report switch was passed, iterate through the list of sandbox names and send the output to the screen
                foreach ($Sandbox in $SandboxesUsed){
                    Write-Host -ForegroundColor Green "$($Sandbox) results:"
                    $Analyses.$Sandbox.tactics
                }
            }
            else{
                # Present the list of sandbox names to the user, so that they can iterate as required
                Write-Host -ForegroundColor Cyan "Sandbox results found. The following sandboxes were used:"
                foreach ($Sandbox in $SandboxesUsed){
                    Write-Host -ForegroundColor Green $Sandbox
                }
                Write-Host -ForegroundColor Cyan 'Access individual results via the sandbox name. Eg: $ResultVariable.SandboxName.tactics'
                # Provide the collection of objects
                $Analyses
            }
        }    
    }
    # Catch any errors from interacting with the API, and give a meaningful message to the user
    catch{Write-Warning $Error[0]}   
}
