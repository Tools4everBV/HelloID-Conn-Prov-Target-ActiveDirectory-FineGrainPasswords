#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json;

$success = $False
$auditLogs = New-Object Collections.Generic.List[PSCustomObject];

$pdc = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
#endregion Initialize default properties

#region Change mapping here
    #Password Config
    $policyGroup = "<POLICY GROUP NAME>";
#endregion Change mapping here

#region Execute
    #Get AD Account
    $previousAccount = Get-ADUser -Identity $aRef -Server $pdc
    
    try {
        if(-Not($dryRun -eq $True)) {
            Remove-ADGroupMember -Identity $policyGroup -Members $previousAccount -Server $pdc -Confirm:$false;
            Write-Information "Removed $($policyGroup) group to $($previousAccount.sAMAccountName)";

            $auditLogs.Add([PSCustomObject]@{
                Action = "UpdateAccount"
                Message = "Removed $($previousAccount.sAMAccountName) to password policy group $($policyGroup)";
                IsError = $false;
            });
        } else { Write-Information "Password Policy $($policyGroup) would be removed" }

        $success = $True; 
    }
    catch
    {
        $auditLogs.Add([PSCustomObject]@{
                        Action = "UpdateAccount"
                        Message = "Failed to remove $($account.sAMAccountName) to password policy group $($policyGroup): $($_)";
                        IsError = $true;
                    });
        Write-Error $_;
    }
#endregion Execute
 
#region build up result
$result = [PSCustomObject]@{
    Success= $success;
    AuditLogs = $auditLogs
    PreviousAccount = $previousAccount
    Account = [PSCustomObject]@{}
};

Write-Output $result | ConvertTo-Json -Depth 10
#endregion build up result
