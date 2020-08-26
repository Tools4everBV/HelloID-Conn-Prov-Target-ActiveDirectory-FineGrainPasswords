#Initialize default properties
$p = $person | ConvertFrom-Json;
$success = $False;
$auditMessage = "for person " + $p.DisplayName;
 
#Specify DC
$DC = "<DC FQDN>"
 
#Get AD Account
$account = Get-ADUser -Filter ('employeeID -eq "' + $p.externalId + '"') -Server $DC;
 
#Fine-Grain Password Group
$group = "<Password Policy Group Name>";
 
try {
 
    if(-Not($dryRun -eq $True)) {
        Remove-ADGroupMember -Identity $group -Members $account -Server $DC -Confirm:$false;    
        $response = $true;
    }
    else
    {
        $response = $true;
    }
     
    if($response -eq $true)
    {
        $success = $True;
        $auditMessage = "Removed " + $p.DisplayName + " to password policy group " + $group;
    }
     
}
catch
{
        $auditMessage = $_.toString() + " : General error"
}
 
#build up result
$result = [PSCustomObject]@{
    Success= $success;
    AccountReference= $account_guid;
    AuditDetails=$auditMessage;
    Account = $account;
};
 
#send result back
Write-Output $result | ConvertTo-Json -Depth 10
