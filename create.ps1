#Initialize default properties
$p = $person | ConvertFrom-Json;
$success = $False;
$auditMessage = "for person " + $p.DisplayName;
 
#Specify DC
$DC = "<DC FQDN>
 
#Get AD Account
$account = Get-ADUser -Filter ('employeeID -eq "' + $p.externalId + '"') -Server $DC;
 
#Fine-Grain Password Group
$group = "<POLICY GROUP NAME>";
 
#Password
$Length = 16
$nonAlphaChars = 5
$password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
 
try {
 
    if(-Not($dryRun -eq $True)) {
        Add-ADGroupMember -Identity $group -Members $account -Server $DC -Confirm:$false;
        Set-ADAccountPassword -Identity $account -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force) -Server $DC -Confirm:$false;
        $response = $true;
    }
    else
    {
        $response = $true;
    }
     
    if($response -eq $true)
    {
        $success = $True;
        $auditMessage = "Added " + $p.DisplayName + " to password policy group " + $group + " and reset password";
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
