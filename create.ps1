#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json

$success = $False
$auditLogs = New-Object Collections.Generic.List[PSCustomObject];

#Get Primary Domain Controller
$pdc = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
#endregion Initialize default properties
 
#region Change mapping here
    #Correlation
    $correlationPersonField = ($config.correlationPersonField | Invoke-Expression)
    $correlationAccountField = $config.correlationAccountField

    #Password Config
    $poiicyGroup = "<POLICY GROUP NAME>";
    $length = 16
    $nonAlphaChars = 5
    $defaultPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)

#endregion Change mapping here

#region Execute
try{
        #Find AD Account by attribute/value
        try{
            $filter = "($($correlationAccountField)=$($correlationPersonField))";
            Write-Information "LDAP Filter: $($filter)";
            
            $account = Get-ADUser -LdapFilter $filter -Property sAMAccountName -Server $pdc
            
            if($account -eq $null) { throw "Failed to return a account" }

            Write-Information "Account correlated to $($account.sAMAccountName)";

            $auditLogs.Add([PSCustomObject]@{
                        Action = "CreateAccount"
                        Message = "Account correlated to $($account.sAMAccountName)";
                        IsError = $false;
                    });
        } catch {
            $auditLogs.Add([PSCustomObject]@{
                Action = "CreateAccount"
                Message = "Account failed to correlate:  $_"
                IsError = $True
            });
            throw $_;
        }

        #Apply Password Policy Group
        if(-Not($dryRun -eq $True)){
            try{  
                Add-ADGroupMember -Identity $policyGroup -Members $account -Server $pdc -Confirm:$false;
                Write-Information "Applied $($policyGroup) group to $($account.sAMAccountName)";

                $auditLogs.Add([PSCustomObject]@{
                    Action = "UpdateAccount"
                    Message = "Added $($account.sAMAccountName) to password policy group $($policyGroup)";
                    IsError = $false;
                });
            }catch {
                $auditLogs.Add([PSCustomObject]@{
                    Action = "UpdateAccount"
                    Message = "Failed to add $($account.sAMAccountName) to password policy group $($policyGroup): $($_)";
                    IsError = $true;
                });
                throw $_;
            }
        } else { Write-Information "Password Policy $($policyGroup) would be applied" }

        #Reset Password
        if(-Not($dryRun -eq $True)){
            try {
                Set-ADAccountPassword -Identity $account -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $defaultPassword -Force) -Server $pdc -Confirm:$false;
                Write-Information "Applied $($policyGroup) group to $($account.sAMAccountName)";

                $auditLogs.Add([PSCustomObject]@{
                    Action = "UpdateAccount"
                    Message = "Reset Password for $($account.sAMAccountName) ";
                    IsError = $false;
                });
            } catch {
                $auditLogs.Add([PSCustomObject]@{
                    Action = "UpdateAccount"
                    Message = "Failed to Reset Password for $($account.sAMAccountName): $($_)";
                    IsError = $true;
                });
                throw $_;
            }
        } else { Write-Information "Reset Password $($defaultPassword) would be applied" }

        $success = $true;
    }
    catch {
        Write-Error $_;
    }
}
catch
{
	Write-Error $_;
}
#endregion Execute

#region build up result
$result = [PSCustomObject]@{
    Success= $success;
    AccountReference= $account.SID.Value
    AuditLogs = $auditLogs
    Account = $account;
    ExportData = [PSCustomObject]@{
        sAMAccountName = $account.sAMAccountName;
        policyGroup = $policyGroup;
    }
};

Write-Output $result | ConvertTo-Json -Depth 10
#endregion build up result