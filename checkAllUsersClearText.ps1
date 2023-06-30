#features to add: blank out or obviscate pwd vs clear-text; also verbose mode vs just the facts
#modulize this
function GP-Info{
    Param (
        [string]$verbose
    )
    Write-Host "Domain GPO Information:"
    if ((Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled -eq $true){
        Write-Host "Critical: Reverse Encryption is enabled Domain Wide. This impacts all users regardless of FGPP or UAC."
    }
    else{
        Write-Host "Reverse Encryption is properly disabled in Domain Password Policy"
    }
    if ($verbose){
        Get-ADDefaultDomainPasswordPolicy
    }
}

function FGPP-Info{
    Param (
        [string]$verbose
    )
    Write-Host "FGPP Information:"
    $FGPPData = Get-ADFineGrainedPasswordPolicy -Filter * -Properties whenChanged
    $FGPPFound = $false
    foreach ($i in $FGPPData){
        if ($i.ReversibleEncryptionEnabled){
            $FGPPFound = $true
            Write-Host $i.Name "Enables Reverse Encryption on: " $i.AppliesTo
        }
    }
    if (!$FGPPFound){
        Write-Host "Reverse Encryption is properly disabled in All Fine-Grained Password Policies"
    }

    if ($verbose){
        $FGPPData | ft -Property name, whenChanged, ReversibleEncryptionEnabled, AppliesTo
    }
}
function User-Info{
    Param (
        [string]$verbose
    )
    $allusers = Get-ADUser -Filter * -Properties whenChanged, PasswordLastSet, PasswordNeverExpires, AllowReversiblePasswordEncryption
    $reverseUsers = $allusers | where {$_.AllowReversiblePasswordEncryption -eq $true}
    Write-Host "Number of users directly configured to allow reverse encryption: " $reverseUsers.count
    if ($verbose){
        Write-Host "Domain Users with Reverse Encryption Enabled via UAC:"
        $reverseUsers | ft name, whenChanged, PasswordLastSet, PasswordNeverExpires
    }
    foreach ($i in $allusers){
        $replUser = Get-ADReplAccount -SamAccountName $i.samaccountname -Server localhost 
        $policy = Get-ADUserResultantPasswordPolicy -Identity $i
        $password = $replUser.SupplementalCredentials
        #Only report on accounts that have a Clear-Text password
        if($password.ClearText -ne $null){
            Write-Host $i.SamAccountName "has a clear-text password."
            #Attempt to determine why a Clear-Text password is set
            if ($i.AllowReversiblePasswordEncryption){
                Write-Host "UAC is configured on this account to directly allow reverse encryption."
                Write-Host "Remove the check-box on this account and change the account password."
            }
            elseif ($policy.ReversibleEncryptionEnabled){
                Write-Host "The " $policy.Name "FGPP is enforced on this account which allows reverse encryption."
                Write-Host "Remove this policy or disable reversible encryption and change the account password." 
            }
            else{
                Write-Host "Nothing is currently enforcing reverse encryption. A prior setting or policy must have allowed this configuration."
                Write-Host "Change the account password."
            }

            if ($verbose){
                Write-Host "Clear Text Password:" $password.ClearText
                Write-Host "User account control:" $replUser.useraccountcontrol
                Write-Host "AD Attributes for user object:"
                $i | fl samaccountname, whenChanged, PasswordLastSet, PasswordNeverExpires, AllowReversiblePasswordEncryption
                Write-Host "FGPP applied to this account: "
                $policy
            }

        }
    }
}


######################################

$allusers = Get-ADUser -Filter * -Properties whenChanged, PasswordLastSet, PasswordNeverExpires, AllowReversiblePasswordEncryption
Write-Host "Domain Information:"
#GPO
if ((Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled -eq $true){
    Write-Host "Bad Default Domain Password Policy Bro"
}
else{
    Write-Host "This is fine..."
}
#$path = "C:\Users\Administrator\Desktop\gpo.xml"
#Get-GPOReport -ReportType Xml -Name "Default Domain Policy" -Path $path
#$xml = Import-Clixml $path #####This doesn't work yet.
# $gpo = Get-GPO -Name "Default Domain Policy"
# Get-GPRegistryValue -Guid $gpo.id
# can't find the right key yet.
#FGPP
Write-Host "Fine Grained Password Policy Data:"
Get-ADFineGrainedPasswordPolicy -Filter * -Properties whenChanged | ft -Property name, whenChanged, ReversibleEncryptionEnabled, AppliesTo
#Domain Users
$reverseUsers = $allusers | where {$_.AllowReversiblePasswordEncryption -eq $true}
Write-Host "Number of users directly configured to allow reverse encryption: " $reverseUsers.count

foreach ($i in $allusers){
 $temp = Get-ADReplAccount -SamAccountName $i.samaccountname -Server localhost 
 $policy = Get-ADUserResultantPasswordPolicy -Identity $i
 
 #write-host "checking" $i.samaccountname "(" $i.name ")"
 $password = $temp.SupplementalCredentials
 if($password.ClearText -ne $null){
    Write-Host "There be a clear text pwd in here"
    $password.ClearText
    $temp.useraccountcontrol
    $i | fl samaccountname, whenChanged, PasswordLastSet, PasswordNeverExpires, AllowReversiblePasswordEncryption
    Write-Host "FGPP applied & Reverse Encryption is:"
    $policy.Name
    $policy.ReversibleEncryptionEnabled
    }
 else{
    #Write-Host "Properly encrypted password"
    }
}

##Figure out how to cast this as XML to pull out the value for the setting as well as modified date of GPO
##Get-GPOReport -ReportType Xml -Name "Default Domain Policy"
##<q1:Name>ClearTextPassword</q1:Name>
   ##       <q1:SettingBoolean>false</q1:SettingBoolean>
  ##        <q1:Type>Password</q1:Type>