<#.
SCRIPTNAME: Check-AllUsersClearText.ps1
AUTHOR: Brandon Colley
AUTHOR EMAIL: Brandon.Colley@trimarcsecurity.com
DESCRIPTION:
This script identifies all accounts in a domain utilizing clear-text passwords via the "Store Password using Reversible Encryption".
It reports on current state of the environment, identifying GPO, FGPP, and UAC settings that configure Reversible Encryption.

https://github.com/MichaelGrafnetter/DSInternals
#Requires -Modules DSInternals
#>

#Variable passed to functions that require domain user information.
$AllUsers = Get-ADUser -Filter * -Properties whenChanged, PasswordLastSet, PasswordNeverExpires, AllowReversiblePasswordEncryption

#Checks the Default Domain Password Policy GPO for password configuration that enables Reversible Encryption domain-wide.
function Get-DDPPInfo{
    Param (
        [string]$verbose
    )
    #Export the Default Domain Policy GPO, injest into xml object to retrieve Modified timestamp and Password Policy data
    Get-GPOReport -Name "Default Domain Policy" -ReportType xml -Path DDPP.xml
    $temp = Get-Content .\DDPP.xml
    $xml = [xml]$temp
    Remove-Item .\DDPP.xml
        
    Write-Host "Default Domain GPO Password Policy Information:"
    if ((Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled -eq $true){
        Write-Host "Critical: Reverse Encryption is enabled Domain Wide. This impacts all users regardless of FGPP or UAC."
            }
    else{
        Write-Host "Reverse Encryption is properly disabled in Domain Password Policy"
    }
    Write-Host "Default Domain Policy GPO was last Modified: " $xml.gpo.ModifiedTime
    if ($verbose){
        Get-ADDefaultDomainPasswordPolicy
    }
}

#Checks all Fine-Grained Password Policies for password configuration that enables Reversible Encryption applied to user accounts or groups.
function Get-FGPPInfo{
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
        $FGPPData | Format-Table -Property name, whenChanged, ReversibleEncryptionEnabled, AppliesTo
    }
}

#Counts the number of users directly configured to allow Reversible Encryption.
function Get-RevEncryptUserInfo{
    Param (
        [string]$verbose
        $userObjects
    )
    
    $ReverseUsers = $AllUsers | Where-Object {$_.AllowReversiblePasswordEncryption -eq $true}
    Write-Host "Number of users directly configured to allow reverse encryption: " $ReverseUsers.count
    if ($verbose){
        Write-Host "Domain Users with Reverse Encryption Enabled via UAC:"
        $reverseUsers | Format-Table name, whenChanged, PasswordLastSet, PasswordNeverExpires
    }
}

#Uses DSInternals cmdlet "Get-ADReplAccount" to check all user accounts with a clear-text password.
#Each account identified is reported along with information regarding how Reversible Encryption has been set on the account.
#WARNING: Verbose mode will display the clear-text password to the screen
function Get-ClearTextUserInfo{
    Param (
        [string]$verbose
        [string]$DChostname
        $userObjects
    }
    
    ForEach-Object ($user in $AllUsers){
        $repluser = Get-ADReplAccount -SamAccountName $i.samaccountname -Server $DChostname 
        $policy = Get-ADUserResultantPasswordPolicy -Identity $i
        $password = $repluser.SupplementalCredentials
        #Only report on accounts that have a ClearText password
        if($null -ne $password.ClearText){
            Write-Host $i.SamAccountName "has a clear-text password."
            #Attempt to determine why a Clear-Text password is set
            if ($i.AllowReversiblePasswordEncryption){
                Write-Host "UAC is configured on this account to directly allow reverse encryption."
                Write-Host "Remove the check-box on this account and change the account password."
            } elseif ($policy.ReversibleEncryptionEnabled){
                Write-Host "The " $policy.Name "FGPP is enforced on this account which allows reverse encryption."
                Write-Host "Remove this policy or disable reversible encryption and change the account password." 
            } else {
                Write-Host "Nothing is currently enforcing reverse encryption. A prior setting or policy must have allowed this configuration."
                Write-Host "Change the account password."
            }

            if ($verbose){
                Write-Host "Clear Text Password:" $password.ClearText
                Write-Host "User account control:" $replUser.useraccountcontrol
                Write-Host "AD Attributes for user object:"
                $i | Format-List samaccountname, whenChanged, PasswordLastSet, PasswordNeverExpires, AllowReversiblePasswordEncryption
                Write-Host "FGPP applied to this account: "
                $policy
            }
        }
    }
}

#### Set the variables
$verboseMode = $false #Change this to true to globally enable verbose mode
$DChostname = localhost #Change this if not running directly on DC

#### Call the functions
Get-DDPPInfo -verbose $verboseMode
Get-FGPPInfo -verbose $verboseMode
Get-RevEncryptUserInfo -verbose $verboseMode
Get-ClearTextUserInfo -verbose $verboseMode -DChostname $DChostname

#Fin
