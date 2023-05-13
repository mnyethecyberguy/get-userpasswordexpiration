# Author:		Michael Nye
# Date:         07-11-2014
# Script Name:  Get-UserPasswordExpiration
# Version:      1.0
# Description:  Script to query password expiration of user objects in Active Directory.
# Change Log:	v1.0:	Initial Release

# ------------------- NOTES -----------------------------------------------
# userAccountControl values:
#   514     = Account disabled, password expires
#   66050   = Account disabled, password never expires
#   66082   = Account disabled, password never expires, password not required
#   546     = Account disabled, password must change at logon
#   590338  = Account disabled, user cannot change password, password never expires
#   8389122 = Account disabled, password expired
#   512     = Account enabled, password expires
#   66048   = Account enabled, password never expires
#   66080   = Account enabled, password never expires, password not required
#   544     = Account enabled, password must change at logon
#   590336  = Account enabled, user cannot change password, password never expires
#   8389120 = Account enabled, password expired

# -------------------------------------------------------------------------

# ------------------- IMPORT AD MODULE (IF NEEDED) ------------------------
Import-Module ActiveDirectory


# ------------------- BEGIN USER DEFINED VARIABLES ------------------------
$SCRIPTNAME    	= "Get-UserPasswordExpiration"
$SCRIPTVERSION 	= "1.0"

# ------------------- END OF USER DEFINED VARIABLES -----------------------


# ------------------- BEGIN MAIN SCRIPT VARIABLES -------------------------
# Establish variable with date/time of script start
$Scriptstart = Get-Date -Format G

$strCurrDir 	= split-path $MyInvocation.MyCommand.Path
$strLogFolder 	= "$SCRIPTNAME -{0} {1}" -f ($_.name -replace ", ","-"),($Scriptstart -replace ":","-" -replace "/","-")
$strLogPath 	= "$strCurrDir\logs"

# Create log folder for run and logfile name
New-Item -Path $strLogPath -name $strLogFolder -itemtype "directory" -Force > $NULL
$LOGFILE 		= "$strLogPath\$strLogFolder\$SCRIPTNAME.log"
$csvResults     = "$strLogPath\$strLogFolder\Results.csv"

# Create ldap query.
# Requirements:
#   1) empType != ServiceAccount, TestUser, TrainingUser
$queryLdap = '(&(!employeeType=ServiceAccount)(!employeeType=TestUser)(!employeeType=TrainingUser))'

# set search domain FQDN for -Server switch of Get-ADUser
$domainFQDN = "mydomain.com"

# set LDAP searchbase for Get-ADUser
$searchBase = "OU=MyUsers,DC=mydomain,DC=com"

# list of user properties to pull
$listProperties = 'givenName','sn','displayName','sAMAccountName','pwdLastSet','msDS-UserPasswordExpiryTimeComputed','lastLogonTimestamp','distinguishedName','whenCreated','userAccountControl'

# list of user properties to send to results
$listResultsProperties = 'givenName','sn','displayName','sAMAccountName','PasswordLastSet','Enabled','PasswordExpiration','PasswordNeverExpires','lastLogonTime','distinguishedName','whenCreated'

# setup array to store result
$arrReport      = @()

# ------------------- END MAIN SCRIPT VARIABLES ---------------------------


# ------------------- DEFINE FUNCTIONS - DO NOT MODIFY --------------------

Function genReports
{
	if ($arrReport.Count -gt 0)
	{
		$arrReport | Export-CSV -NoTypeInformation $csvResults
	}
}

Function Writelog ($LogText)
{
	$date = Get-Date -format G
	
    write-host "$date $LogText"
	write-host ""
	
    "$date $LogText" >> $LOGFILE
	"" >> $LOGFILE
}

Function BeginScript () {
    Writelog "-------------------------------------------------------------------------------------"
    Writelog "**** BEGIN SCRIPT AT $Scriptstart ****"
    Writelog "**** Script Name:     $SCRIPTNAME"
    Writelog "**** Script Version:  $SCRIPTVERSION"
    Writelog "-------------------------------------------------------------------------------------"

    $error.clear()
}

Function EndScript () {
    Writelog "-------------------------------------------------------------------------------------"
    Writelog "**** SCRIPT RESULTS ****"
    Writelog "**** SUCCESS Count = $CountSuccess"
    Writelog "**** ERROR Count   = $CountError"
    Writelog "-------------------------------------------------------------------------------------"

	$Scriptfinish = Get-Date -Format G
	$span = New-TimeSpan $Scriptstart $Scriptfinish
	
  	Writelog "-------------------------------------------------------------------------------------"
  	Writelog "**** $SCRIPTNAME script COMPLETED at $Scriptfinish ****"
	Writelog $("**** Total Runtime: {0:00} hours, {1:00} minutes, and {2:00} seconds ****" -f $span.Hours,$span.Minutes,$span.Seconds)
	Writelog "-------------------------------------------------------------------------------------"
}

# ------------------- END OF FUNCTION DEFINITIONS -------------------------


# ------------------- SCRIPT MAIN - DO NOT MODIFY -------------------------

BeginScript

$CountError = 0
$CountSuccess = 0

$arrUsers = Get-ADUser -LDAPFilter $queryLdap -Server $domainFQDN -SearchBase $searchBase -Properties $listProperties

Writelog "-------------------------------------------------------------------------------------"
Writelog "**** $($arrUsers.Count) users collected. Processing user account information. ****"
Writelog "-------------------------------------------------------------------------------------"

ForEach ($user in $arrUsers)
{
    $uac = $($user.userAccountControl)
    $pwdExpiration = $null

    # account is disabled
    If (($uac -eq 514) -or ($uac -eq 66050) -or ($uac -eq 66082) -or ($uac -eq 546) -or ($uac -eq 590338) -or ($uac -eq 8389122))
    {
        $user | Add-Member -MemberType NoteProperty -Name AccountIsEnabled -Value $false -Force

        # password never expires
        If (($uac -eq 66050) -or ($uac -eq 66082) -or ($uac -eq 590338))
        {
            $user | Add-Member -MemberType NoteProperty -Name PasswordNeverExpires -Value $true -Force
            $user | Add-Member -MemberType NoteProperty -Name PasswordExpiration -Value "Never" -Force
        }

        # password expires normally
        Else
        {
            $user | Add-Member -MemberType NoteProperty -Name PasswordNeverExpires -Value $false -Force

            # get password expiration date
            $pwdExpiration = [datetime]::FromFileTime($user."msDS-UserPasswordExpiryTimeComputed")

            $user | Add-Member -MemberType NoteProperty -Name PasswordExpiration -Value $pwdExpiration -Force
        }

        $CountSuccess++
    }

    # account is enabled
    ElseIf (($uac -eq 512) -or ($uac -eq 66048) -or ($uac -eq 66080) -or ($uac -eq 544) -or ($uac -eq 590336) -or ($uac -eq 8389120))
    {
        $user | Add-Member -MemberType NoteProperty -Name AccountIsEnabled -Value $true -Force

        # password never expires
        If (($uac -eq 66048) -or ($uac -eq 66080) -or ($uac -eq 590336))
        {
            $user | Add-Member -MemberType NoteProperty -Name PasswordNeverExpires -Value $true -Force
            $user | Add-Member -MemberType NoteProperty -Name PasswordExpiration -Value "Never" -Force
        }

        # password expires normally
        Else
        {
            $user | Add-Member -MemberType NoteProperty -Name PasswordNeverExpires -Value $false -Force

            # get password expiration date
            $pwdExpiration = [datetime]::FromFileTime($user."msDS-UserPasswordExpiryTimeComputed")

            $user | Add-Member -MemberType NoteProperty -Name PasswordExpiration -Value $pwdExpiration -Force
        }

        $CountSuccess++
    }

    # need to research uac value
    Else
    {
        $user | Add-Member -MemberType NoteProperty -Name AccountIsEnabled -Value "Research uac" -Force
        $user | Add-Member -MemberType NoteProperty -Name PasswordNeverExpires -Value "Research uac" -Force
        $user | Add-Member -MemberType NoteProperty -Name PasswordExpiration -Value "Research uac" -Force

        $CountError++
    }

    # ----------------------------------------------
    # convert pwdLastSet into datetime
    If (($null -eq $user.pwdLastSet) -or ($user.pwdLastSet -eq 0))
    {
        $pwdLastSet = "Never"
    }
    
    Else
    {
        $pwdLastSet = [datetime]::FromFileTime($user.pwdLastSet)
    }

    # ----------------------------------------------
    # convert lastLogonTimestamp into datetime
    If ($null -eq $user.lastLogonTimestamp)
    {
        $lastLogonTimestamp = "Never"
    }
    
    Else
    {
        $lastLogonTimestamp = [datetime]::FromFileTime($user.lastLogonTimestamp)
    }

    # ----------------------------------------------
    $user | Add-Member -MemberType NoteProperty -Name PasswordLastSet -Value $pwdLastSet -Force
    $user | Add-Member -MemberType NoteProperty -Name LastLogonTime -Value $lastLogonTimestamp -Force
    
    $arrReport += $user | Select-Object $listResultsProperties
}

genReports

# ------------------- END OF SCRIPT MAIN ----------------------------------


# ------------------- CLEANUP ---------------------------------------------


# ------------------- SCRIPT END ------------------------------------------
$error.clear()

EndScript
