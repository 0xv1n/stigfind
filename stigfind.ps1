# ########################################################################################
#  _______ _______ ___ _______        _______ __          __
# |   _   |       |   |   _   |______|   _   |__.-----.--|  |
# |   1___|.|   | |.  |.  |___|______|.  1___|  |     |  _  |
# |____   `-|.  |-|.  |.  |   |      |.  __| |__|__|__|_____|
# |:  1   | |:  | |:  |:  1   |      |:  |
# |::.. . | |::.| |::.|::.. . |      |::.|    author: 0xv1n             
# `-------' `---' `---`-------'      `---'
# A free and open source STIG compliance audit tool.   
# 
# Purpose: 
#     This project exists to bring STIG compliance auditing to the hands of anyone. 
#     STIG-Find is built upon the Pester test framework, and allows unit-test style 
#     programatic auditing of the DISA STIGs for Windows 10 Enterprise images.
#
# NOTE: 
#     Checks are performed as specified in the MITRE InSpec profile. e.g.,
#     If a value is NOT what is specified, it is a "finding".
#     This can mean that it is configured incorrectly, exists, or does not exist.
#     
#   For full documentation, refer to MITRE repo, descriptions will not be copied.
# 
# Reference Source:
#   https://github.com/mitre/microsoft-windows-10-stig-baseline/tree/master/controls
# 
# ########################################################################################

Describe "Software Policies" {
  Context "Operating System" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63319.rb
    It "V-63319: Domain-joined systems must use Windows 10 Enterprise Edition 64-bit version." {
      $edition = (Get-WindowsEdition -Online).Edition
      $arch = (Get-Wmiobject Win32_Processor).AddressWidth
      If (($edition -eq "Enterprise") -and ($arch -eq 64)) { $setting = 0 } Else { $setting = 1 }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63337.rb
    It "V-63337: Windows 10 information systems must use BitLocker to encrypt all disks to protect the confidentiality and integrity of all information at rest." {
      # this is hacky, essentially loops through every volume and if it finds a singly unencrypted volume this fails
      foreach ($volume in Get-BitLockerVolume) { If ($volume.ProtectionStatus -eq "Off") { $setting = 1; break } Else { $setting = 0 } }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63349.rb
    It "V-63349-CurrentVersion: Windows 10 systems must be maintained at a supported servicing level." {
      $setting = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion
      $setting | Should -BeGreaterOrEqual 6.3
    }
    It "V-63349-CurrentVersion: Windows 10 systems must be maintained at a supported servicing level." {
      $setting = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
      $setting | Should -BeGreaterOrEqual 1703
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63355.rb
    It "V-63355: Alternate operating systems must not be permitted on the same system." {
      $setting =  (bcdedit | Findstr description | Findstr /v /c:'Windows Boot Manager').split(" ",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Be "10"
    }
  }

  Context "Anti-Virus" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63351.rb
    It "V-63351: The Windows 10 system must use an anti-virus program." {
      # TEST: Need testing to determine if this is correct for anything beyond Defender
      $setting = (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).ProductState
      $setting | Should -Be 397568  # enabled and up to date
    }
  }

  Context "Registry" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63321.rb
    It "V-63321: Users must be prevented from changing installation options." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer").EnableUserControl
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63325.rb
    It "V-63325: The Windows Installer Always install with elevated privileges must be disabled." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63329.rb
    It "V-63329: Users must be notified if a web-based program attempts to install software." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer").SafeForScripting
      $setting | Should -Not -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63333.rb
    It "V-63333: Automatically signing in the last interactive user after a system-initiated restart must be disabled." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").DisableAutomaticRestartSignOn
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63335.rb
    It "V-63335: The Windows Remote Management (WinRM) client must not use Basic authentication." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client").AllowBasic
      $setting | Should -Be 0   
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63339.rb
    It "V-63339: The Windows Remote Management (WinRM) client must not allow unencrypted traffic." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client").AllowUnencryptedTraffic
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63341.rb
    It "V-63341: The Windows Remote Management (WinRM) client must not use Digest authentication." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client").AllowDigest
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63347.rb
    It "V-63347: The Windows Remote Management (WinRM) service must not use Basic authentication." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service").AllowBasic
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63369.rb
    It "V-63369: The Windows Remote Management (WinRM) service must not allow unencrypted traffic." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service").AllowUnencryptedTraffic
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63375.rb
    It "V-63375: The Windows Remote Management (WinRM) service must not store RunAs credentials." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service").DisableRunAs
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63519.rb
    It "V-63519: The Application event log size must be configured to 32768 KB or greater." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application").MaxSize
      $setting | Should -BeGreaterOrEqual 32768
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63523.rb
    It "V-63523: The Security event log size must be configured to 1024000 KB or greater." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security").MaxSize
      $setting | Should -BeGreaterOrEqual 1024000
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63527.rb
    It "V-63527: The System event log size must be configured to 32768 KB or greater." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System").MaxSize
      $setting | Should -BeGreaterOrEqual 32768
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63545.rb
    It "V-63545: Camera access from the lock screen must be disabled." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization").NoLockScreenCamera
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63549.rb
    It "V-63549: The display of slide shows on the lock screen must be disabled." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization").NoLockScreenSlideshow
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63555.rb
    It "V-63555: IPv6 source routing must be configured to highest protection." {
      $setting = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters").DisableIPSourceRouting
      $setting | Should -Be 2
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63563.rb
    It "V-63563: The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes." {
      $setting = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters").EnableICMPRedirect
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63567.rb
    It "V-63567: The system must be configured to ignore NetBIOS name release requests except from WINS servers." {
      $setting = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters").NoNameReleaseOnDemand
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63569.rb
    It "V-63569: Insecure logons to an SMB server must be disabled." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation").AllowInsecureGuestAuth
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63581.rb
    It "V-63581: Simultaneous connections to the Internet or a Windows domain must be limited." {
      $checkdomainjoined = ((wmic computersystem get domain | FINDSTR /V Domain).split(" ",[StringSplitOptions]'RemoveEmptyEntries'))
      If ($checkdomainjoined -eq 'WORKGROUP') { 
        $setting = 0
        $setting | Should -Be 0 -Because "The system is not a member of a domain, control is NA" 
      }
      Else {
        $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy").fMinimizeConnections
        $setting | Should -Be 1
      }
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63585.rb
    It "V-63585: Connections to non-domain networks when connected to a domain authenticated network must be blocked." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy").fBlockNonDomain
      $setting | Should -Be 1  
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63591.rb
    It "V-63591: 'Wi-Fi Sense must be disabled." {
      $curver = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
      If ($curver -gt 1803) { $setting = 2 }
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config").AutoConnectAllowedOEM
      $setting | Should -Be 2 -Because "This is NA as of v1803 of Windows 10; Wi-Fi sense is no longer available."
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63615.rb
    It "V-63615: Downloading print driver packages over HTTP must be prevented." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers").DisableWebPnPDownload
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63617.rb
    It "V-63617: Local accounts with blank passwords must be restricted to prevent access from the network" {
      $setting = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").LimitBlankPasswordUse
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63621.rb
    It "V-63621: Web publishing and online ordering wizards must be prevented from downloading a list of providers." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer").NoWebServices
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63623.rb
    It "V-63623: Printing over HTTP must be prevented." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers").DisableHTTPPrinting
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63627.rb
    It "V-63627: Systems must at least attempt device authentication using certificates." {
      $checkdomainjoined = ((wmic computersystem get domain | FINDSTR /V Domain).split(" ",[StringSplitOptions]'RemoveEmptyEntries'))
      If ($checkdomainjoined -eq 'WORKGROUP') { 
        $setting = 0
        $setting | Should -Be 0 -Because "The system is not a member of a domain, control is NA" 
      }
      Else {
        $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters").DevicePKInitEnabled
        $setting | Should -Be 1
      }
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-88203.rb
    It "V-88203: OneDrive must only allow synchronizing of accounts for DoD organization instances." {
      # INPUT - Change value to Organization Tenant GUID
      $approvedguids = @('{YOUR-ORGANIZATION-GUID-HERE}', '{1111-2222-3333-4444}')
      $onedrivesetting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\AllowTenantList")
      If ($onedrivesetting -in $approvedguids) { $setting = 0 } Else { $setting = 1 }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-94719.rb
    It "V-94719: Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked." {
      $voiceabove = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy").LetAppsActivateWithVoiceAboveLock
      $voice = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy").LetAppsActivateWithVoice
      If (($voiceabove -eq 2) -and ($voice -eq 2)) { $setting = 0 } Else { $setting = 1 }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-94859.rb
    It "V-94859: Windows 10 systems must use a BitLocker PIN for pre-boot authentication." {
      $advstartup = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE").UseAdvancedStartup
      $tpmpin = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE").UseTPMPIN
      $tpmkeypin = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE").UseTPMKeyPIN
      If (($advstartup -eq 1) -and ($tpmpin -eq 1) -and ($tpmkeypin -eq 1)) {
        $setting = 0;
      } Else { $setting = 1 }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-94861.rb
    It "V-94861: Windows 10 systems must use a BitLocker PIN with a minimum length of <x> digits for pre-boot authentication." {
      # INPUT - Change x value to desired value. NA for VDIs
      $inval = 0
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Bitlocker").MinimumPIN
      $setting | Should -BeGreaterOrEqual $inval
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-99557.rb
    It "V-99557: Windows 10 Kernel (Direct Memory Access) DMA Protection must be enabled." {
      $setting = (Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection").DeviceEnumerationPolicy
      $setting | SHould -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-99559.rb
    It "V-99559: The convenience PIN for Windows 10 must be disabled." {
      $setting = (Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\System").AllowDomainPINLogon
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-99561.rb
    It "V-99561: Windows Ink Workspace configured but disallow access above the lock." {
      $setting = (Get-ItemProperty "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace").AllowWindowsInkWorkspace
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-99563.rb
    It "V-99563: Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications." {
      $setting = (Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\CloudContent").DisableThirdPartySuggestions
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63629.rb
    It "V-63629: The network selection user interface (UI) must not be displayed on the logon screen." {
      $setting = (Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\System").DontDisplayNetworkSelectionUI
      $setting | Should -Be 1
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63633.rb
    It "V-63633: Local users on domain-joined computers must not be enumerated" {
      $checkdomainjoined = (wmic computersystem get domain | FINDSTR /V Domain).split(" ",[StringSplitOptions]'RemoveEmptyEntries')
      If ($checkdomainjoined -eq 'WORKGROUP') { 
        $setting = 0
        $setting | Should -Be 0 -Because "The system is not a member of a domain, control is NA" 
      }  
      $setting = (Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\System").EnumerateLocalUsers
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63635.rb
    It "V-63635: Audit policy using subcategories must be enabled." {
      $setting = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa").SCENoApplyLegacyAuditPolicy
      $setting | Should -Be 1
    }
  }

  Context "Additional Features" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63377.rb
    It "V-63377: Internet Information System (IIS) or its subcomponents must not be installed on a workstation." {
      foreach($iis in (Get-WindowsOptionalFeature -Online -FeatureName “IIS*”)) { If ($iis.State -ne 'Disabled') { $setting = 1; break } Else { $setting = 0 } }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63381.rb
    It "V-63381: Simple Network Management Protocol (SNMP) must not be installed on the system." {
      $setting = (Get-WindowsCapability -Online -Name "SNMP*").State
      $setting | Should -Be "NotPresent"
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63383.rb
    It "V-63383: Simple TCP/IP Services must not be installed on the system." {
      $setting = (Get-WindowsOptionalFeature -Online -FeatureName "SimpleTCP").State
      $setting | Should -Be "Disabled"
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63385.rb
    It "V-63385: The Telnet Client must not be installed on the system." {
      $setting = (Get-WindowsOptionalFeature -Online -FeatureName "TelnetClient").State
      $setting | Should -Be "Disabled"
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63389.rb
    It "V-63389: The TFTP Client must not be installed on the system." {
      $setting = (Get-WindowsOptionalFeature -Online -FeatureName "TFTP").State
      $setting | Should -Be "Disabled"
    }
  }

  Context "Firewall" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63399.rb
    It "V-63399: A host-based firewall must be installed and enabled on the system." {
      # Iterates through Domain, Private, and Public Firewall profiles. All must be enabled. 
      foreach ($fw in ((Get-NetFirewallProfile).Enabled)) { If ($fw -eq "False") { $setting = 1; break } Else { $setting = 0 } }
      $setting | Should -Be 0
    }
  }

  Context "Certificates" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63393.rb
    It "V-63393: Software certificate installation files must be removed from Windows 10." {
      # ! this is an expensive command - will need to explore alternatives.
      $pfx = cmd /c 'where /R c:\ *.p12 *.pfx'
      If ($pfx -ne '') { 
        $setting = 1
        break 
      }
      Else {
        $setting = 0
      }
      $setting | Should -Be 0
    }
  }
}

Describe "Hardware Policies" {
  Context "TPM" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63323.rb
    It "V-63323: Windows 10 domain-joined systems must have a Trusted Platform Module (TPM) enabled." {
      $present = (Get-Tpm).TpmPresent
      $ready = (Get-Tpm).TpmReady
      If ($present -and $ready) { $setting = 0 } Else { $setting = 1 }
      $setting | Should -Be 0
    }
  }

  Context "Logical Drives" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63353.rb
    It "V-63353: Local volumes must be formatted using NTFS." {
      foreach ($disk in (wmic logicaldisk get FileSystem | findstr /r /v '^$' |Findstr /v 'FileSystem')) { If ($disk -ne "NTFS") { $setting = 1; break } Else { $setting = 0 } }
      $setting | Should -Be 0
    }
  }
}

Describe "Account Policies" {
  Context "Administrative Accounts" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63361.rb
    It "V-63361: Only accounts responsible for the administration of a system must have Administrator rights on the system." {
      # Any accounts found added to this group should be reviewed per the STIG.
      # Note: The default local Administrator account should not be enabled in a domain per V-63367, but this may flag it.
      foreach ($acct in (net localgroup Administrators | Format-List | Findstr /V 'Alias Name Comment Members - command')) { If ($acct -ne "") { $setting = 1; break } Else { $setting = 0 } }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63363.rb
    It "V-63363: Only accounts responsible for the backup operations must be members of the Backup Operators group." {
      # Any accounts found added to this group should be reviewed per the STIG.
      foreach ($acct in (net localgroup "Backup Operators" | Format-List | Findstr /V 'Alias Name Comment Members - command')) { If ($acct -ne "") { $setting = 1; break } Else { $setting = 0 } }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63365.rb
    It "V-63365: Only authorized user accounts must be allowed to create or run virtual machines on Windows 10 systems." {
      # Any accounts found added to this group should be reviewed per the STIG.
      foreach ($acct in (net localgroup "Hyper-V Administrators" | Format-List | Findstr /V 'Alias Name Comment Members - command')) { If ($acct -ne "") { $setting = 1; break } Else { $setting = 0 } }
      $setting | Should -Be 0
    }
  }

  Context "Default Accounts" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63367.rb
    It "V-63367: Standard local user accounts must not exist on a system in a domain." {
      $default_acct = @('Administrator', 'Guest', 'DefaultAccount', 'defaultuser0', 'WDAGUtilityAccount')
      # Note: A single enabled default account fails this test, review the list of local users.
      foreach ($acct in $default_acct) { If ((Get-LocalUser $acct).Enabled -eq "True") { $setting = 1; break } Else { $setting = 0 } }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63611.rb
    It "V-63611: The built-in guest account must be disabled." {
      $setting = (Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='$true'" | Where-Object {$_.Name -eq 'Guest'} | ForEach-Object { $_.Disabled })
      $setting | Should -Be 'True'
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63619.rb
    It "V-63619: The built-in administrator account must be renamed." {
      $setting = (Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='$true'" | Where-Object {$_.Name -eq 'Administrator'} | ForEach-Object { $_.Disabled })
      $setting | Should -BeNullOrEmpty -Because "Administrator account should be renamed."
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63625.rb
    It "V-63625: The built-in guest account must be renamed." {
      $setting = (Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='$true'" | Where-Object {$_.Name -eq 'Guest'} | ForEach-Object { $_.Disabled })
      $setting | Should -BeNullOrEmpty -Because "Guest account should be renamed."
    }
  }

  Context "Passwords" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63371.rb
    It "V-63371: Accounts must be configured to require password expiration." {
      foreach ($acct in (Get-CimInstance -Class Win32_Useraccount -Filter 'PasswordExpires=False and LocalAccount=True and Disabled=False' | Format-Table Name | Findstr /V 'Name --')) { If ($acct -ne "") {$setting = 1; break} Else { $setting = 0 } }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63415.rb
    It "V-63415: The password history must be configured to 24 passwords remembered." {
      $setting = ((net accounts | findstr "history").split(':')[1] | Out-String).Trim()
      $setting | Should -Not -Be "Never"
      $setting | Should -BeGreaterOrEqual 24
    }
  }

  Context "Security" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63405.rb
    It "V-63405: Windows 10 account lockout duration must be configured to <x> minutes or greater." {
      $x = 30
      # Microsoft default is 30 minutes - We will check if it's less.
      # This does not currently use AD objects - adjust as needed.
      $setting = ((net accounts | findstr "Lockout" | findstr "duration").split(':')[1] | Out-String).Trim()
      $setting | Should -BeGreaterOrEqual $x
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63409.rb
    It "V-63409: The number of allowed bad logon attempts must be configured to <x> or less." {
      # Never, 0, or too high a number fail this test. Replace x val with reasonable value.
      $x = 3
      $setting = ((net accounts | findstr "Lockout" | findstr "threshold").split(':')[1] | Out-String).Trim()
      $setting | Should -Not -Be "Never"
      $setting | Should -BeGreaterOrEqual $x
    }
  }
}
  
Describe "Audit Logging" {
# ! GUIDs retrieved via -- auditpol /list /subcategory:* /r
  Context "Account Logon" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63431.rb
    It "V-63431: The system must be configured to audit Account Logon - Credential Validation failures." {
      $setting = (auditpol /get /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63435.rb
    It "V-63435: The system must be configured to audit Account Logon - Credential Validation successes." {
      $setting = (auditpol /get /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
  }

  Context "Account Management" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63445.rb
    It "V-63445: The system must be configured to audit Account Management - Security Group Management successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63447.rb
    It "V-63447: The system must be configured to audit Account Management - User Account Management failures." {
      $setting = (auditpol /get /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63449.rb
    It "V-63449: The system must be configured to audit Account Management - User Account Management successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
  }
  
  Context "Detailed Tracking" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63451.rb
    It "V-63451: The system must be configured to audit Detailed Tracking - PNP Activity successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9248-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63453.rb
    It "V-63453: The system must be configured to audit Detailed Tracking - Process Creation successes." {
      $setting = (auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
  }

  Context "Logon/Logoff" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63457.rb
    It "V-63457: The system must be configured to audit Logon/Logoff - Group Membership successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9249-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63459.rb
    It "V-63459: The system must be configured to audit Logon/Logoff - Logoff successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63463.rb
    It "V-63463: The system must be configured to audit Logon/Logoff - Logon failures." {
      $setting = (auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63467.rb
    It "V-63467: The system must be configured to audit Logon/Logoff - Logon successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63469.rb
    It "V-63469: The system must be configured to audit Logon/Logoff - Special Logon successes." {
      $setting = (auditpol /get /subcategory:"{0CCE921B-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-99543.rb
    It "V-99541: Windows 10 must be configured to audit other Logon/Logoff Events Failures." {
      $setting = (auditpol /get /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")     
    }    
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-99543.rb
    It "V-99543: Windows 10 must be configured to audit other Logon/Logoff Events Successes." {
      $setting = (auditpol /get /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")     
    }
  }

  Context "Object Access" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63471.rb
    It "V-63471: The system must be configured to audit Object Access - Removable Storage failures." {
      $setting = (auditpol /get /subcategory:"{0CCE9245-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63473.rb
    It "V-63473: The system must be configured to audit Object Access - Removable Storage successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9245-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-99545.rb
    It "V-99545: Windows 10 must be configured to audit Detailed File Share Failures." {
      $setting = (auditpol /get /subcategory:"{0CCE9244-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")     
    }
  }

  Context "Policy Change" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63479.rb
    It "V-63479: The system must be configured to audit Policy Change - Audit Policy Change successes." {
      $setting = (auditpol /get /subcategory:"{0CCE922F-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")    
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63481.rb
    It "V-63481: The system must be configured to audit Policy Change - Authentication Policy Change successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9230-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-99547.rb
    It "V-99547: Windows 10 must be configured to audit MPSSVC Rule-Level Policy Change Successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9232-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-99549.rb
    It "V-99549: Windows 10 must be configured to audit MPSSVC Rule-Level Policy Change Failures." {
      $setting = (auditpol /get /subcategory:"{0CCE9232-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-99551.rb
    It "V-99551: Windows 10 must be configured to audit Other Policy Change Events Successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9234-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-99553.rb
    It "V-99553: Windows 10 must be configured to audit Other Policy Change Events Failures." {
      $setting = (auditpol /get /subcategory:"{0CCE9234-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")
    }
  }

  Context "Privilege Use" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63483.rb
    It "V-63483: The system must be configured to audit Privilege Use - Sensitive Privilege Use failures." {
      $setting = (auditpol /get /subcategory:"{0CCE9228-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63487.rb
    It "V-63487: The system must be configured to audit Privilege Use - Sensitive Privilege Use successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9228-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
  }

  Context "System" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63491.rb
    It "V-63491: The system must be configured to audit System - IPSec Driver failures." {
      $setting = (auditpol /get /subcategory:"{0CCE9213-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63499.rb
    It "V-63499: The system must be configured to audit System - Other System Events successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9214-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63503.rb
    It "V-63503: The system must be configured to audit System - Other System Events failures." {
      $setting = (auditpol /get /subcategory:"{0CCE9214-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63507.rb
    It "V-63507: The system must be configured to audit System - Security State Change successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9210-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63513.rb
    It "V-63513: The system must be configured to audit System - Security System Extension successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9211-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63515.rb
    It "V-63515: The system must be configured to audit System - System Integrity failures." {
      $setting = (auditpol /get /subcategory:"{0CCE9212-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Failure", "Success and Failure")
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63517.rb
    It "V-63517: The system must be configured to audit System - System Integrity successes." {
      $setting = (auditpol /get /subcategory:"{0CCE9212-69AE-11D9-BED3-505054503030}" /r).split(",",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $setting | Should -Not -Be "No Auditing"
      $setting | Should -BeIn @("Success", "Success and Failure")
    }
  }

}

Describe "File Permissions" {
  Context "System Directories" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63373.rb
    # Separated to check each default system dir - a single incorrect/unexpected perm fails.
    # For C:\\ local users that can write to this directory will trigger a fail condition
    #   local SID perms are usually listed first.
    It "V-63373-C:\\: Permissions for system files and directories must conform to minimum requirements." {
      $default_perms = @(
        'BUILTIN\\Administrators:(OI)(CI)(F)',
        'NT AUTHORITY\\SYSTEM:(OI)(CI)(F)',
        'BUILTIN\\Users:(OI)(CI)(RX)', 
        'NT AUTHORITY\\Authenticated Users:(OI)(CI)(IO)(M)', 
        'NT AUTHORITY\\Authenticated Users:(AD)', 
        'Mandatory Label\\High Mandatory Level:(OI)(NP)(IO)(NW)'
      )
      foreach($line in (icacls 'C:\\' | Findstr /V 'Successfully' | Findstr /r /v "^$")) { $trimmed = ($line | Out-String).Trim(); If ($trimmed -in $default_perms) { $setting = 0 } Else { $setting = 1; break } }
      $setting | Should -Be 0
    }
    It "V-63373-C:\\Program Files: Permissions for system files and directories must conform to minimum requirements." {
      $default_perms = @(
        'C:\\Program Files NT SERVICE\TrustedInstaller:(F)',
        'NT SERVICE\\TrustedInstaller:(CI)(IO)(F)',
        'NT AUTHORITY\\SYSTEM:(M)',
        'NT AUTHORITY\\SYSTEM:(OI)(CI)(IO)(F)',
        'BUILTIN\\Administrators:(M)',
        'BUILTIN\\Administrators:(OI)(CI)(IO)(F)',
        'BUILTIN\\Users:(RX)',
        'BUILTIN\\Users:(OI)(CI)(IO)(GR,GE)',
        'CREATOR OWNER:(OI)(CI)(IO)(F)',
        'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(RX)',
        'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)',
        'APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:(RX)',
        'APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION',
        'PACKAGES:(OI)(CI)(IO)(GR,GE)'
      )
      foreach($line in (icacls 'C:\\Program Files' | Findstr /V 'Successfully' | Findstr /r /v "^$")) { $trimmed = ($line | Out-String).Trim(); If ($trimmed -in $default_perms) { $setting = 0 } Else { $setting = 1; break }  }
      $setting | Should -Be 0
    }
    It "V-63373-C:\\Windows: Permissions for system files and directories must conform to minimum requirements." {
      $default_perms = @(
        'C:\\Windows NT SERVICE\TrustedInstaller:(F)',
        'NT SERVICE\\TrustedInstaller:(CI)(IO)(F)',
        'NT AUTHORITY\\SYSTEM:(M)',
        'NT AUTHORITY\\SYSTEM:(OI)(CI)(IO)(F)',
        'BUILTIN\\Administrators:(M)',
        'BUILTIN\\Administrators:(OI)(CI)(IO)(F)',
        'BUILTIN\\Users:(RX)',
        'BUILTIN\\Users:(OI)(CI)(IO)(GR,GE)',
        'CREATOR OWNER:(OI)(CI)(IO)(F)',
        'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(RX)',
        'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)',
        'APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:(RX)',
        'APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION',
        'PACKAGES:(OI)(CI)(IO)(GR,GE)'
      )
      foreach($line in (icacls 'C:\\Windows' | Findstr /V 'Successfully' | Findstr /r /v "^$")) { $trimmed = ($line | Out-String).Trim(); If ($trimmed -in $default_perms) { $setting = 0 } Else {$setting = 1; break}  }
      $setting | Should -Be 0
    }
  }

  Context "File Shares" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63357.rb
    It "V-63357: Non system-created file shares on a system must limit access to groups that require it." {
      $default_share_paths = @('C:\WINDOWS', 'C:\')
      foreach ($path in ((Get-WMIObject -Query "SELECT * FROM Win32_Share" | Select-Object Path | Findstr /V "Path --" | Out-String).Trim()))
      {
        If ($path -in $default_share_paths) { continue }
        Else {
          If ((Get-Acl -Path $path | Format-List | Findstr /i /C:'Everyone Allow') -ne '') {
            $setting = 1
            break
          }
          Else { $setting = 0 }
        }
      }
      $setting | Should -Be 0
    }
  }

  Context "Event Logs" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63533.rb
    It "V-63533: Windows 10 permissions for the Application event log must prevent access by non-privileged accounts." {
      $privaccts = @('NT SERVICE\EventLog', 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')
      $evtx = Application.evtx
      $sysroot = (Get-ChildItem Env: | Findstr SystemRoot).split(" ",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $evtxpath = "$sysroot\SYSTEM32\WINEVT\LOGS\$evtx"
      foreach ($identity in ((Get-Acl $evtxpath).Access).IdentityReference) { If ($identity -in $privaccts) {$setting = 0} Else {$setting = 1; break} }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63537.rb
    It "V-63537: Windows 10 permissions for the Security event log must prevent access by non-privileged accounts." {
      $privaccts = @('NT SERVICE\EventLog', 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')
      $evtx = Security.evtx
      $sysroot = (Get-ChildItem Env: | Findstr SystemRoot).split(" ",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $evtxpath = "$sysroot\SYSTEM32\WINEVT\LOGS\$evtx"
      foreach ($identity in ((Get-Acl $evtxpath).Access).IdentityReference) { If ($identity -in $privaccts) {$setting = 0} Else {$setting = 1; break} }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63541.rb
    It "V-63541: Windows 10 permissions for the System event log must prevent access by non-privileged accounts." {
      $privaccts = @('NT SERVICE\EventLog', 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')
      $evtx = System.evtx
      $sysroot = (Get-ChildItem Env: | Findstr SystemRoot).split(" ",[StringSplitOptions]'RemoveEmptyEntries')[-1]
      $evtxpath = "$sysroot\SYSTEM32\WINEVT\LOGS\$evtx"
      foreach ($identity in ((Get-Acl $evtxpath).Access).IdentityReference) { If ($identity -in $privaccts) {$setting = 0} Else {$setting = 1; break} }
      $setting | Should -Be 0
    }
  }
}