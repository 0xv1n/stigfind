# MITRE STIG Baseline - Controls for Windows 10 Workstations
# AUDITING VIA POWERSHELL
#   NOTE: Checks are done as specified in the MITRE InSpec profile.
#     e.g., If a value is not what is specified, it is a "finding".
#     This can mean that it is configured incorrectly, or does not exist.
#     For full documentation, refer to MITRE repo, descriptions will not be copied.
# Source:
#   https://github.com/mitre/microsoft-windows-10-stig-baseline/tree/master/controls
Describe "Software Policies" {
  Context "Operating System" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63319.rb
    It "V-63319-Edition: Domain-joined systems must use Windows 10 Enterprise Edition 64-bit version." {
      $setting = (Get-WindowsEdition -Online).Edition
      $setting | Should -Be "Enterprise"
    }
    It "V-63319-Architecture: Domain-joined systems must use Windows 10 Enterprise Edition 64-bit version." {
      $setting = (Get-Wmiobject Win32_Processor).AddressWidth
      $setting | Should -Be 64
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63337.rb
    It "V-63337: Windows 10 information systems must use BitLocker to encrypt all disks to protect the confidentiality and integrity of all information at rest." {
      $setting = ''
      # this is hacky, essentially loops through every volume and if it finds a singly unencrypted volume this fails
      $loop = foreach ($volume in Get-BitLockerVolume) { If ($volume.ProtectionStatus -eq "Off") { $setting = 0 } }
      $setting | Should -Not -Be 0
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
      $setting = (bcdedit | Findstr description | Findstr /v /c:'Windows Boot Manager')
      # TODO: can this be parsed/filtered better to just be 10 or Windows 10?
      $setting | Should -Be "description             Windows 10"
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
  }

  Context "Additional Features" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63377.rb
    It "V-63377: Internet Information System (IIS) or its subcomponents must not be installed on a workstation." {
      $setting = ''
      $loop = foreach($iis in (Get-WindowsOptionalFeature -Online -FeatureName “IIS*”)) { If ($iis.State -ne 'Disabled') { $setting = 1; break } Else { $setting = 0 } }
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
      $setting = ''
      # Iterates through Domain, Private, and Public Firewall profiles. All must be enabled. 
      $loop = foreach ($fw in ((Get-NetFirewallProfile).Enabled)) { If ($fw -eq "False") { $setting = 1; break } Else { $setting = 0 } }
      $setting | Should -Be 0
    }
  }
}

Describe "Hardware Policies" {
  Context "TPM" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63323.rb
    It "V-63323-TPMPresent: Windows 10 domain-joined systems must have a Trusted Platform Module (TPM) enabled." {
      $setting = (Get-Tpm).TpmPresent
      $setting | Should -BeTrue
    }
    It "V-63323-TPMReady: Windows 10 domain-joined systems must have a Trusted Platform Module (TPM) ready for use." {
      $setting = (Get-Tpm).TpmReady
      $setting | Should -BeTrue
    }
  }

  Context "Logical Drives" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63353.rb
    It "V-63353: Local volumes must be formatted using NTFS." {
      $setting = ''
      # TODO: Is there a better way than this hacky stuff?
      $loop = foreach ($disk in (wmic logicaldisk get FileSystem | findstr /r /v '^$' |Findstr /v 'FileSystem')) { If ($disk -ne "NTFS") { $setting = 0 } }
      $setting | Should -Not -Be 0
    }
  }
}

Describe "Account Policies" {
  Context "Administrative Accounts" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63361.rb
    It "V-63361: Only accounts responsible for the administration of a system must have Administrator rights on the system." {
      # Any accounts found added to this group should be reviewed per the STIG.
      # Note: The default local Administrator account should not be enabled in a domain per V-63367, but this may flag it.
      $setting = ''
      $loop =  foreach ($acct in (net localgroup Administrators | Format-List | Findstr /V 'Alias Name Comment Members - command')) { If ($acct -ne "") { $setting = 0 } }
      $setting | Should -Not -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63363.rb
    It "V-63363: Only accounts responsible for the backup operations must be members of the Backup Operators group." {
      # TODO: Is there a better way than this hacky stuff?
      $setting = ''
      # Any accounts found added to this group should be reviewed per the STIG.
      $loop =  foreach ($acct in (net localgroup "Backup Operators" | Format-List | Findstr /V 'Alias Name Comment Members - command')) { If ($acct -ne "") { $setting = 0 } }
      $setting | Should -Be 0
    }
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63365.rb
    It "V-63365: Only authorized user accounts must be allowed to create or run virtual machines on Windows 10 systems." {
      # TODO: Is there a better way than this hacky stuff?
      $setting = ''
      # Any accounts found added to this group should be reviewed per the STIG.
      $loop =  foreach ($acct in (net localgroup "Hyper-V Administrators" | Format-List | Findstr /V 'Alias Name Comment Members - command')) { If ($acct -ne "") { $setting = 0 } }
      $setting | Should -Be 0
    }
  }

  Context "Default Accounts" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63367.rb
    It "V-63367: Standard local user accounts must not exist on a system in a domain." {
      $setting = ''
      $default_acct = @('Administrator', 'Guest', 'DefaultAccount', 'defaultuser0', 'WDAGUtilityAccount')
      # Note: A single enabled default account fails this test, review the list of local users.
      $loop = foreach ($acct in $default_acct) { If ((Get-LocalUser $acct).Enabled -ne "True") { $setting = '0' } }
      $setting | Should -Be 0
    }
  }

  Context "Passwords" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63371.rb
    It "V-63371: Accounts must be configured to require password expiration." {
      $setting = ''
      $loop = foreach ($acct in (Get-CimInstance -Class Win32_Useraccount -Filter 'PasswordExpires=False and LocalAccount=True and Disabled=False' | FT Name | Findstr /V 'Name --')) { If ($acct -ne "") {$setting = 0} }
      $setting | Should -Not -Be 0
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

Describe "File Permissions" {
  Context "System Directories" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63373.rb
    # Separated to check each default system dir - a single incorrect/unexpected perm fails.
    # For C:\\ local users that can write to this directory will trigger a fail condition
    #   local SID perms are usually listed first.
    # TODO: In general, I think a better way should be explored.
    It "V-63373-C:\\: Permissions for system files and directories must conform to minimum requirements." {
      $setting = 1
      $default_perms = @(
        'BUILTIN\\Administrators:(OI)(CI)(F)',
        'NT AUTHORITY\\SYSTEM:(OI)(CI)(F)',
        'BUILTIN\\Users:(OI)(CI)(RX)', 
        'NT AUTHORITY\\Authenticated Users:(OI)(CI)(IO)(M)', 
        'NT AUTHORITY\\Authenticated Users:(AD)', 
        'Mandatory Label\\High Mandatory Level:(OI)(NP)(IO)(NW)'
      )
      # TODO: Needs more testing
      $loop = foreach($line in (icacls 'C:\\' | Findstr /V 'Successfully' | Findstr /r /v "^$")) { $trimmed = ($line | Out-String).Trim(); If ($trimmed -in $default_perms) { $setting = 0 } Else {$setting = 1; break} }
      $setting | Should -Be 0
    }
    It "V-63373-C:\\Program Files: Permissions for system files and directories must conform to minimum requirements." {
      $setting ''
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
      # TODO: Needs more testing
      $loop = foreach($line in (icacls 'C:\\Program Files' | Findstr /V 'Successfully' | Findstr /r /v "^$")) { $trimmed = ($line | Out-String).Trim(); If ($trimmed -in $default_perms) { $setting = 0 } Else {$setting = 1; break}  }
      $setting | Should -Be 0
    }
    It "V-63373-C:\\Windows: Permissions for system files and directories must conform to minimum requirements." {
      $setting = ''
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
      # TODO: Needs more testing
      $loop = foreach($line in (icacls 'C:\\Windows' | Findstr /V 'Successfully' | Findstr /r /v "^$")) { $trimmed = ($line | Out-String).Trim(); If ($trimmed -in $default_perms) { $setting = 0 } Else {$setting = 1; break}  }
      $setting | Should -Be 0
    }
  }
}