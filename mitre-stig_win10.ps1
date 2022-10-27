# MITRE STIG Baseline - Controls for Windows 10
# AUDITING VIA POWERSHELL
#   NOTE: Checks are done as specified in the MITRE InSpec profile.
#     e.g., If a value is not what is specified, it is a "finding".
#     This can mean that it is configured incorrectly, or does not exist.
#     For full documentation, refer to MITRE repo, descriptions will not be copied.
# Source:
#   https://github.com/mitre/microsoft-windows-10-stig-baseline/tree/master/controls
Describe "Software Policies" {
  Context "Operating System Settings" {
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
  }

  Context "Anti-Virus Settings" {
    # https://github.com/mitre/microsoft-windows-10-stig-baseline/blob/master/controls/V-63351.rb
    It "V-63351: The Windows 10 system must use an anti-virus program." {
      # TEST: Need testing to determine if this is correct for anything beyond Defender
      $setting = (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).ProductState
      $setting | Should -Be 397568  # enabled and up to date
    }
  }

  Context "Registry Settings" {
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
      # Hack to parse out multiple values.
      $loop = foreach ($disk in (wmic logicaldisk get FileSystem | findstr /r /v '^$' |Findstr /v 'FileSystem')) { If ($disk -ne "NTFS") { $setting = 0 } }
      $setting | Should -Not -Be 0
    }
  }
}