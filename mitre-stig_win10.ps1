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
      $setting = Get-WindowsEdition -Online
      $setting.Edition | Should -Be "Enterprise"
    }
    It "V-63319-Architecture: Domain-joined systems must use Windows 10 Enterprise Edition 64-bit version." {
      $setting = Get-Wmiobject Win32_Processor
      $setting.AddressWidth | Should -Be 64
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
    #
    It "V-63335: The Windows Remote Management (WinRM) client must not use Basic authentication." {
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client").AllowBasic
      $setting | Should -Be 0   
    }
  }
}

Describe "Hardware Policies" {
  Context "Endpoint Settings" {
    # For output clarity these are broken up into two separate checks rather than a singular check using a boolean.
    It "V-63323-TPMPresent: Windows 10 domain-joined systems must have a Trusted Platform Module (TPM) enabled." {
      $setting = Get-Tpm
      $setting.TpmPresent | Should -Be "True"
    }
    It "V-63323-TPMReady: Windows 10 domain-joined systems must have a Trusted Platform Module (TPM) ready for use." {
      $setting = Get-Tpm
      $setting.TpmReady | Should -Be "True"
    }
  }
}