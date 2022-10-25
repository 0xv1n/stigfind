# This project is an attempt to translate all of the MITRE STIG baseline control checks into Pester.
# This is not intended for commercial or enterprise use, but rather an educational project to learn how to access
# each of these properties via PowerShell.
# MITRE STIG Baseline - Controls for Windows 10
# https://github.com/mitre/microsoft-windows-10-stig-baseline/tree/master/controls
Describe "Software Policies" {
  Context "Operating System Settings" {
    It "V-63319: Domain-joined systems must use Windows 10 Enterprise Edition 64-bit version." {
      $setting = Get-WindowsEdition -Online
      $setting.Edition | Should -Be "Enterprise"
    }
  }

  Context "Registry Settings" {
    It "V-63321: Users must be prevented from changing installation options." {
      # Installation options for applications are typically controlled by
      # administrators.  This setting prevents users from changing installation options
      # that may bypass security features.
      $setting = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer").EnableUserControl
      $setting | Should -Be 0
    }
  }
}

Describe "Hardware Policies" {
  Context "Endpoint Settings" {
    # For output clarity these are broken up into two separate checks rather than a singular check using a boolean.
    It "V-63323: Windows 10 domain-joined systems must have a Trusted Platform Module (TPM) enabled." {
      $setting = Get-Tpm
      $setting.TpmPresent | Should -Be "True"
    }
    It "V-63323: Windows 10 domain-joined systems must have a Trusted Platform Module (TPM) ready for use." {
      $setting = Get-Tpm
      $setting.TpmReady | Should -Be "True"
    }
  }
}