![](assets/stigfind.png)

# What is STIG-Find?

This project exists to bring STIG compliance auditing to the hands of anyone. This project is built upon the [Pester](https://pester.dev/) test framework, and allows unit-test style auditing of the [DISA STIGs](https://public.cyber.mil/stigs/) for Windows 10 Enterprise images. Some of this work may be applicable to Windows 11 - but validating that is currently beyond the scope of this project. Should Windows 11 deviate greatly from prior methods, a new repo will be opened. 

# Prerequisites

You must have the [Pester](https://github.com/pester/Pester) framework installed. A simple command via **administrator console** can be executed: `Install-Module -Name Pester -Force`

## Usage

To utilize this script simply run `Invoke-Pester stigfind.ps1`.

# Reporting Bugs/Issues

Please open an issue in the GitHub repo (or fix it yourself and open a PR).

# Contributions

Please refer to `Current Completed STIGs.md` for current list of work left to do, or notations regarding additional testing that may be needed. If you're a documentation wizard, I'd love help organizing these better. 