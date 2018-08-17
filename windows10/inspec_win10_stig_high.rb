# # encoding: utf-8

# Inspec test for Windows 10 STIG

# Examples: https://lollyrock.com/articles/inspec-windows/
# Security Policies: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn221963(v=ws.11)

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# WN10-SO-000195
# https://www.stigviewer.com/stig/windows_10/

control 'V-63797' do
  impact 1.0
  title 'The system must be configured to prevent the storage of the LAN Manager hash of passwords.'
  desc '
    The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash
    to retrieve account passwords. This setting controls whether or not a LAN Manager hash of the password is stored
    in the SAM the next time the password is changed.
  '
  ref 'V-63797', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63797'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property('NoLMHash') }
    it { should have_property_value('NoLMHash', :dword, 1) }
  end
end

control 'V-63651' do
  impact 1.0
  title 'Solicited Remote Assistance must not be allowed.'
  desc '
    Remote assistance allows another user to view or take control of the local session of a user. Solicited assistance
    is help that is specifically requested by the local user. This may allow unauthorized parties access to the
    resources on the computer.
  '
  ref 'V-63651', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63651'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property('fAllowToGetHelp') }
    it { should have_property_value('fAllowToGetHelp', :dword, 0) }
  end
end

control 'V-63869' do
  impact 1.0
  title 'The Debug programs user right must only be assigned to the Administrators group.'
  desc '
    Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
    Accounts with the "Debug Programs" user right can attach a debugger to any process or to the kernel, providing
    complete access to sensitive and critical operating system components. This right is given to Administrators in
    the default configuration.
  '
  ref 'V-63869', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63869'

  describe security_policy do
    its('SeDebugPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'V-63325' do
  impact 1.0
  title 'The Windows Installer Always install with elevated privileges must be disabled.'
  desc '
    Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges
    when installing applications can allow malicious persons and applications to gain full control of a system.
  '
  ref 'V-63325', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63325'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer') do
    it { should have_property('AlwaysInstallElevated') }
    it { should have_property_value('AlwaysInstallElevated', :dword, 0) }
  end
end

control 'V-63353' do
  impact 1.0
  title 'Local volumes must be formatted using NTFS.'
  desc '
    The ability to set access permissions and auditing is critical to maintaining the security and proper access
    controls of a system. To support this, volumes must be formatted using the NTFS file system.
  '
  ref 'V-63353', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63353'

  v_63353_script = <<-EOH
    $filesSystems = Get-Volume -ErrorAction Stop | Where-Object {$_.DriveType -eq "Fixed"} | Select-Object -ExpandProperty FileSystemType -Unique
    Write-Host $($filesSystems -eq "NTFS") -NoNewline
  EOH
  describe powershell(v_63353_script) do
    its('stdout') { should eq 'True' }
  end
end

control 'V-63667' do
  impact 1.0
  title 'Autoplay must be turned off for non-volume devices.'
  desc '
    Allowing autoplay to execute may introduce malicious code to a system. Autoplay begins reading from a drive
    as soon as you insert media in the drive. As a result, the setup file of programs or music on audio media
    may start. This setting will disable autoplay for non-volume devices (such as Media Transfer Protocol (MTP)
    devices).
  '
  ref 'V-63667', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63667'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
    it { should have_property('NoAutoplayfornonVolume') }
    it { should have_property_value('NoAutoplayfornonVolume', :dword, 1) }
  end
end

control 'V-63759' do
  impact 1.0
  title 'Anonymous access to Named Pipes and Shares must be restricted.'
  desc '
    Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access.
    This setting restricts access to those defined in "Network access: Named Pipes that can be accessed
    anonymously" and "Network access: Shares that can be accessed anonymously", both of which must be blank under
    other requirements.
  '
  ref 'V-63759', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63759'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should have_property('RestrictNullSessAccess') }
    it { should have_property_value('RestrictNullSessAccess', :dword, 1) }
  end
end

control 'V-63749' do
  impact 1.0
  title 'Anonymous enumeration of shares must be restricted.'
  desc '
    Allowing anonymous logon users (null session connections) to list all account names and enumerate all
    shared resources can provide a map of potential points to attack the system.
  '
  ref 'V-63749', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63749'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property('RestrictAnonymous') }
    it { should have_property_value('RestrictAnonymous', :dword, 1) }
  end
end

control 'V-63673' do
  impact 1.0
  title 'Autoplay must be disabled for all drives.'
  desc '
    Allowing autoplay to execute may introduce malicious code to a system. Autoplay begins reading from a
    drive as soon as you insert media in the drive. As a result, the setup file of programs or music on
    audio media may start. By default, autoplay is disabled on removable drives, such as the floppy disk
    drive (but not the CD-ROM drive) and on network drives. If you enable this policy, you can also
    disable autoplay on all drives.
  '
  ref 'V-63673', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63673'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer') do
    it { should have_property('NoDriveTypeAutoRun') }
    it { should have_property_value('NoDriveTypeAutoRun', :dword, 255) }
  end
end

control 'V-63671' do
  impact 1.0
  title 'The default autorun behavior must be configured to prevent autorun commands.'
  desc '
    Allowing autorun commands to execute may introduce malicious code to a system. Configuring this setting
    prevents autorun commands from executing.
  '
  ref 'V-63671', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63671'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    it { should have_property('NoAutorun') }
    it { should have_property_value('NoAutorun', :dword, 1) }
  end
end

control 'V-63377' do
  impact 1.0
  title 'Internet Information System (IIS) or its subcomponents must not be installed on a workstation.'
  desc '
    Installation of Internet Information System (IIS) may allow unauthorized internet services to be hosted.
    Websites must only be hosted on servers that have been designed for that purpose and can be adequately
    secured.
  '
  ref 'V-63377', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63377'

  describe windows_feature('IIS-WebServer') do
    it { should_not be_installed }
  end
  describe windows_feature('IIS-HostableWebCore ') do
    it { should_not be_installed }
  end
end

control 'V-63847' do
  impact 1.0
  title 'The Act as part of the operating system user right must not be assigned to any groups or accounts.'
  desc '
    Inappropriate granting of user rights can provide system, administrative, and other high level
    capabilities. Accounts with the "Act as part of the operating system" user right can assume the identity
    of any user and gain access to resources that user is authorized to access. Any accounts with this right
    can take complete control of a system.
  '
  ref 'V-63847', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63847'

  describe security_policy do
    its('SeTcbPrivilege') { should eq [] }
  end
end

control 'V-78129' do
  impact 1.0
  title 'Administrative accounts must not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.'
  desc '
    Using applications that access the Internet or have potential Internet sources using administrative
    privileges exposes a system to compromise. If a flaw in an application is exploited while running as a
    privileged user, the entire system could be compromised. Web browsers and email are common attack vectors
    for introducing malicious code and must not be run with an administrative account. Since administrative
    accounts may generally change or work around technical restrictions for running a web browser or other
    applications, it is essential that policy requires administrative accounts to not access the Internet
    or use applications, such as email. The policy should define specific exceptions for local service
    administration. These exceptions may include HTTP(S)-based tools that are used for the administration
    of the local system, services, or attached devices. Technical means such as application whitelisting can
    be used to enforce the policy to ensure compliance.
  '
  ref 'V-78129', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-78129'

  # TODO
  describe powershell('Write-Host "TODO" -NoNewLine') do
    its('stdout') { should eq 'True' }
  end
end

control 'V-63361' do
  impact 1.0
  title 'Only accounts responsible for the administration of a system must have Administrator rights on the system.'
  desc '
    An account that does not have Administrator duties must not have Administrator rights. Such rights would
    allow the account to bypass or modify required security restrictions on that machine and make it
    vulnerable to attack. System administrators must log on to systems only using accounts with the minimum
    level of authority necessary. For domain-joined workstations, the Domain Admins group must be replaced
    by a domain workstation administrator group (see V-36434 in the Active Directory Domain STIG).
    Restricting highly privileged accounts from the local Administrators group helps mitigate the risk of
    privilege escalation resulting from credential theft attacks. Systems dedicated to the management of
    Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from
    this. AD admin platforms may use the Domain Admins group or a domain administrative group created
    specifically for AD admin platforms (see V-43711 in the Active Directory Domain STIG). Standard user
    accounts must not be members of the local administrators group.
  '
  ref 'V-63361', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63361'

  # TODO: check group members?
  describe powershell('Write-Host "TODO" -NoNewLine') do
    its('stdout') { should eq 'True' }
  end
end

control 'V-63859' do
  impact 1.0
  title 'The Create a token object user right must not be assigned to any groups or accounts.'
  desc '
    Inappropriate granting of user rights can provide system, administrative, and other high level
    capabilities. The "Create a token object" user right allows a process to create an access token.
    This could be used to provide elevated rights and compromise a system.
  '
  ref 'V-63859', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63859'

  describe security_policy do
    its('SeCreateTokenPrivilege') { should eq [] }
  end
end

control 'V-63351' do
  impact 1.0
  title 'The Windows 10 system must use an anti-virus program.'
  desc '
    Malicious software can establish a base on individual desktops and servers. Employing an automated
    mechanism to detect this type of software will aid in elimination of the software from the operating
    system.
  '
  ref 'V-63351', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63351'

  # TODO: check against a list of AV packages?
  describe package('McAfee') do
    it { should be_installed }
  end
end

control 'V-63745' do
  impact 1.0
  title 'Anonymous enumeration of SAM accounts must not be allowed.'
  desc '
    Anonymous enumeration of SAM accounts allows anonymous log on users (null session connections) to
    list all accounts names, thus providing a list of potential points to attack the system.
  '
  ref 'V-63745', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63745'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property('RestrictAnonymousSAM') }
    it { should have_property_value('RestrictAnonymousSAM', :dword, 1) }
  end
end

control 'V-63429' do
  impact 1.0
  title 'Reversible password encryption must be disabled.'
  desc '
    Storing passwords using reversible encryption is essentially the same as storing clear-text
    versions of the passwords. For this reason, this policy must never be enabled.
  '
  ref 'V-63429', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63429'

  # TODO: find policy name.
  # describe security_policy do
  #   its('UNKNOWN') { should eq 'disabled' }
  # end
  describe powershell('Write-Host "TODO" -NoNewLine') do
    its('stdout') { should eq 'True' }
  end
end

control 'V-68849' do
  impact 1.0
  title 'Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.'
  desc '
    Attackers are constantly looking for vulnerabilities in systems and applications. Structured
    Exception Handling Overwrite Protection (SEHOP) blocks exploits that use the Structured
    Exception Handling overwrite technique, a common buffer overflow attack.
  '
  ref 'V-68849', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-68849'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel') do
    it { should have_property('DisableExceptionChainValidation') }
    it { should have_property_value('DisableExceptionChainValidation', :dword, 0) }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EMET\SysSettings') do
    it { should have_property('SEHOP') }
    it { should have_property_value('SEHOP', :dword, 2) }
  end
end

control 'V-63739' do
  impact 1.0
  title 'Anonymous SID/Name translation must not be allowed.'
  desc '
    Allowing anonymous SID/Name translation can provide sensitive information for accessing a
    system. Only authorized users must be able to perform such translations.
  '
  ref 'V-63739', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63739'

  # TODO: find policy name.
  # describe security_policy do
  #   its('UNKNOWN') { should eq 'disabled' }
  # end
  describe powershell('Write-Host "TODO" -NoNewLine') do
    its('stdout') { should eq 'True' }
  end
end

control 'V-68845' do
  impact 1.0
  title 'Data Execution Prevention (DEP) must be configured to at least OptOut.'
  desc '
    Attackers are constantly looking for vulnerabilities in systems and applications. Data
    Execution Prevention (DEP) prevents harmful code from running in protected memory locations
    reserved for Windows and other programs.
  '
  ref 'V-68845', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-68845'

  v_68845_script = <<-EOH
    $depresults = BCDEdit /enum "{current}"
    $nxfinding = $depresults | where-object {$_ -like "nx*"}
    Write-Host $($nxfinding -like "*OptOut" -or $nxfinding -like "*AlwaysOn") -NoNewline
  EOH
  describe powershell(v_68845_script) do
    its('stdout') { should eq 'True' }
  end
end

control 'V-63801' do
  impact 1.0
  title 'The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.'
  desc '
    The Kerberos v5 authentication protocol is the default for authentication of users who are
    logging on to domain accounts. NTLM, which is less secure, is retained in later Windows versions
    for compatibility with clients and servers that are running earlier versions of Windows or
    applications that still use it. It is also used to authenticate logons to stand-alone computers
    that are running later versions.
  '
  ref 'V-63801', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63801'

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property('LmCompatibilityLevel') }
    it { should have_property_value('LmCompatibilityLevel', :dword, 5) }
  end
end

control 'V-63347' do
  impact 1.0
  title 'The Windows Remote Management (WinRM) service must not use Basic authentication.'
  desc '
    Basic authentication uses plain text passwords that could be used to compromise a system.
  '
  ref 'V-63347', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63347'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service') do
    it { should have_property('AllowBasic') }
    it { should have_property_value('AllowBasic', :dword, 0) }
  end
end

control 'V-63337' do
  impact 1.0
  title 'Mobile systems must encrypt all disks to protect the confidentiality and integrity of all information at rest.'
  desc '
    If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system
    enforces permissions on data access, an adversary can remove non-volatile memory and read it
    directly, thereby circumventing operating system controls. Encrypting the data ensures that
    confidentiality is protected even when the operating system is not running.
  '
  ref 'V-63337', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63337'

  # TODO: maybe powershell to check for bitlocker, might have to test for more encryption tools. Get-BitLockerVolume
  v_63337_script = <<-EOH
    $bitcheck = $true
    $bitdrives = Get-BitLockerVolume
    foreach($bitdrive in $bitdrives){
        $bitcheck = $bitcheck -and $($bitdrive.EncryptionMethod -ne 'None')
    }
    Write-Host $bitcheck -NoNewline
  EOH
  describe powershell(v_63337_script) do
    its('stdout') { should eq 'True' }
  end
end

control 'V-63349' do
  impact 1.0
  title 'Windows 10 systems must be maintained at a supported servicing level.'
  desc '
    Windows 10 is maintained by Microsoft at servicing levels for specific periods of time to support
    Windows as a Service. Systems at unsupported servicing levels or releases will not receive security
    updates for new vulnerabilities which leaves them subject to exploitation. New versions with
    feature updates are planned to be released on a semi-annual basis with an estimated support
    timeframe of 18 months. The initial release of a feature update is the Semi-Annual Channel (Pilot),
    previously referred to as the Current Branch (CB). Approximately 4 months after a new release it is
    declared ready for broad deployment, previously referred to as the Current Branch for Business
    (CBB). Only 2 active versions will typically be supported with updates at any given time (with some
    overlap during the period the latest version is declared ready for broad deployment and support
    ending for the oldest version.) Note: Microsoft has extended support for an additional 6 months
    with supplemental servicing for versions 1607, 1703, and 1709. Supplemental servicing provides
    critical and important updates for Windows 10 Enterprise only. A separate servicing branch
    intended for special purpose systems is the Long-Term Servicing Channel (LTSC, formerly Branch -
    LTSB) which will receive security updates for 10 years but excludes feature updates. Systems
    using an LTSC\B version may not be able to meet all requirements of the STIG as new features
    are added, which organizations will need to address.
  '
  ref 'V-63349', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63349'

  v_63349_script = <<-EOH
    $winbuild = [System.Environment]::OSVersion.Version.Build
    Write-Host $($winbuild -gt 14393) -NoNewline
  EOH
  describe powershell(v_63349_script) do
    its('stdout') { should eq 'True' }
  end
end

control 'V-63335' do
  impact 1.0
  title 'The Windows Remote Management (WinRM) client must not use Basic authentication.'
  desc '
    Basic authentication uses plain text passwords that could be used to compromise a system.
  '
  ref 'V-63335', url: 'https://www.stigviewer.com/stig/windows_10/2018-04-06/finding/V-63335'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client') do
    it { should have_property('AllowBasic') }
    it { should have_property_value('AllowBasic', :dword, 0) }
  end
end
