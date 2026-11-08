# Offline Pester 5 tests. These stubs prevent any directory or tenant access.
Import-Module (Join-Path $PSScriptRoot '..\IAMToolkit.psm1') -Force

Describe 'IAM Toolkit' {
    InModuleScope IAMToolkit {
        BeforeAll {
            function script:Get-ADUser {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Offline stubs bind API parameters; Pester mocks supply behavior.')]
                [CmdletBinding()]
                param($Identity,$Server,$Properties)
                throw 'Unmocked AD read'
            }
            function script:Get-ADGroup {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Offline stubs bind API parameters; Pester mocks supply behavior.')]
                [CmdletBinding()]
                param($Identity,$LDAPFilter,$Server,$Properties)
                throw 'Unmocked AD read'
            }
            function script:Get-ADObject {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Offline stubs bind API parameters; Pester mocks supply behavior.')]
                [CmdletBinding()]
                param($Identity,$LDAPFilter,$SearchBase,$SearchScope,$Server,$Properties)
                throw 'Unmocked AD read'
            }
            function script:Get-ADGroupMember {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Offline stubs bind API parameters; Pester mocks supply behavior.')]
                [CmdletBinding()]
                param($Identity,$Server)
                throw 'Unmocked AD read'
            }
            function script:Get-ADOrganizationalUnit {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Offline stubs bind API parameters; Pester mocks supply behavior.')]
                [CmdletBinding()]
                param($Identity,$Server)
                throw 'Unmocked AD read'
            }
            function script:New-ADGroup {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Offline stubs bind API parameters; Pester mocks supply behavior.')]
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSupportsShouldProcess', '', Justification = 'Explicit Confirm binding counts every mocked write; no inner WhatIf can hide a call.')]
                [CmdletBinding()]
                param($Name,$SamAccountName,$Description,$GroupCategory,$GroupScope,$Path,$Server,$ManagedBy,[switch]$PassThru,[switch]$Confirm)
                throw 'Unmocked AD write'
            }
            function script:Set-ADGroup {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Offline stubs bind API parameters; Pester mocks supply behavior.')]
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSupportsShouldProcess', '', Justification = 'Explicit Confirm binding counts every mocked write; no inner WhatIf can hide a call.')]
                [CmdletBinding()]
                param($Identity,$Server,$ManagedBy,$Replace,[switch]$Confirm)
                throw 'Unmocked AD write'
            }
            function script:Add-ADGroupMember {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Offline stubs bind API parameters; Pester mocks supply behavior.')]
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSupportsShouldProcess', '', Justification = 'Explicit Confirm binding counts every mocked write; no inner WhatIf can hide a call.')]
                [CmdletBinding()]
                param($Identity,$Members,$Server,[switch]$Confirm)
                throw 'Unmocked AD write'
            }
            function script:Remove-ADGroupMember {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Offline stubs bind API parameters; Pester mocks supply behavior.')]
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSupportsShouldProcess', '', Justification = 'Explicit Confirm binding counts every mocked write; no inner WhatIf can hide a call.')]
                [CmdletBinding()]
                param($Identity,$Members,$Server,[switch]$Confirm)
                throw 'Unmocked AD write'
            }
            function script:Invoke-MgGraphRequest {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Offline stubs bind API parameters; Pester mocks supply behavior.')]
                [CmdletBinding()]
                param($Method,$Uri,$Headers)
                throw 'Unmocked Graph request'
            }

            function script:New-TestUser($Name) {
                [pscustomobject]@{
                    SamAccountName = $Name; Name = $Name; DisplayName = "Sample $Name"
                    DistinguishedName = "CN=$Name,OU=Users,DC=corp,DC=example,DC=com"
                    SID = "sample-sid-$Name"; Enabled = $true; MemberOf = @('CN=SG-Parent,DC=corp,DC=example,DC=com')
                }
            }
            function script:New-TestGroup($Name) {
                [pscustomobject]@{
                    Name = $Name; SamAccountName = $Name
                    DistinguishedName = "CN=$Name,OU=Groups,DC=corp,DC=example,DC=com"
                    GroupCategory = 'Security'; GroupScope = 'Universal'; Description = 'Sample access'
                    ManagedBy = ''; extensionAttribute12 = ''; info = ''; MemberOf = @()
                }
            }
            function script:Write-TestCsv($Name, [string[]]$Lines) {
                $file = Join-Path $TestDrive $Name
                $Lines | Set-Content -LiteralPath $file
                $file
            }
            function script:Assert-NoADWrite {
                Should -Invoke New-ADGroup -Times 0 -Exactly -Scope It
                Should -Invoke Set-ADGroup -Times 0 -Exactly -Scope It
                Should -Invoke Add-ADGroupMember -Times 0 -Exactly -Scope It
                Should -Invoke Remove-ADGroupMember -Times 0 -Exactly -Scope It
            }
        }

        BeforeEach {
            $script:groups = @{}
            $script:members = @{}
            $script:createdNames = @()
            $script:ownerWrites = @()
            $script:membershipFile = Write-TestCsv 'membership.csv' @('GroupName,UserName,Action','SG-Test,alex,Add')
            $script:creationFile = Write-TestCsv 'new-groups.csv' @(
                'GroupName,Description,PrimaryOwner,SecondaryOwner,Members,TicketNumber,GroupScope'
                'SG-New,Sample access,alex,jamie,taylor,SAMPLE-1001,Universal'
            )
            $script:ou = 'OU=Groups,DC=corp,DC=example,DC=com'
            Mock Assert-IamADModule { }
            Mock Get-ADUser { New-TestUser $Identity }
            Mock Get-ADGroup {
                if ($LDAPFilter) { return }
                if ($script:groups.ContainsKey($Identity)) { return $script:groups[$Identity] }
                New-TestGroup $Identity
            }
            Mock Assert-IamSecondaryOwnerAttribute { }
            Mock Get-ADObject { }
            Mock Get-ADOrganizationalUnit { [pscustomobject]@{ DistinguishedName = $Identity } }
            Mock Get-ADGroupMember { @($script:members[$Identity]) | Where-Object { $null -ne $_ } }
            Mock New-ADGroup {
                $group = New-TestGroup $Name
                $group.Description = $Description
                $group.ManagedBy = $ManagedBy
                $group.GroupScope = $GroupScope
                $script:groups[$group.DistinguishedName] = $group
                $script:createdNames += $Name
                $group
            }
            Mock Set-ADGroup {
                $group = $script:groups[$Identity]
                if (-not $group) { $group = New-TestGroup 'SG-Test'; $script:groups[$Identity] = $group }
                if ($ManagedBy) { $group.ManagedBy = $ManagedBy }
                if ($Replace) { foreach ($key in $Replace.Keys) { $group.$key = $Replace[$key] } }
                $script:ownerWrites += $Identity
            }
            Mock Add-ADGroupMember { $script:members[$Identity] = @($script:members[$Identity]) + @($Members) | Where-Object { $null -ne $_ } }
            Mock Remove-ADGroupMember {
                $removeDns = @($Members | ForEach-Object { $_.DistinguishedName })
                $script:members[$Identity] = @($script:members[$Identity] | Where-Object { $_.DistinguishedName -notin $removeDns })
            }
            Mock Invoke-MgGraphRequest { @{ value = @() } }
        }

        Context 'Input validation' {
            It 'reads names from TXT, ignoring comments, whitespace and case-insensitive duplicates' {
                $file = Write-TestCsv 'groups.txt' @(' SG-Test ','','# comment','sg-test','SG-Other')
                $values = @(Read-IamNameInput -Path $file -ColumnName GroupName)
                $values | Should -HaveCount 2
                $values[0] | Should -Be 'SG-Test'
                $values[1] | Should -Be 'SG-Other'
            }
            It 'rejects simultaneous inline and file input' {
                { Read-IamNameInput -Names 'SG-Test' -Path $script:membershipFile -ColumnName GroupName } | Should -Throw
            }
            It 'escapes LDAP special characters' {
                ConvertTo-IamLdapValue 'SG-(Test)*\' | Should -Be 'SG-\28Test\29\2a\5c'
            }
            It 'rejects duplicate semicolon-separated members' {
                { Split-IamMember 'alex; jamie; ALEX; ' } | Should -Throw
            }
            It 'rejects a missing required CSV column before writes' {
                $file = Write-TestCsv 'bad.csv' @('GroupName,UserName','SG-Test,alex')
                { Invoke-IamMembershipCsv -Path $file -Server corp.example.com -Commit } | Should -Throw '*Action*'
                Assert-NoADWrite
            }
            It 'rejects extra fields, missing fields and unterminated quotes before writes: <Row>' -TestCases @(
                @{ Row = 'SG-Test,alex,Add,unexpected' }
                @{ Row = 'SG-Test,alex' }
                @{ Row = 'SG-Test,"alex,Add' }
            ) {
                param($Row)
                $file = Write-TestCsv 'malformed.csv' @('GroupName,UserName,Action','SG-First,jamie,Add',$Row)
                { Invoke-IamMembershipCsv -Path $file -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'accepts quoted commas and multiline CSV fields without truncation' {
                $file = Write-TestCsv 'quoted.csv' @('GroupName,Description','SG-Test,"Sample, access','on two lines"')
                $rows = @(Import-IamRequestCsv -Path $file -RequiredColumns @('GroupName','Description'))
                $rows | Should -HaveCount 1
                $rows[0].Description | Should -Match 'Sample, access'
                $rows[0].Description | Should -Match 'on two lines'
            }
        }

        Context 'Membership requests' {
            It 'previews Add without any AD writes' {
                (Invoke-IamMembershipCsv -Path $script:membershipFile -Server corp.example.com).Status | Should -Be Preview
                Assert-NoADWrite
            }
            It 'makes no AD writes with Commit WhatIf' {
                (Invoke-IamMembershipCsv -Path $script:membershipFile -Server corp.example.com -Commit -WhatIf).Status | Should -Be Skipped
                Assert-NoADWrite
            }
            It 'adds and verifies a missing membership' {
                $result = Invoke-IamMembershipCsv -Path $script:membershipFile -Server corp.example.com -Commit
                $result.Status | Should -Be Updated
                Should -Invoke Add-ADGroupMember -Times 1 -Exactly -ParameterFilter { $Identity -eq 'CN=SG-Test,OU=Groups,DC=corp,DC=example,DC=com' -and $Members.SamAccountName -eq 'alex' -and $Server -eq 'corp.example.com' }
                Should -Invoke Remove-ADGroupMember -Times 0 -Exactly
            }
            It 'removes and verifies an existing membership even for a disabled user' {
                $script:members['CN=SG-Test,OU=Groups,DC=corp,DC=example,DC=com'] = @(New-TestUser alex)
                Mock Get-ADUser { $user = New-TestUser $Identity; $user.Enabled = $false; $user }
                $file = Write-TestCsv 'remove.csv' @('GroupName,UserName,Action','SG-Test,alex,Remove')
                (Invoke-IamMembershipCsv -Path $file -Server corp.example.com -Commit).Status | Should -Be Updated
                Should -Invoke Remove-ADGroupMember -Times 1 -Exactly
                Should -Invoke Add-ADGroupMember -Times 0 -Exactly
            }
            It 'does not write when Add is already present or Remove is already absent' {
                $script:members['CN=SG-Test,OU=Groups,DC=corp,DC=example,DC=com'] = @(New-TestUser alex)
                $file = Write-TestCsv 'nochange.csv' @('GroupName,UserName,Action','SG-Test,alex,Add','SG-Test,jamie,Remove')
                $result = @(Invoke-IamMembershipCsv -Path $file -Server corp.example.com -Commit)
                $result | Should -HaveCount 2
                @($result | Where-Object Status -ne NoChange) | Should -HaveCount 0
                Assert-NoADWrite
            }
            It 'rejects a malformed later row before the first write' {
                $file = Write-TestCsv 'invalid.csv' @('GroupName,UserName,Action','SG-Test,alex,Add','SG-Other,jamie,Delete')
                { Invoke-IamMembershipCsv -Path $file -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'rejects duplicate and conflicting requests before writes' {
                $file = Write-TestCsv 'duplicate.csv' @('GroupName,UserName,Action','SG-Test,alex,Add','sg-test,ALEX,Remove')
                { Invoke-IamMembershipCsv -Path $file -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'rejects aliases that resolve to the same group and user before writes' {
                Mock Get-ADGroup { New-TestGroup 'SG-Test' }
                Mock Get-ADUser { New-TestUser alex }
                $file = Write-TestCsv 'alias.csv' @('GroupName,UserName,Action','SG-Test,alex,Add','group-alias,user-alias,Remove')
                { Invoke-IamMembershipCsv -Path $file -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'rejects disabled additions before writes' {
                Mock Get-ADUser { $user = New-TestUser $Identity; $user.Enabled = $false; $user }
                { Invoke-IamMembershipCsv -Path $script:membershipFile -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'reports a failed read-back and stops subsequent writes' {
                Mock Add-ADGroupMember { }
                $file = Write-TestCsv 'failure.csv' @('GroupName,UserName,Action','SG-Test,alex,Add','SG-Other,jamie,Add')
                $result = @(Invoke-IamMembershipCsv -Path $file -Server corp.example.com -Commit)
                $result[0].Status | Should -Be Failed
                $result[0].Message | Should -Match 'read-back'
                $result[1].Status | Should -Be NotAttempted
                Should -Invoke Add-ADGroupMember -Times 1 -Exactly
            }
            It 'preserves successful rows in the report when a later AD write fails' {
                Mock Add-ADGroupMember { throw 'Sample AD failure' } -ParameterFilter { $Members.SamAccountName -eq 'jamie' }
                $file = Write-TestCsv 'partial.csv' @('GroupName,UserName,Action','SG-Test,alex,Add','SG-Other,jamie,Add','SG-Last,taylor,Add')
                $report = Join-Path $TestDrive 'membership-results.csv'
                $result = @(Invoke-IamMembershipCsv -Path $file -Server corp.example.com -Commit -ReportPath $report)
                $result[0].Status | Should -Be Updated
                $result[1].Status | Should -Be Failed
                $result[1].Message | Should -Match 'Sample AD failure'
                $result[2].Status | Should -Be NotAttempted
                @(Import-Csv $report)[0].Status | Should -Be Updated
                Should -Invoke Add-ADGroupMember -Times 2 -Exactly
            }
        }

        Context 'Group creation' {
            It 'previews creation without any AD writes' {
                $result = New-IamADGroupsFromCsv -Path $script:creationFile -TargetOU $script:ou -Server corp.example.com
                $result.Status | Should -Be Preview
                $result.MemberCount | Should -Be 1
                Assert-NoADWrite
            }
            It 'makes no AD writes with Commit WhatIf' {
                (New-IamADGroupsFromCsv -Path $script:creationFile -TargetOU $script:ou -Server corp.example.com -Commit -WhatIf).Status | Should -Be Skipped
                Assert-NoADWrite
            }
            It 'creates and verifies owners, metadata and members and exports a success comment' {
                $comments = Join-Path $TestDrive 'comments.csv'
                $result = New-IamADGroupsFromCsv -Path $script:creationFile -TargetOU $script:ou -Server corp.example.com -Commit -TicketCommentsPath $comments
                $result.Status | Should -Be Created
                $rows = @(Import-Csv $comments)
                $rows | Should -HaveCount 1
                $rows[0].TicketNumber | Should -Be SAMPLE-1001
                $rows[0].Comments | Should -Match 'Created AD group: SG-New'
                Should -Invoke New-ADGroup -Times 1 -Exactly -ParameterFilter { $SamAccountName -eq 'SG-New' -and $ManagedBy -eq 'CN=alex,OU=Users,DC=corp,DC=example,DC=com' }
                Should -Invoke Set-ADGroup -Times 1 -Exactly -ParameterFilter { $Replace.extensionAttribute12 -eq 'CN=jamie,OU=Users,DC=corp,DC=example,DC=com' -and $Replace.info -eq 'SAMPLE-1001' }
                Should -Invoke Add-ADGroupMember -Times 1 -Exactly -ParameterFilter { $Members[0].SamAccountName -eq 'taylor' }
            }
            It 'rejects malformed later creation rows before writes' {
                $file = Write-TestCsv 'bad-groups.csv' @('GroupName,Description,PrimaryOwner,SecondaryOwner,Members','SG-New,Sample access,alex,jamie,taylor','invalid name,Sample access,alex,jamie,taylor')
                { New-IamADGroupsFromCsv -Path $file -TargetOU $script:ou -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'rejects duplicate group names before writes' {
                $file = Write-TestCsv 'duplicate-groups.csv' @('GroupName,Description,PrimaryOwner,SecondaryOwner,Members','SG-New,Sample access,alex,jamie,taylor','sg-new,Sample access,alex,jamie,taylor')
                { New-IamADGroupsFromCsv -Path $file -TargetOU $script:ou -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'rejects an unresolved later owner before writes' {
                Mock Get-ADUser { throw 'Sample missing owner' } -ParameterFilter { $Identity -eq 'missing' }
                $file = Write-TestCsv 'missing-owner.csv' @('GroupName,Description,PrimaryOwner,SecondaryOwner,Members','SG-New,Sample access,alex,jamie,taylor','SG-Other,Sample access,missing,jamie,taylor')
                { New-IamADGroupsFromCsv -Path $file -TargetOU $script:ou -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'rejects duplicate member requests before creating a group' {
                $file = Write-TestCsv 'duplicate-members.csv' @('GroupName,Description,PrimaryOwner,SecondaryOwner,Members','SG-New,Sample access,alex,jamie,taylor; TAYLOR')
                { New-IamADGroupsFromCsv -Path $file -TargetOU $script:ou -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'rejects member aliases resolving to the same user before creation' {
                Mock Get-ADUser { New-TestUser taylor } -ParameterFilter { $Identity -in @('taylor','taylor-alias') }
                $file = Write-TestCsv 'alias-members.csv' @('GroupName,Description,PrimaryOwner,SecondaryOwner,Members','SG-New,Sample access,alex,jamie,taylor; taylor-alias')
                { New-IamADGroupsFromCsv -Path $file -TargetOU $script:ou -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'fails schema validation before creating any groups' {
                Mock Assert-IamSecondaryOwnerAttribute { throw 'Sample missing schema attribute' }
                { New-IamADGroupsFromCsv -Path $script:creationFile -TargetOU $script:ou -Server corp.example.com -Commit } | Should -Throw '*schema*'
                Assert-NoADWrite
            }
            It 'rejects a same-name object already present in the target OU before writes' {
                Mock Get-ADObject { [pscustomobject]@{ Name = 'SG-New' } } -ParameterFilter { $SearchScope -eq 'OneLevel' }
                { New-IamADGroupsFromCsv -Path $script:creationFile -TargetOU $script:ou -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'reports Failed if the creation cmdlet fails and stops the batch' {
                Mock New-ADGroup { throw 'Sample create failure' }
                $file = Write-TestCsv 'create-failure.csv' @('GroupName,Description,PrimaryOwner,SecondaryOwner,Members','SG-New,Sample access,alex,jamie,taylor','SG-Other,Sample access,alex,jamie,taylor')
                $result = @(New-IamADGroupsFromCsv -Path $file -TargetOU $script:ou -Server corp.example.com -Commit)
                $result[0].Status | Should -Be Failed
                $result[0].Message | Should -Match 'Sample create failure'
                $result[1].Status | Should -Be NotAttempted
                Should -Invoke New-ADGroup -Times 1 -Exactly
                Should -Invoke Set-ADGroup -Times 0 -Exactly
            }
            It 'reports Partial when metadata fails after creation and emits no success comments' {
                Mock Set-ADGroup { throw 'Sample metadata failure' }
                $comments = Join-Path $TestDrive 'partial-comments.csv'
                'Stale success from an earlier run' | Set-Content $comments
                $result = New-IamADGroupsFromCsv -Path $script:creationFile -TargetOU $script:ou -Server corp.example.com -Commit -TicketCommentsPath $comments
                $result.Status | Should -Be Partial
                $result.Message | Should -Match 'Sample metadata failure'
                # Windows PowerShell can write a UTF-8 BOM without any CSV content.
                Get-Content -LiteralPath $comments -Raw | Should -BeNullOrEmpty
                @(Import-Csv -LiteralPath $comments) | Should -HaveCount 0
                Should -Invoke New-ADGroup -Times 1 -Exactly
                Should -Invoke Add-ADGroupMember -Times 0 -Exactly
            }
            It 'reports Partial when member verification fails after creation' {
                Mock Add-ADGroupMember { }
                (New-IamADGroupsFromCsv -Path $script:creationFile -TargetOU $script:ou -Server corp.example.com -Commit).Status | Should -Be Partial
            }
        }

        Context 'Owner changes' {
            It 'previews primary ownership without any AD writes' {
                (Set-IamGroupOwner -GroupName SG-Test -PrimaryOwner alex -Server corp.example.com).Status | Should -Be Preview
                Assert-NoADWrite
            }
            It 'makes no AD writes with Commit WhatIf' {
                (Set-IamGroupOwner -GroupName SG-Test -PrimaryOwner alex -Server corp.example.com -Commit -WhatIf).Status | Should -Be Skipped
                Assert-NoADWrite
            }
            It 'writes and verifies primary and explicit secondary owner attributes' {
                $result = Set-IamGroupOwner -GroupName SG-Test -PrimaryOwner alex -SecondaryOwner jamie -SecondaryOwnerAttribute extensionAttribute12 -Server corp.example.com -Commit
                $result.Status | Should -Be Updated
                Should -Invoke Set-ADGroup -Times 1 -Exactly -ParameterFilter { $ManagedBy -eq 'CN=alex,OU=Users,DC=corp,DC=example,DC=com' -and $Replace.extensionAttribute12 -eq 'CN=jamie,OU=Users,DC=corp,DC=example,DC=com' }
            }
            It 'does not write an unchanged owner' {
                $group = New-TestGroup SG-Test
                $group.ManagedBy = (New-TestUser alex).DistinguishedName
                $script:groups['SG-Test'] = $group
                (Set-IamGroupOwner -GroupName SG-Test -PrimaryOwner alex -Server corp.example.com -Commit).Status | Should -Be NoChange
                Assert-NoADWrite
            }
            It 'requires an explicit secondary attribute' {
                { Set-IamGroupOwner -GroupName SG-Test -SecondaryOwner jamie -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'validates all target groups before changing the first owner' {
                Mock Get-ADGroup { throw 'Sample missing group' } -ParameterFilter { $Identity -eq 'SG-Missing' }
                { Set-IamGroupOwner -GroupName SG-Test,SG-Missing -PrimaryOwner alex -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'rejects the same primary and secondary account' {
                { Set-IamGroupOwner -GroupName SG-Test -PrimaryOwner alex -SecondaryOwner alex -SecondaryOwnerAttribute extensionAttribute12 -Server corp.example.com -Commit } | Should -Throw
                Assert-NoADWrite
            }
            It 'loads the existing secondary owner before rejecting a primary-only same-account change' {
                $group = New-TestGroup SG-Test
                $group.extensionAttribute12 = (New-TestUser alex).DistinguishedName
                $script:groups['SG-Test'] = $group
                {
                    Set-IamGroupOwner -GroupName SG-Test -PrimaryOwner alex `
                        -SecondaryOwnerAttribute extensionAttribute12 -Server corp.example.com -Commit
                } | Should -Throw
                Should -Invoke Get-ADGroup -Times 1 -Exactly -ParameterFilter {
                    $Identity -eq 'SG-Test' -and 'extensionAttribute12' -in $Properties
                }
                Assert-NoADWrite
            }
            It 'rejects a later group secondary-owner conflict before any primary-owner writes' {
                $first = New-TestGroup SG-First
                $first.extensionAttribute12 = (New-TestUser jamie).DistinguishedName
                $later = New-TestGroup SG-Later
                $later.extensionAttribute12 = (New-TestUser alex).DistinguishedName
                $script:groups['SG-First'] = $first
                $script:groups['SG-Later'] = $later
                {
                    Set-IamGroupOwner -GroupName SG-First,SG-Later -PrimaryOwner alex `
                        -SecondaryOwnerAttribute extensionAttribute12 -Server corp.example.com -Commit
                } | Should -Throw
                Should -Invoke Get-ADGroup -Times 2 -Exactly -ParameterFilter {
                    'extensionAttribute12' -in $Properties
                }
                Assert-NoADWrite
            }
            It 'rejects extra fields in an owner group-list CSV before any AD writes' {
                $file = Write-TestCsv 'owner-list.csv' @('GroupName','SG-First','SG-Later,unexpected')
                { Set-IamGroupOwner -Path $file -PrimaryOwner alex -Server corp.example.com -Commit } |
                    Should -Throw
                Assert-NoADWrite
            }
            It 'reports successful, failed and unattempted owner changes without losing earlier results' {
                Mock Set-ADGroup { throw 'Sample owner write failure' } -ParameterFilter { $Identity -like 'CN=SG-Fail,*' }
                $result = @(Set-IamGroupOwner -GroupName SG-Test,SG-Fail,SG-Last -PrimaryOwner alex -Server corp.example.com -Commit)
                $result | Should -HaveCount 3
                $result[0].Status | Should -Be Updated
                $result[1].Status | Should -Be Failed
                $result[1].Message | Should -Match 'Sample owner write failure'
                $result[2].Status | Should -Be NotAttempted
                Should -Invoke Set-ADGroup -Times 2 -Exactly
            }
            It 'reports Failed if owner read-back does not match' {
                Mock Set-ADGroup { }
                $result = Set-IamGroupOwner -GroupName SG-Test -PrimaryOwner alex -Server corp.example.com -Commit
                $result.Status | Should -Be Failed
                $result.Message | Should -Match 'verification'
            }
        }

        Context 'Read-only reports' {
            It 'reports direct group members and owner names' {
                $group = New-TestGroup SG-Test
                $group.ManagedBy = (New-TestUser alex).DistinguishedName
                $script:groups['SG-Test'] = $group
                $script:members[$group.DistinguishedName] = @(New-TestUser jamie)
                $result = Get-IamADGroupReport -GroupName SG-Test -Server corp.example.com
                $result.Members | Should -Be jamie
                $result.PrimaryOwner | Should -Be alex
                Assert-NoADWrite
            }
            It 'reports direct user memberOf links' {
                (Get-IamADUserGroupReport -UserName alex -Server corp.example.com).DirectGroups | Should -Be SG-Parent
                Assert-NoADWrite
            }
            It 'writes a JSON snapshot without changing AD' {
                $result = Export-IamGroupSnapshot -GroupName SG-Test -Server corp.example.com -OutputDirectory (Join-Path $TestDrive 'snapshots')
                (Get-Content $result.File -Raw | ConvertFrom-Json).GroupName | Should -Be SG-Test
                Assert-NoADWrite
            }
            It 'uses distinct snapshot filenames when sanitized group names collide' {
                $result = @(Export-IamGroupSnapshot -GroupName 'SG/Test','SG?Test' -Server corp.example.com -OutputDirectory (Join-Path $TestDrive 'collisions'))
                $result | Should -HaveCount 2
                $result[0].File | Should -Not -Be $result[1].File
                @((Get-ChildItem (Join-Path $TestDrive 'collisions') -Filter '*.json')) | Should -HaveCount 2
                (Get-Content $result[0].File -Raw | ConvertFrom-Json).GroupName | Should -Be 'SG/Test'
                (Get-Content $result[1].File -Raw | ConvertFrom-Json).GroupName | Should -Be 'SG?Test'
                Assert-NoADWrite
            }
            It 'rejects an existing file as the snapshot output directory without reporting a saved file' {
                $outputPath = Join-Path $TestDrive 'existing-file.txt'
                'Sample existing content' | Set-Content -LiteralPath $outputPath
                $script:snapshotRows = @()
                {
                    Export-IamGroupSnapshot -GroupName SG-Test -Server corp.example.com `
                        -OutputDirectory $outputPath -ErrorAction Continue |
                        ForEach-Object { $script:snapshotRows += $_ }
                } | Should -Throw
                $script:snapshotRows | Should -HaveCount 0
                Get-Content -LiteralPath $outputPath | Should -Be 'Sample existing content'
                Assert-NoADWrite
            }
            It 'terminates a snapshot on a directory creation error without reporting a saved file' {
                Mock New-Item { Write-Error 'Sample directory creation failure' }
                $script:snapshotRows = @()
                {
                    Export-IamGroupSnapshot -GroupName SG-Test -Server corp.example.com `
                        -OutputDirectory (Join-Path $TestDrive 'uncreated') -ErrorAction Continue |
                        ForEach-Object { $script:snapshotRows += $_ }
                } | Should -Throw '*Sample directory creation failure*'
                $script:snapshotRows | Should -HaveCount 0
                Should -Invoke New-Item -Times 1 -Exactly -ParameterFilter { $ErrorAction -eq 'Stop' }
                Assert-NoADWrite
            }
            It 'terminates a snapshot on a JSON write error without reporting a saved file' {
                Mock Set-Content { Write-Error 'Sample snapshot write failure' }
                $script:snapshotRows = @()
                {
                    Export-IamGroupSnapshot -GroupName SG-Test -Server corp.example.com `
                        -OutputDirectory $TestDrive -ErrorAction Continue |
                        ForEach-Object { $script:snapshotRows += $_ }
                } | Should -Throw '*Sample snapshot write failure*'
                $script:snapshotRows | Should -HaveCount 0
                Should -Invoke Set-Content -Times 1 -Exactly -ParameterFilter { $ErrorAction -eq 'Stop' }
                Assert-NoADWrite
            }
        }

        Context 'Read-only Graph pagination' {
            It 'follows the full nextLink and sends GET and the advanced query header on every page' {
                $script:next = 'https://graph.microsoft.com/v1.0/users/alex%40contoso.com/memberOf/microsoft.graph.group?$skiptoken=opaque%2Btoken'
                Mock Invoke-MgGraphRequest {
                    if ($Uri -eq $script:next) { return [pscustomobject]@{ value = @([pscustomobject]@{ id = 'sample-group-2'; displayName = 'Sample editors'; securityEnabled = $true }) } }
                    @{ value = @(@{ id = 'sample-group-1'; displayName = 'Sample readers'; securityEnabled = $true }); '@odata.nextLink' = $script:next }
                }
                $result = @(Get-IamGraphGroupMembership -UserPrincipalName alex@contoso.com)
                $result | Should -HaveCount 2
                $result[0].GroupId | Should -Be sample-group-1
                $result[1].GroupName | Should -Be 'Sample editors'
                Should -Invoke Invoke-MgGraphRequest -Times 2 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Headers.ConsistencyLevel -eq 'eventual' }
                Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq $script:next }
                Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -match '\$count=true' -and $Uri -match '/memberOf/microsoft.graph.group' }
                Assert-NoADWrite
            }
            It 'rejects an unexpected next link before sending a second request: <Url>' -TestCases @(
                @{ Url = 'https://example.org/steal-token' }
                @{ Url = 'http://graph.microsoft.com/v1.0/users/alex%40contoso.com/memberOf/microsoft.graph.group?$skiptoken=2' }
                @{ Url = 'https://graph.microsoft.com:8443/v1.0/users/alex%40contoso.com/memberOf/microsoft.graph.group?$skiptoken=2' }
                @{ Url = 'https://sample@graph.microsoft.com/v1.0/users/alex%40contoso.com/memberOf/microsoft.graph.group?$skiptoken=2' }
                @{ Url = 'https://graph.microsoft.com/v1.0/users/other%40contoso.com/memberOf/microsoft.graph.group?$skiptoken=2' }
                @{ Url = 'https://graph.microsoft.com/v1.0/users/alex%40contoso.com/transitiveMemberOf?$skiptoken=2' }
                @{ Url = 'https://graph.microsoft.com/v1.0/users/alex%40contoso.com/memberOf/microsoft.graph.group?$skiptoken=2#fragment' }
            ) {
                param($Url)
                $script:badNext = $Url
                Mock Invoke-MgGraphRequest { @{ value = @(); '@odata.nextLink' = $script:badNext } }
                { Get-IamGraphGroupMembership -UserPrincipalName alex@contoso.com } | Should -Throw '*pagination*'
                Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly
            }
            It 'rejects repeated pagination links instead of looping forever' {
                $script:next = 'https://graph.microsoft.com/v1.0/users/alex%40contoso.com/memberOf/microsoft.graph.group?$skiptoken=repeat'
                $script:graphCalls = 0
                Mock Invoke-MgGraphRequest {
                    $script:graphCalls++
                    if ($script:graphCalls -gt 3) { throw 'Test guard: repeated Graph calls' }
                    @{ value = @(); '@odata.nextLink' = $script:next }
                }
                { Get-IamGraphGroupMembership -UserPrincipalName alex@contoso.com } | Should -Throw '*pagination*'
                Should -Invoke Invoke-MgGraphRequest -Times 2 -Exactly
            }
            It 'returns no synthetic group row for a user without direct groups' {
                @(Get-IamGraphGroupMembership -UserPrincipalName alex@contoso.com) | Should -HaveCount 0
                Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly
            }
            It 'rejects a malformed Graph response instead of reporting an empty membership' {
                Mock Invoke-MgGraphRequest { @{ error = @{ message = 'Sample error payload' } } }
                { Get-IamGraphGroupMembership -UserPrincipalName alex@contoso.com } | Should -Throw
            }
        }
    }
}
