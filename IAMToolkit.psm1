#Requires -Version 5.1

# Generic AD and Entra ID helpers. No connection or directory changes happen on import.

function Assert-IamADModule {
    if (-not (Get-Module -Name ActiveDirectory)) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
}

function Read-IamNameInput {
    param(
        [string[]]$Names,
        [string]$Path,
        [string]$ColumnName
    )

    if ($Path -and $Names) {
        throw 'Use names or -Path, not both.'
    }

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Input file not found: $Path"
        }

        $extension = [IO.Path]::GetExtension($Path).ToLowerInvariant()
        if ($extension -eq '.txt') {
            $Names = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
        }
        elseif ($extension -eq '.csv') {
            $rows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
            if ($rows.Count -eq 0 -or $ColumnName -notin $rows[0].PSObject.Properties.Name) {
                throw "CSV must have a '$ColumnName' column and at least one row."
            }
            $Names = @($rows | ForEach-Object { $_.$ColumnName })
        }
        else {
            throw 'Use a .txt or .csv file for list input.'
        }
    }

    $seen = @{}
    $clean = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($Names)) {
        $value = ([string]$item).Trim()
        if (-not $value -or $value.StartsWith('#')) { continue }
        if (-not $seen.ContainsKey($value)) {
            $seen[$value] = $true
            $clean.Add($value)
        }
    }

    if ($clean.Count -eq 0) { throw 'No usable input values were supplied.' }
    return $clean.ToArray()
}

function Import-IamRequestCsv {
    param([string]$Path, [string[]]$RequiredColumns)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "CSV file not found: $Path"
    }
    if ([IO.Path]::GetExtension($Path) -ine '.csv') {
        throw 'Input must be a .csv file.'
    }

    # Import-Csv silently drops extra fields. Reject malformed requests instead.
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
    $csv = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser((Resolve-Path -LiteralPath $Path).ProviderPath)
    $csv.SetDelimiters(',')
    $csv.HasFieldsEnclosedInQuotes = $true
    $csv.TrimWhiteSpace = $false
    try {
        if ($csv.EndOfData) { throw 'CSV has no header row.' }
        $headings = @($csv.ReadFields())
        $seen = @{}
        foreach ($heading in $headings) {
            if ([string]::IsNullOrWhiteSpace($heading) -or $seen.ContainsKey($heading)) {
                throw 'CSV headings must be nonempty and unique.'
            }
            $seen[$heading] = $true
        }
        foreach ($name in $RequiredColumns) {
            if ($name -notin $headings) { throw "Missing CSV column '$name'." }
        }
        $rows = New-Object 'System.Collections.Generic.List[object]'
        while (-not $csv.EndOfData) {
            $line = $csv.LineNumber
            $fields = @($csv.ReadFields())
            if ($fields.Count -ne $headings.Count) {
                throw "CSV row at line $line has $($fields.Count) fields; expected $($headings.Count)."
            }
            $row = [ordered]@{}
            for ($i = 0; $i -lt $headings.Count; $i++) { $row[$headings[$i]] = $fields[$i] }
            $rows.Add([PSCustomObject]$row)
        }
        if ($rows.Count -eq 0) { throw 'CSV has no data rows.' }
        return $rows.ToArray()
    }
    finally {
        $csv.Close()
    }
}

function Split-IamMember {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    $seen = @{}
    $members = New-Object 'System.Collections.Generic.List[string]'
    foreach ($part in ($Value -split '[;\r\n]+')) {
        $member = $part.Trim()
        if ($member) {
            if ($seen.ContainsKey($member)) { throw "Repeated member '$member'." }
            $seen[$member] = $true
            $members.Add($member)
        }
    }
    return $members.ToArray()
}

function ConvertTo-IamLdapValue {
    param([string]$Text)

    $result = $Text.Replace('\', '\5c')
    $result = $result.Replace('*', '\2a')
    $result = $result.Replace('(', '\28').Replace(')', '\29')
    return $result.Replace([string][char]0, '\00')
}

function Get-IamRdnName {
    param([string]$DistinguishedName)

    if ($DistinguishedName -match '^CN=((?:\\.|[^,])+)') {
        return ($Matches[1] -replace '\\,', ',' -replace '\\\\', '\')
    }
    return $DistinguishedName
}

function Get-IamADUser {
    param([string]$Identity, [string]$Server)

    try {
        return Get-ADUser -Identity $Identity -Server $Server `
            -Properties DisplayName,GivenName,Surname,Enabled -ErrorAction Stop
    }
    catch {
        throw "Cannot resolve user '$Identity' on '$Server': $($_.Exception.Message)"
    }
}

function Get-IamADGroup {
    param([string]$Identity, [string]$Server, [string[]]$Properties = @())

    try {
        $options = @{ Identity = $Identity; Server = $Server; ErrorAction = 'Stop' }
        if ($Properties.Count -gt 0) { $options['Properties'] = $Properties }
        return Get-ADGroup @options
    }
    catch {
        throw "Cannot resolve group '$Identity' on '$Server': $($_.Exception.Message)"
    }
}

function Assert-IamSecondaryOwnerAttribute {
    param([string]$Attribute, [string]$Server)

    $root = Get-ADRootDSE -Server $Server -ErrorAction Stop
    $safeAttribute = ConvertTo-IamLdapValue $Attribute
    $schema = @(Get-ADObject -SearchBase $root.SchemaNamingContext -Server $Server `
        -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$safeAttribute))" `
        -Properties isSingleValued -ErrorAction Stop)
    if ($schema.Count -ne 1 -or -not $schema[0].isSingleValued) {
        throw "Secondary owner attribute '$Attribute' must exist as a single-valued attribute in the AD schema."
    }
}

function Test-IamMembership {
    param($User, $Group, [string]$Server)

    $userSid = [string]$User.SID
    $userDn = [string]$User.DistinguishedName
    $members = @(Get-ADGroupMember -Identity $Group.DistinguishedName `
        -Server $Server -ErrorAction Stop)

    foreach ($member in $members) {
        if ($userSid -and $member.SID -and [string]$member.SID -eq $userSid) {
            return $true
        }
        if ($member.DistinguishedName -and $userDn -and
            $member.DistinguishedName -ieq $userDn) {
            return $true
        }
    }
    return $false
}

function Save-IamCsv {
    param([object[]]$Rows, [string]$Path)

    if (-not $Path) { return }
    if ($Rows.Count -eq 0) {
        Write-Warning "No rows available; CSV output will be empty: $Path"
    }
    $Rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
}

function Get-IamADGroupReport {
    <#
    .SYNOPSIS
        Show direct members, parent groups, description and primary owner.
    .EXAMPLE
        Get-IamADGroupReport -GroupName 'SG-App-Readers' -Server 'corp.example.com'
    .EXAMPLE
        Get-IamADGroupReport -Path .\Examples\groups.txt -Server 'corp.example.com' -ExportPath .\group-report.csv
    #>
    [CmdletBinding()]
    param(
        [string[]]$GroupName,
        [string]$Path,
        [Parameter(Mandatory)][string]$Server,
        [string]$ExportPath
    )

    Assert-IamADModule
    $names = @(Read-IamNameInput -Names $GroupName -Path $Path -ColumnName 'GroupName')
    $report = foreach ($name in $names) {
        $group = Get-IamADGroup -Identity $name -Server $Server `
            -Properties @('Description','ManagedBy','MemberOf')
        $members = @(Get-ADGroupMember -Identity $group.DistinguishedName -Server $Server -ErrorAction Stop)

        [PSCustomObject]@{
            GroupName    = $group.Name
            Members      = (@($members | ForEach-Object { $_.Name } | Sort-Object) -join '; ')
            MemberOf     = (@($group.MemberOf | ForEach-Object { Get-IamRdnName $_ } | Sort-Object) -join '; ')
            Description  = [string]$group.Description
            PrimaryOwner = if ($group.ManagedBy) { Get-IamRdnName $group.ManagedBy } else { '' }
        }
    }

    $results = @($report)
    Save-IamCsv -Rows $results -Path $ExportPath
    $results
}

function Get-IamADUserGroupReport {
    <#
    .SYNOPSIS
        List a user's memberOf attribute (direct links, excluding the primary group).
    #>
    [CmdletBinding()]
    param(
        [string[]]$UserName,
        [string]$Path,
        [Parameter(Mandatory)][string]$Server,
        [string]$ExportPath
    )

    Assert-IamADModule
    $users = @(Read-IamNameInput -Names $UserName -Path $Path -ColumnName 'UserName')
    $report = foreach ($name in $users) {
        $user = Get-ADUser -Identity $name -Server $Server -Properties MemberOf,DisplayName -ErrorAction Stop
        [PSCustomObject]@{
            UserName    = $user.SamAccountName
            DisplayName = $user.DisplayName
            DirectGroups = (@($user.MemberOf | ForEach-Object { Get-IamRdnName $_ } | Sort-Object) -join '; ')
        }
    }

    $results = @($report)
    Save-IamCsv -Rows $results -Path $ExportPath
    $results
}

function Invoke-IamMembershipCsv {
    <#
    .SYNOPSIS
        Apply add/remove membership requests from a simple CSV, preview first.
    .DESCRIPTION
        The CSV must have GroupName, UserName and Action columns.
        Action is Add or Remove. All rows are checked before writes begin.
    .EXAMPLE
        Invoke-IamMembershipCsv -Path .\Examples\membership.csv -Server 'corp.example.com'
    .EXAMPLE
        Invoke-IamMembershipCsv -Path .\Examples\membership.csv -Server 'corp.example.com' -Commit
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Server,
        [switch]$Commit,
        [string]$ReportPath
    )

    Assert-IamADModule
    $rows = @(Import-IamRequestCsv -Path $Path -RequiredColumns @('GroupName','UserName','Action'))
    $plan = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    $resolved = @{}

    foreach ($row in $rows) {
        $groupName = ([string]$row.GroupName).Trim()
        $userName = ([string]$row.UserName).Trim()
        $action = ([string]$row.Action).Trim()
        if (-not $groupName -or -not $userName -or $action -notin @('Add','Remove')) {
            throw "Invalid membership row: GroupName='$groupName'; UserName='$userName'; Action='$action'."
        }
        $key = "$($groupName.ToLowerInvariant())|$($userName.ToLowerInvariant())"
        if ($seen.ContainsKey($key)) { throw "Repeated membership request for $groupName / $userName." }
        $seen[$key] = $true

        $group = Get-IamADGroup -Identity $groupName -Server $Server
        if ($group.GroupCategory -ne 'Security') {
            throw "'$groupName' is not a security group."
        }
        $user = Get-IamADUser -Identity $userName -Server $Server
        $resolvedKey = "$($group.DistinguishedName)|$($user.DistinguishedName)"
        if ($resolved.ContainsKey($resolvedKey)) {
            throw "Repeated membership request resolving to $groupName / $userName."
        }
        $resolved[$resolvedKey] = $true
        if ($action -eq 'Add' -and -not $user.Enabled) {
            throw "Cannot add disabled user '$userName'."
        }
        $present = Test-IamMembership -User $user -Group $group -Server $Server
        $plan.Add([PSCustomObject]@{
            GroupName = $group.Name
            UserName  = $user.SamAccountName
            Action    = $action
            Group     = $group
            User      = $user
            Present   = $present
        })
    }

    $results = New-Object 'System.Collections.Generic.List[object]'
    $stopped = $false
    foreach ($item in $plan) {
        $needsChange = ($item.Action -eq 'Add' -and -not $item.Present) -or
            ($item.Action -eq 'Remove' -and $item.Present)
        $status = 'NoChange'
        $message = ''

        if ($stopped) {
            $status = 'NotAttempted'
            $message = 'Batch stopped after an earlier failure.'
        }
        elseif ($needsChange -and -not $Commit) {
            $status = 'Preview'
            $message = 'No AD changes made.'
        }
        elseif ($needsChange) {
            $target = "$($item.UserName) / $($item.GroupName)"
            if ($PSCmdlet.ShouldProcess($target, "$($item.Action) direct group membership")) {
                try {
                    if ($item.Action -eq 'Add') {
                        Add-ADGroupMember -Identity $item.Group.DistinguishedName `
                            -Members $item.User -Server $Server -Confirm:$false -ErrorAction Stop
                    }
                    else {
                        Remove-ADGroupMember -Identity $item.Group.DistinguishedName `
                            -Members $item.User -Server $Server -Confirm:$false -ErrorAction Stop
                    }

                    $after = Test-IamMembership -User $item.User -Group $item.Group -Server $Server
                    if ($after -ne ($item.Action -eq 'Add')) {
                        throw 'Directory read-back did not match the requested change.'
                    }
                    $status = 'Updated'
                }
                catch {
                    $status = 'Failed'
                    $message = "Change may have been applied; verify AD before retrying. $($_.Exception.Message)"
                    $stopped = $true
                }
            }
            else {
                $status = 'Skipped'
            }
        }

        $results.Add([PSCustomObject]@{
            GroupName = $item.GroupName
            UserName  = $item.UserName
            Action    = $item.Action
            Status    = $status
            Message   = $message
        })
    }

    Save-IamCsv -Rows $results.ToArray() -Path $ReportPath
    return $results.ToArray()
}

function Set-IamGroupOwner {
    <#
    .SYNOPSIS
        Update a group's primary owner and optionally a secondary owner attribute.
    .EXAMPLE
        Set-IamGroupOwner -GroupName SG-App-Readers -PrimaryOwner jdoe -Server corp.example.com -Commit
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [string[]]$GroupName,
        [string]$Path,
        [Parameter(Mandatory)][string]$Server,
        [string]$PrimaryOwner,
        [string]$SecondaryOwner,
        [ValidatePattern('^extensionAttribute(?:[1-9]|1[0-5])$')]
        [string]$SecondaryOwnerAttribute,
        [switch]$Commit
    )

    if (-not $PrimaryOwner -and -not $SecondaryOwner) {
        throw 'Supply -PrimaryOwner, -SecondaryOwner, or both.'
    }
    if ($SecondaryOwner -and -not $SecondaryOwnerAttribute) {
        throw 'Supply -SecondaryOwnerAttribute when setting a secondary owner.'
    }

    Assert-IamADModule
    $names = @(Read-IamNameInput -Names $GroupName -Path $Path -ColumnName 'GroupName')
    $primary = if ($PrimaryOwner) { Get-IamADUser -Identity $PrimaryOwner -Server $Server }
    $secondary = if ($SecondaryOwner) { Get-IamADUser -Identity $SecondaryOwner -Server $Server }
    if ($primary -and -not $primary.Enabled) { throw 'Primary owner must be enabled.' }
    if ($secondary -and -not $secondary.Enabled) { throw 'Secondary owner must be enabled.' }
    if ($primary -and $secondary -and $primary.DistinguishedName -ieq $secondary.DistinguishedName) {
        throw 'Primary and secondary owners cannot be the same account.'
    }

    $properties = @('ManagedBy')
    if ($secondary) {
        Assert-IamSecondaryOwnerAttribute -Attribute $SecondaryOwnerAttribute -Server $Server
        $properties += $SecondaryOwnerAttribute
    }
    $seenGroups = @{}
    $groups = foreach ($name in $names) {
        $group = Get-IamADGroup -Identity $name -Server $Server -Properties $properties
        $effectivePrimary = if ($primary) { $primary.DistinguishedName } else { $group.ManagedBy }
        if ($secondary -and $effectivePrimary -ieq $secondary.DistinguishedName) {
            throw "Primary and secondary owners cannot be the same account for '$($group.Name)'."
        }
        if (-not $seenGroups.ContainsKey($group.DistinguishedName)) {
            $seenGroups[$group.DistinguishedName] = $true
            $group
        }
    }

    $stopped = $false
    $results = foreach ($group in $groups) {
        $primaryChange = $primary -and $group.ManagedBy -ine $primary.DistinguishedName
        $secondaryChange = $secondary -and $group.$SecondaryOwnerAttribute -ine $secondary.DistinguishedName
        $status = 'NoChange'
        $message = ''
        if ($stopped) {
            $status = 'NotAttempted'
            $message = 'Batch stopped after an earlier failure.'
        }
        elseif ($primaryChange -or $secondaryChange) {
            if (-not $Commit) {
                $status = 'Preview'
            }
            elseif ($PSCmdlet.ShouldProcess($group.Name, 'Update group owner attributes')) {
                $set = @{
                    Identity = $group.DistinguishedName
                    Server = $Server
                    Confirm = $false
                    ErrorAction = 'Stop'
                }
                if ($primaryChange) { $set['ManagedBy'] = $primary.DistinguishedName }
                if ($secondaryChange) {
                    $replace = @{}
                    $replace[$SecondaryOwnerAttribute] = $secondary.DistinguishedName
                    $set['Replace'] = $replace
                }
                try {
                    Set-ADGroup @set
                    $fresh = Get-IamADGroup -Identity $group.DistinguishedName -Server $Server -Properties $properties
                    if (($primary -and $fresh.ManagedBy -ine $primary.DistinguishedName) -or
                        ($secondary -and $fresh.$SecondaryOwnerAttribute -ine $secondary.DistinguishedName)) {
                        throw "Owner verification failed for '$($group.Name)'."
                    }
                    $status = 'Updated'
                }
                catch {
                    $status = 'Failed'
                    $message = "Change may have been applied; verify AD before retrying. $($_.Exception.Message)"
                    $stopped = $true
                }
            }
            else {
                $status = 'Skipped'
            }
        }
        [PSCustomObject]@{ GroupName = $group.Name; Status = $status; Message = $message }
    }
    $results
}

function New-IamADGroupsFromCsv {
    <#
    .SYNOPSIS
        Create security groups, owners and direct members from a CSV.
    .DESCRIPTION
        Required columns: GroupName, Description, PrimaryOwner,
        SecondaryOwner, Members. Optional: TicketNumber, GroupScope.
        Identifiers are sAMAccountNames in the chosen AD domain.
    .EXAMPLE
        New-IamADGroupsFromCsv -Path .\Examples\new-groups.csv -TargetOU 'OU=Groups,DC=corp,DC=example,DC=com' -Server corp.example.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$TargetOU,
        [Parameter(Mandatory)][string]$Server,
        [ValidatePattern('^extensionAttribute(?:[1-9]|1[0-5])$')]
        [string]$SecondaryOwnerAttribute = 'extensionAttribute12',
        [switch]$Commit,
        [string]$ReportPath,
        [string]$TicketCommentsPath
    )

    Assert-IamADModule
    $rows = @(Import-IamRequestCsv -Path $Path -RequiredColumns @(
        'GroupName','Description','PrimaryOwner','SecondaryOwner','Members'
    ))
    $null = Get-ADOrganizationalUnit -Identity $TargetOU -Server $Server -ErrorAction Stop
    Assert-IamSecondaryOwnerAttribute -Attribute $SecondaryOwnerAttribute -Server $Server

    $plan = New-Object 'System.Collections.Generic.List[object]'
    $seenNames = @{}

    foreach ($row in $rows) {
        $name = ([string]$row.GroupName).Trim()
        $description = ([string]$row.Description).Trim()
        $scope = ([string]$row.GroupScope).Trim()
        if (-not $scope) { $scope = 'Universal' }
        $ticket = ([string]$row.TicketNumber).Trim()

        if ($name -notmatch '^[A-Za-z0-9._-]{3,64}$') {
            throw "Invalid group name '$name'. Use 3-64 letters, numbers, periods, underscores or dashes."
        }
        if (-not $description) { throw "Group '$name' needs a description." }
        if ($scope -notin @('Global','Universal','DomainLocal')) {
            throw "Invalid GroupScope '$scope' for '$name'."
        }
        if ($seenNames.ContainsKey($name)) { throw "Group '$name' appears more than once in the CSV." }
        $seenNames[$name] = $true

        $safeName = ConvertTo-IamLdapValue $name
        $existing = @(Get-ADObject -LDAPFilter "(sAMAccountName=$safeName)" -Server $Server -ErrorAction Stop)
        if ($existing.Count -gt 0) { throw "sAMAccountName '$name' already exists on '$Server'." }
        $sameRdn = @(Get-ADObject -SearchBase $TargetOU -SearchScope OneLevel `
            -LDAPFilter "(cn=$safeName)" -Server $Server -ErrorAction Stop)
        if ($sameRdn.Count -gt 0) { throw "Name '$name' already exists in the target OU." }

        $primaryText = ([string]$row.PrimaryOwner).Trim()
        $secondaryText = ([string]$row.SecondaryOwner).Trim()
        if (-not $primaryText -or -not $secondaryText) {
            throw "Group '$name' requires both owner columns."
        }
        $primary = Get-IamADUser -Identity $primaryText -Server $Server
        $secondary = Get-IamADUser -Identity $secondaryText -Server $Server
        if (-not $primary.Enabled -or -not $secondary.Enabled) {
            throw "Group '$name' has a disabled owner."
        }
        if ($primary.DistinguishedName -ieq $secondary.DistinguishedName) {
            throw "Group '$name' has the same primary and secondary owner."
        }

        $memberObjects = New-Object 'System.Collections.Generic.List[object]'
        $seenMembers = @{}
        foreach ($memberName in @(Split-IamMember $row.Members)) {
            $user = Get-IamADUser -Identity $memberName -Server $Server
            if (-not $user.Enabled) { throw "Group '$name': member '$memberName' is disabled." }
            if ($seenMembers.ContainsKey($user.DistinguishedName)) {
                throw "Group '$name' has a repeated member resolving to '$memberName'."
            }
            $seenMembers[$user.DistinguishedName] = $true
            $memberObjects.Add($user)
        }

        $plan.Add([PSCustomObject]@{
            GroupName      = $name
            Description    = $description
            GroupScope     = $scope
            TicketNumber   = $ticket
            Primary        = $primary
            Secondary      = $secondary
            Members        = $memberObjects.ToArray()
        })
    }

    $results = New-Object 'System.Collections.Generic.List[object]'
    $ticketComments = New-Object 'System.Collections.Generic.List[object]'
    $stopped = $false
    foreach ($item in $plan) {
        $status = 'Preview'
        $message = 'No AD changes made.'
        if ($stopped) {
            $status = 'NotAttempted'
            $message = 'Batch stopped after an earlier failure.'
        }
        elseif ($Commit) {
            if (-not $PSCmdlet.ShouldProcess($item.GroupName, "Create AD security group in $TargetOU")) {
                $status = 'Skipped'
                $message = ''
            }
            else {
                $created = $false
                try {
                    $newGroup = New-ADGroup -Name $item.GroupName -SamAccountName $item.GroupName `
                        -Description $item.Description -GroupCategory Security `
                        -GroupScope $item.GroupScope -Path $TargetOU -Server $Server `
                        -ManagedBy $item.Primary.DistinguishedName -PassThru -Confirm:$false -ErrorAction Stop
                    $created = $true

                    $extra = @{}
                    $extra[$SecondaryOwnerAttribute] = $item.Secondary.DistinguishedName
                    if ($item.TicketNumber) { $extra['info'] = $item.TicketNumber }
                    Set-ADGroup -Identity $newGroup.DistinguishedName -Replace $extra `
                        -Server $Server -Confirm:$false -ErrorAction Stop

                    if ($item.Members.Count -gt 0) {
                        Add-ADGroupMember -Identity $newGroup.DistinguishedName `
                            -Members $item.Members -Server $Server -Confirm:$false -ErrorAction Stop
                    }

                    $fresh = Get-IamADGroup -Identity $newGroup.DistinguishedName -Server $Server `
                        -Properties @('Description','ManagedBy',$SecondaryOwnerAttribute,'info')
                    if ($fresh.ManagedBy -ine $item.Primary.DistinguishedName -or
                        $fresh.$SecondaryOwnerAttribute -ine $item.Secondary.DistinguishedName -or
                        $fresh.Description -ne $item.Description -or
                        ($item.TicketNumber -and $fresh.info -ne $item.TicketNumber)) {
                        throw 'Group metadata verification failed.'
                    }
                    $actualMembers = @(Get-ADGroupMember -Identity $newGroup.DistinguishedName `
                        -Server $Server -ErrorAction Stop)
                    foreach ($member in $item.Members) {
                        $found = @($actualMembers | Where-Object {
                            $_.DistinguishedName -ieq $member.DistinguishedName
                        })
                        if ($found.Count -eq 0) { throw "Member verification failed: $($member.SamAccountName)" }
                    }

                    $status = 'Created'
                    $message = 'Created and verified.'
                    $ownerName = if ($item.Primary.DisplayName) { $item.Primary.DisplayName } else { $item.Primary.SamAccountName }
                    $backupName = if ($item.Secondary.DisplayName) { $item.Secondary.DisplayName } else { $item.Secondary.SamAccountName }
                    $memberLines = @($item.Members | ForEach-Object {
                        if ($_.DisplayName) { '- ' + $_.DisplayName } else { '- ' + $_.SamAccountName }
                    })
                    $comment = @(
                        "Created AD group: $($item.GroupName)",
                        "Primary owner: $ownerName",
                        "Secondary owner: $backupName",
                        '',
                        'Members added:'
                    ) + $memberLines
                    $ticketComments.Add([PSCustomObject]@{
                        TicketNumber = $item.TicketNumber
                        GroupName = $item.GroupName
                        Comments = $comment -join "`r`n"
                    })
                }
                catch {
                    $status = if ($created) { 'Partial' } else { 'Failed' }
                    $message = "Verify AD before retrying; a failed request may still have reached the server. $($_.Exception.Message)"
                    $stopped = $true
                }
            }
        }

        $results.Add([PSCustomObject]@{
            TicketNumber = $item.TicketNumber
            GroupName    = $item.GroupName
            GroupScope   = $item.GroupScope
            MemberCount  = $item.Members.Count
            Status       = $status
            Message      = $message
        })
    }

    Save-IamCsv -Rows $results.ToArray() -Path $ReportPath
    Save-IamCsv -Rows $ticketComments.ToArray() -Path $TicketCommentsPath
    return $results.ToArray()
}

function Export-IamGroupSnapshot {
    <#
    .SYNOPSIS
        Save a read-only group information report for a change ticket.
    .EXAMPLE
        Export-IamGroupSnapshot -GroupName SG-Legacy-App -Server corp.example.com -OutputDirectory .\Snapshots
    #>
    [CmdletBinding()]
    param(
        [string[]]$GroupName,
        [string]$Path,
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$OutputDirectory
    )

    $groups = @(Get-IamADGroupReport -GroupName $GroupName -Path $Path -Server $Server)
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    foreach ($group in $groups) {
        $safeName = $group.GroupName -replace '[^A-Za-z0-9._-]', '_'
        $suffix = [Guid]::NewGuid().ToString('N')
        $output = Join-Path $OutputDirectory "$safeName-$stamp-$suffix.json"
        $group | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $output -Encoding UTF8
        [PSCustomObject]@{ GroupName = $group.GroupName; File = $output }
    }
}

function Get-IamGraphValue {
    param($InputObject, [string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject[$Name] }
    return $InputObject.$Name
}

function Test-IamGraphNextLink {
    param([string]$Url, [string]$ExpectedPath)
    [Uri]$uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri)) { return $false }
    if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'graph.microsoft.com' -or
        $uri.Port -ne 443 -or $uri.UserInfo -or $uri.Fragment) { return $false }
    if ($uri.AbsolutePath -cnotmatch '^/v1\.0/users/[^/]+/memberOf(?:/microsoft\.graph\.group)?$') {
        return $false
    }
    return (-not $ExpectedPath -or $uri.AbsolutePath -ceq $ExpectedPath)
}

function Get-IamGraphGroupMembership {
    <#
    .SYNOPSIS
        Read a user's direct Microsoft Entra ID group memberships through Graph.
    .DESCRIPTION
        Connect first with Connect-MgGraph. Handles @odata.nextLink paging.
        This command only makes GET requests; it never changes a tenant.
    .EXAMPLE
        Connect-MgGraph -Scopes 'GroupMember.Read.All'
        Get-IamGraphGroupMembership -UserPrincipalName 'alex@contoso.com'
    #>
    [CmdletBinding()]
    param(
        [string[]]$UserPrincipalName,
        [string]$Path,
        [string]$ExportPath
    )

    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Microsoft.Graph.Authentication is required. Install/import the module and run Connect-MgGraph.'
    }
    $names = @(Read-IamNameInput -Names $UserPrincipalName -Path $Path -ColumnName 'UserPrincipalName')
    $report = New-Object 'System.Collections.Generic.List[object]'
    foreach ($upn in $names) {
        $encoded = [Uri]::EscapeDataString($upn)
        $url = 'https://graph.microsoft.com/v1.0/users/{0}/memberOf/microsoft.graph.group?$count=true&$select=id,displayName,mail,securityEnabled' -f $encoded
        $expectedPath = ([Uri]$url).AbsolutePath
        $seenUrls = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        do {
            if (-not $seenUrls.Add($url)) { throw 'Microsoft Graph returned a repeated pagination URL.' }
            $response = Invoke-MgGraphRequest -Method GET -Uri $url `
                -Headers @{ ConsistencyLevel = 'eventual' } -ErrorAction Stop
            $hasValues = if ($response -is [System.Collections.IDictionary]) {
                $response.Contains('value')
            }
            else { $null -ne $response -and 'value' -in $response.PSObject.Properties.Name }
            if (-not $hasValues) { throw 'Microsoft Graph returned a response without a membership collection.' }
            foreach ($group in @(Get-IamGraphValue -InputObject $response -Name 'value')) {
                if ($null -eq $group) { continue }
                $report.Add([PSCustomObject]@{
                    UserPrincipalName = $upn
                    GroupId           = [string](Get-IamGraphValue -InputObject $group -Name 'id')
                    GroupName         = [string](Get-IamGraphValue -InputObject $group -Name 'displayName')
                    Mail              = [string](Get-IamGraphValue -InputObject $group -Name 'mail')
                    SecurityEnabled   = (Get-IamGraphValue -InputObject $group -Name 'securityEnabled')
                })
            }
            $url = [string](Get-IamGraphValue -InputObject $response -Name '@odata.nextLink')
            if ($url -and -not (Test-IamGraphNextLink -Url $url -ExpectedPath $expectedPath)) {
                throw 'Microsoft Graph returned an unexpected pagination URL.'
            }
        } while ($url)
    }
    Save-IamCsv -Rows $report.ToArray() -Path $ExportPath
    return $report.ToArray()
}

Export-ModuleMember -Function @(
    'Get-IamADGroupReport',
    'Get-IamADUserGroupReport',
    'Invoke-IamMembershipCsv',
    'Set-IamGroupOwner',
    'New-IamADGroupsFromCsv',
    'Export-IamGroupSnapshot',
    'Get-IamGraphGroupMembership'
)
