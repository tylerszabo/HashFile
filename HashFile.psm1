#Requires -Version 6

# Copyright (C) 2020 Tyler Szabo
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program.  If not, see <http:#www.gnu.org/licenses/>.

<#
.SYNOPSIS
Write hash output to file in GNU coreutils hash file format
.DESCRIPTION
Output results of Get-FileHash to files such that the resulting files can be consumed by GNU coreutils hash programs such as md5sum, sha1sum, sha256sum, etc.
.PARAMETER InputObject
Object output with Hash, Path, Algorithm properties
.PARAMETER Hash
Hash string (typically hex string)
.PARAMETER Path
Path to file
.PARAMETER Algorithm
Hash algorithm
.PARAMETER HashFile
If specified output hashes into a single specified file
.PARAMETER Force
If specified overwrite hash files
.EXAMPLE
Get-FileHash example.txt | Out-HashFile

Write SHA256 hash of example.txt to example.txt.sha256sum (assuming SHA256 is the Get-FileHash default)
.EXAMPLE
Get-ChildItem | Get-FileHash -Algorithm SHA1 | Out-HashFile

For each filename, write SHA1 hashes to FILENAME.sha1sum
.EXAMPLE
Get-ChildItem | Get-FileHash -Algorithm MD5 | Out-HashFile -HashFile md5sums.txt

Write MD5 hashes to md5sums.txt
.NOTES
If the hash file being written is also being taken as input will result in a FileReadError "The process cannot access the file ... because it is being used by another process"
#>
function Out-HashFile {
  [CmdletBinding(SupportsShouldProcess = $True, DefaultParameterSetName = "None")]
  Param (
    [Parameter(Mandatory = $True, Position = 0, ParameterSetName = "PipelineByProperty", ValueFromPipelineByPropertyName = $true)]
    [string]
    $Hash,

    [Parameter(Mandatory = $True, Position = 1, ParameterSetName = "PipelineByProperty", ValueFromPipelineByPropertyName = $true)]
    [string]
    $Path,

    [Parameter(Mandatory = $True, Position = 2, ParameterSetName = "PipelineByProperty", ValueFromPipelineByPropertyName = $true)]
    [string]
    $Algorithm,

    [string]
    $HashFile = $null,

    [switch]
    $Force = $False,

    [switch]
    $PassThru = $False
  )

  Begin {
    If ($HashFile) {
      Write-Verbose "Creating $HashFile"
      If (Test-Path -Path $HashFile) {
        If ($Force) {
          $null | Set-Content -LiteralPath $HashFile
        } Else {
          Throw "Will not overwrite $HashFile without -Force option"
        }
      }

      $BasePath = Split-Path -Path $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($HashFile)
      Write-Verbose "Am at $BasePath"
    }
  }

  Process {
    If ($InputObject) {
      $Path = $InputObject.Path
      $Hash = $InputObject.Hash
      $Algorithm = $InputObject.Algorithm
    }

    If (-Not $Path) { Throw "Missing Path" }
    If (-Not $Hash) { Throw "Missing Hash" }

    $outputHashString = $Hash.ToLower()

    If ($HashFile) {
      $outputFilename = $Path
      If ($outputFilename.StartsWith($BasePath)) {
        $outputFilename = $outputFilename.Substring($BasePath.Length + 1)
      }
      $outputFilename = $outputFilename.Replace("\", "/")
    } Else {
      $outputFilename = Split-Path -Path $Path -Leaf
    }

    $outputString = "{0} *{1}`n" -f $outputHashString, $outputFilename

    $outputString | Write-Verbose

    If ($HashFile) {
      # Append to single file
      $outputString | Add-Content -Encoding UTF8NoBOM -NoNewline -LiteralPath $HashFile
    } Else {
      If (-Not $Algorithm) { Throw "Missing Algorithm" }
      # Write to individual file
      $IndividualHashFile = "{0}.{1}sum" -f $Path, $Algorithm.toLower()
      If (-Not $Force -And (Test-Path -Path $IndividualHashFile)) {
        Throw "Will not overwrite $IndividualHashFile without -Force option"
      } Else {
        $outputString | Set-Content -Encoding UTF8NoBOM -NoNewline -LiteralPath $IndividualHashFile
      }
    }

    If ($PassThru) {
      $InputHashObject | Write-Output
    }
  }

  End {
    Write-Verbose "Done"
  }
}

$script:defaultDisplaySet = "Path", "Ok"
$script:defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]]$script:defaultDisplaySet)
$script:PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($script:defaultDisplayPropertySet)

<#
.SYNOPSIS
Tests hashes from a file in GNU coreutils hash file format
.DESCRIPTION
Tests hashes in a file that's been written by or for GNU coreutils hash programs such as md5sum, sha1sum, sha256sum, etc.
Provides the functionality of `sha256sum -c`
.PARAMETER InputObject
Text contents of hash file
.PARAMETER Path
Path to hash file
.PARAMETER Algorithm
Hash algorithm (if specified overrides Path extension)
.EXAMPLE
Test-HashFile -Path example.sha265sum

Tests the files in example.sha256sum using the SHA256 hash
.EXAMPLE
Get-Content example.sha256sum | Test-HashFile

Tests the files in example.sha256sum using the SHA256 hash
.EXAMPLE
Get-Content example.hashes | Test-HashFile -Algorithm SHA256

Tests the files in example.sha256sum using the SHA256 hash
.NOTES
If the hash file being written is also being taken as input will result in a FileReadError "The process cannot access the file ... because it is being used by another process"
#>
function Test-HashFile {
  [CmdletBinding(DefaultParameterSetName = "None")]
  Param (
    [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $True, ParameterSetName = "Path")]
    [Alias("FullName")]
    [string[]]
    $Path,

    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ParameterSetName = "InputObject")]
    [string[]]
    $InputObject,

    [Parameter(Mandatory = $False, Position = 1)]
    [ValidateSet(
      "SHA512",
      "SHA384",
      "SHA256",
      "SHA1",
      "MD5"
    )]
    [string]
    $Algorithm
  )

  Begin {
    If (-Not $Path) {
      $Path = @($null)
    }
    If ($Algorithm) {
      $ForceAlgorithm = $true
    }
  }

  Process {
    ForEach ($CurrentPath in $Path) {
      If ($CurrentPath) {
        Write-Verbose "Processing file: $CurrentPath"
        $Item = Get-Item -Path $CurrentPath
        $BasePath = $Item.Directory.FullName
        If (-Not $ForceAlgorithm -And $Item) {
          switch -wildcard ($Item.Extension) {
            ".sha512*" { $Algorithm = "SHA512" ; break }
            ".sha384*" { $Algorithm = "SHA384" ; break }
            ".sha256*" { $Algorithm = "SHA256" ; break }
            ".sha1*" { $Algorithm = "SHA1" ; break }
            ".md5*" { $Algorithm = "MD5" ; break }
          }
          Write-Verbose "Determined algorithm: $Algorithm"
        }
        $InputObject = Get-Content -Path $CurrentPath -Encoding UTF8
      } Else {
        $CurrentPath = "<stdin>"
        $BasePath = Get-Location
      }

      If (-Not $Algorithm) {
        Throw "Unable to determine algorithm"
      }

      $Lines = ($InputObject -split "[\r\n]", 0, "RegexMatch")
      ForEach ($Line in $Lines) {
        Write-Verbose "Processing line: $Line"
        If ($Line -match "^\s*$") {
          # Skip whitespace
        } ElseIf ($Line -match "(?m)^(?<Hash>[0-9a-f]+)\s+\*?(?<File>.*)$") {
          $TestFile = $Matches.File
          $ExpectedHash = $Matches.Hash

          $Result = [PSCustomObject]@{
            Algorithm = $Algorithm
            Path = $TestFile
            InputPath = $TestFile
            ActualHash = $null
            ExpectedHash = $ExpectedHash
            Ok = $False
          }

          Try {
            $Actual = Get-FileHash -Algorithm $Algorithm -LiteralPath (Join-Path -Path $BasePath -ChildPath $TestFile) -ErrorAction Stop
            $Result.ActualHash = $Actual.Hash
            $Result.Path = $Actual.Path

            If ($ExpectedHash -Eq $Actual.Hash) {
              $Result.Ok = $True
            } Else {
              Write-Warning "Hashes do not match in $CurrentPath`n $($Actual.Hash) $($Actual.Path)`n $ExpectedHash $TestFile"
            }
          } Catch {
            Write-Warning "$CurrentPath`: Get-FileHash failed $($_ | Out-String)"
          }

          $Result | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $script:PSStandardMembers
          $Result | Write-Output
        } Else {
          Throw "$CurrentPath`: Incorrectly formatted line: $Line"
        }
      }
    }
  }
}

Export-ModuleMember Out-HashFile
Export-ModuleMember Test-HashFile