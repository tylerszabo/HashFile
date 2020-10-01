#Requires -Version 6

# Copyright (C) 2020 Tyler Szabo
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program.  If not, see <http:#www.gnu.org/licenses/>.

if ((Get-Module Pester).Version -ge [version]'5.0') { throw "Pester 4.x is required." }

$here = (Split-Path -Parent $MyInvocation.MyCommand.Path)
Import-Module (Join-Path -Path $here -ChildPath "HashFile.psm1") -Force

$AsciiEncoder = New-Object System.Text.ASCIIEncoding
$UTF8Encoder = New-Object System.Text.UTF8Encoding

$dataSet = @(
  @{
    "Name" = "empty.dat"
    "NameUTF8" = $AsciiEncoder.GetBytes("empty.dat")
    "Input" = $null
    "SHA1" = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    "SHA256" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
  @{
    "Name" = "string.txt"
    "NameUTF8" = $AsciiEncoder.GetBytes("string.txt")
    "Input" = $AsciiEncoder.GetBytes("The quick brown fox jumped over the lazy dog")
    "SHA1" = "f6513640f3045e9768b239785625caa6a2588842"
    "SHA256" = "7d38b5cd25a2baf85ad3bb5b9311383e671a8a142eb302b324d4a5fba8748c69"
  }
  @{
    "Name" = "null.dat"
    "NameUTF8" = $AsciiEncoder.GetBytes("null.dat")
    "Input" = @([byte]0)
    "SHA1" = "5ba93c9db0cff93f52b521d7420e43f6eda2784f"
    "SHA256" = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
  }
  @{
    "Name" = ("" + [char]0x4e2d + [char]0x6587 + ".txt")
    "NameUTF8" = @([byte]0xe4, [byte]0xb8, [byte]0xad, [byte]0xe6, [byte]0x96, [byte]0x87) + $AsciiEncoder.GetBytes(".txt")
    "Input" = @([byte]0xff, [byte]0xfe, [byte]0x60, [byte]0x4f, [byte]0x7d, [byte]0x59)
    "SHA1" = "d80c7cfdaa53665217506b06a9929f687c9f6946"
    "SHA256" = "551f4acf3baee9c8110341d61b44638ef9621e731e35737820e26f38ceeba06c"
  }
)

function ComposeOutput {
  param( $Item, $Algorithm )
  return $UTF8Encoder.GetString($AsciiEncoder.GetBytes($Item[$Algorithm]) + [byte]0x20 + [byte]0x2a + $Item.NameUTF8 + [byte]0x0a)
}

function DoOutfile {
  param ( $Algorithm )

  Get-ChildItem "$TestDrive\" | Get-FileHash -Algorithm $Algorithm | Out-HashFile

  foreach ($item in $dataSet) {
    $hashfile = "$TestDrive\$($item.Name).$($Algorithm)sum"
    $hashfile | Should -Exist
    $data = $null
    $data = Get-Content -Path $hashfile -Encoding utf8 -Raw
    $expected = ComposeOutput -Item $item -Algorithm $Algorithm
    $data | Should -Be $expected
  }
}

function DoOutfileSingle {
  param ( $Algorithm )

  Get-ChildItem "$TestDrive\" | Get-FileHash -Algorithm $Algorithm | Out-HashFile -HashFile "$TestDrive\hashes"

  $hashfile = "$TestDrive\hashes"
  $hashfile | Should -Exist
  $data = $null
  $data = Get-Content -Path $hashfile -Encoding utf8 -Raw

  $expected = ""
  foreach ($item in $dataSet | Sort-Object { $_.Name }) {
    $expected += ComposeOutput -item $item -Algorithm $Algorithm
  }

  $data | Should -Be $expected
}

Describe "Out-HashFile" {
  BeforeAll {
    foreach ($item in $dataSet) {
      Set-Content -Path "$TestDrive\$($item.Name)" -Value $item.Input -AsByteStream
    }
  }

  It "Outputs individual SHA1 hashes" {
    DoOutfile -Algorithm "sha1"
  }

  It "Outputs individual SHA256 hashes" {
    DoOutfile -Algorithm "sha256"
  }

  It "Single hash file SHA1" {
    DoOutfileSingle -Algorithm "sha1"
  }

  It "Single hash file SHA256" {
    DoOutfileSingle -Algorithm "sha256"
  }

  AfterEach {
    Remove-Item "$TestDrive\*" -Include "*.*sum", "hashes"
  }
}

Describe "Test-HashFile" {
  BeforeAll {
    foreach ($item in $dataSet) {
      Set-Content -Path "$TestDrive\$($item.Name)" -Value $item.Input -AsByteStream

      $sha1data = (ComposeOutput -item $item -Algorithm "SHA1")
      $sha1data | Set-Content -Path "$TestDrive\$($item.Name).sha1sum" -Encoding UTF8NoBOM
      $sha1data | Add-Content -Path "$TestDrive\sha1files" -Encoding UTF8NoBOM

      $sha256data = (ComposeOutput -item $item -Algorithm "SHA256")
      $sha256data | Set-Content -Path "$TestDrive\$($item.Name).sha256sum" -Encoding UTF8NoBOM
      $sha256data | Add-Content -Path "$TestDrive\sha256files" -Encoding UTF8NoBOM
    }
  }

  It "Tests individual hashfiles (autodetect by filename)" {
    $results = Get-ChildItem "$TestDrive\" -Filter "*.*sum" | Test-HashFile
    $results | Should -HaveCount ($dataSet.Count * 2)
    $results | ForEach-Object { $_.Ok | Should -Be $true }
  }

  It "Tests multi-entry hashfiles (SHA1)" {
    $results = Test-HashFile -Path "$TestDrive\sha1files" -Algorithm SHA1
    $results | Should -HaveCount ($dataSet.Count)
    $results | ForEach-Object { $_.Ok | Should -Be $true }
  }

  It "Tests multi-entry hashfiles (SHA256)" {
    $results = Test-HashFile -Path "$TestDrive\sha256files" -Algorithm SHA256
    $results | Should -HaveCount ($dataSet.Count)
    $results | ForEach-Object { $_.Ok | Should -Be $true }
  }

  Context "input stream" {
    BeforeAll {
      $script:origLocation = Get-Location
      Set-Location "$TestDrive\"
    }

    AfterAll {
      $script:origLocation | Set-Location
    }

    It "Tests input stream (SHA1)" {
      $results = (Get-Content -Path "sha1files" -Encoding UTF8 -Raw) | Test-HashFile -Algorithm SHA1
      $results | Should -HaveCount ($dataSet.Count)
      $results | ForEach-Object { $_.Ok | Should -Be $true }
    }

    It "Tests input stream (SHA256)" {
      $results = (Get-Content -Path "sha256files" -Encoding UTF8 -Raw) | Test-HashFile -Algorithm SHA256
      $results | Should -HaveCount ($dataSet.Count)
      $results | ForEach-Object { $_.Ok | Should -Be $true }
    }
  }
}