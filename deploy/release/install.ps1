# Installs Splint's programs for this Windows user into %USERPROFILE%\.splint, with no administrator
# and nothing to build. It's install.sh for Windows, and decides what it installs the same way:
#
#   irm https://github.com/nennovate/splint/releases/latest/download/install.ps1 | iex
#
# Each release writes its version, its commit and the SHA-256 of every archive and every program into
# this script, so the script alone decides what it will install, wherever the archive came from. With
# cosign 3 or later on the machine, it also checks that the archive was signed by this repository's
# release workflow for this tag, run on that commit. Any mismatch refuses, and leaves
# %USERPROFILE%\.splint as it was.
#
# SPLINT_FROM_DIR=DIR installs from a release's files already downloaded into DIR, checked the same way.
#
# For a person setting up their controls, `controls HOST` installs the same way, then opens their
# controls on this computer, with `splint controls HOST` and anything after it:
#
#   & ([scriptblock]::Create((irm https://github.com/nennovate/splint/releases/latest/download/install.ps1))) controls HOST
#
# With --verify it installs nothing, and checks the programs in %USERPROFILE%\.splint\bin are byte for
# byte this release's, running none of them.
#
# Windows has no host build: a host runs on Linux.
#
# All of it is one script block, run on the last line. `irm | iex` runs a script in the person's own
# PowerShell, which this leaves as it was, with none of these settings or functions left in it. A
# download cut short has no closing brace, so it runs nothing.

& {
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$Repo = 'nennovate/splint'
$Version = '@VERSION@'
$Commit = '@COMMIT@'
$Sums = @'
@SUMS@
'@
$Programs = @('splint', 'splint-signet', 'splint-owner-key')
$Issuer = 'https://token.actions.githubusercontent.com'

function Say([string]$Text) { [Console]::Error.WriteLine($Text) }

function Refuse([string]$Why) {
    throw "splint install: $Why. Nothing was installed."
}

# Runs a program and drops what it says on stderr, so its exit code alone says how it went. Windows
# PowerShell 5.1 makes each stderr line of a program whose stderr is redirected an error, which 'Stop'
# would make fatal, though cosign says there that it checked a signature. What it prints comes back.
# A program that never ran, such as one gone since it was found, would leave the exit code of the
# last that did, so it counts as failed until one says otherwise.
function Quietly([scriptblock]$Run) {
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = -1
    try { & $Run 2>$null } catch { $global:LASTEXITCODE = -1 }
}

# The checksum this script holds for a file in the release, or nothing.
function Listed([string]$Name) {
    foreach ($line in $Sums -split "`n") {
        $fields = $line.Trim() -split '\s+'
        if ($fields.Count -eq 2 -and $fields[1] -ceq $Name) { return $fields[0] }
    }
    return $null
}

function Sha256Of([string]$Path) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

# Only this user, the way splint makes its own folders: no entry inherited from the folder above.
function Make-Private([string]$Path) {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $Path /inheritance:r /grant:r "*${me}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { Refuse "couldn't make $Path readable by you alone" }
}

# Older cosign can't read the bundle format a release is signed in.
function Cosign-CanCheck {
    if (-not (Get-Command cosign -ErrorAction SilentlyContinue)) { return $false }
    $said = Quietly { & cosign version } | Select-String '^GitVersion:\s*v?(\d+)'
    return $null -ne $said -and [int]$said.Matches[0].Groups[1].Value -ge 3
}

# From SPLINT_FROM_DIR, or the release, or with gh while the repository is private.
function Fetch([string]$Name, [string]$Work) {
    $to = Join-Path $Work $Name
    if ($env:SPLINT_FROM_DIR) {
        $from = Join-Path $env:SPLINT_FROM_DIR $Name
        if (-not (Test-Path -LiteralPath $from -PathType Leaf)) { return $false }
        Copy-Item -LiteralPath $from -Destination $to
        return $true
    }
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/$Repo/releases/download/$Version/$Name" -OutFile $to
        return $true
    } catch {
        if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { return $false }
        Quietly { & gh release download $Version --repo $Repo --pattern $Name --dir $Work --clobber } | Out-Null
        return $LASTEXITCODE -eq 0
    }
}

function Platform {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        'X64' { return 'windows-x86_64' }
        'Arm64' { return 'windows-arm64' }
        default { Refuse "there's no build for Windows on $arch" }
    }
}

# Where splint looks, in the profile folder rather than AppData: Windows sends what a packaged app,
# such as a Store app this runs in, writes under AppData to the app's own folder, out of sight of
# everything else and deleted with the app. A roaming profile copies this folder, keys and all, to
# each PC its user logs in to, which AppData\Local it doesn't, and nothing yet warns of one.
function SplintHome {
    if (-not $env:USERPROFILE) { Refuse "USERPROFILE isn't set" }
    return Join-Path $env:USERPROFILE '.splint'
}

# Checks what's installed against this release, by this script's own lists alone.
function Verify([string]$Platform) {
    $bin = Join-Path (SplintHome) 'bin'
    $differ = $false
    foreach ($program in $Programs) {
        $want = Listed "splint-$Version-$Platform/bin/$program.exe"
        if (-not $want) { Refuse "this release lists no $program for $Platform" }
        $path = Join-Path $bin "$program.exe"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Say "${program}: not installed in $bin"
            $differ = $true
        } elseif ((Sha256Of $path) -eq $want) {
            Say "${program}: the same as $Version for $Platform"
        } else {
            Say "${program}: NOT the same as $Version for $Platform"
            $differ = $true
        }
    }
    if ($differ) {
        throw "install.ps1 --verify: what's installed isn't $Version. Reinstall it, and find out what changed it."
    }
}

function Install-Splint([string[]]$Words) {
    if ($Version -notmatch '^v[0-9]') { Refuse "this is the template in the repository, not a release's install.ps1" }
    $verifying = $false
    $controls = $false
    $rest = @()
    if ($Words.Count -gt 0) {
        switch -CaseSensitive ($Words[0]) {
            '--verify' { $verifying = $true }
            'controls' {
                if ($Words.Count -lt 2 -or -not $Words[1]) {
                    Refuse "controls needs the host that keeps your list, such as: controls splint.example"
                }
                $controls = $true
                $rest = $Words[1..($Words.Count - 1)]
            }
            default { Refuse "the options are --verify, and controls HOST" }
        }
    }
    $platform = Platform
    if ($verifying) {
        Verify $platform
        return
    }

    $archive = "splint-$Version-$platform.tar.gz"
    $want = Listed $archive
    if (-not $want) { Refuse "this release has no checksum for $archive" }

    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("splint-install-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        if (-not (Fetch $archive $work)) { Refuse "couldn't download $archive from github.com/$Repo for $Version" }
        $downloaded = Join-Path $work $archive
        if ((Sha256Of $downloaded) -ne $want) { Refuse "$archive doesn't match the checksum $Version was released with" }

        if (Cosign-CanCheck) {
            if (-not (Fetch "$archive.sigstore.json" $work)) { Refuse "couldn't download $archive.sigstore.json" }
            $signer = "https://github.com/$Repo/.github/workflows/release.yml@refs/tags/$Version"
            Quietly {
                & cosign verify-blob --bundle "$downloaded.sigstore.json" --certificate-identity $signer `
                    --certificate-oidc-issuer $Issuer --certificate-github-workflow-repository $Repo `
                    --certificate-github-workflow-sha $Commit $downloaded
            } | Out-Null
            if ($LASTEXITCODE -ne 0) { Refuse "$archive isn't signed by $Repo's release workflow for $Version on $Commit" }
            $checked = 'its checksum and its signature'
        } else {
            $checked = "its checksum. There's no cosign 3 here, so its signature wasn't checked"
        }

        # Windows's own tar, there since Windows 10 1803, so nothing else is needed to unpack it.
        $open = Join-Path $work 'open'
        New-Item -ItemType Directory -Path $open | Out-Null
        & "$env:SystemRoot\System32\tar.exe" -xzf $downloaded -C $open
        if ($LASTEXITCODE -ne 0) { Refuse "$archive wouldn't unpack" }
        $found = Join-Path $open "splint-$Version-$platform"
        foreach ($program in $Programs) {
            $path = Join-Path $found "bin\$program.exe"
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Refuse "$archive has no $program" }
            # The archive's checksum covers these too, and this costs nothing.
            if ((Sha256Of $path) -ne (Listed "splint-$Version-$platform/bin/$program.exe")) {
                Refuse "$program in $archive doesn't match the checksum $Version was released with"
            }
        }
        foreach ($folder in @('examples', 'adapters')) {
            if (-not (Test-Path -LiteralPath (Join-Path $found $folder) -PathType Container)) {
                Refuse "$archive is missing what the programs read"
            }
        }

        $splintDir = SplintHome
        $bin = Join-Path $splintDir 'bin'
        New-Item -ItemType Directory -Force -Path $bin | Out-Null
        Make-Private $splintDir
        # A running program can't be written over on Windows, but it can be renamed, so each one moves
        # aside and the new one takes its name. What's running keeps going on the old file.
        foreach ($program in $Programs) {
            $target = Join-Path $bin "$program.exe"
            $new = Join-Path $bin ".$program.exe.new"
            $old = Join-Path $bin ".$program.exe.old"
            Copy-Item -LiteralPath (Join-Path $found "bin\$program.exe") -Destination $new -Force
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $target) { Move-Item -LiteralPath $target -Destination $old -Force }
            Move-Item -LiteralPath $new -Destination $target -Force
            # Gone now if nothing runs it, and next time if something does.
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
        }
        # A schemas folder an older release installed held types Signet ran; now nothing reads it.
        $schemas = Join-Path $splintDir 'schemas'
        if (Test-Path -LiteralPath $schemas) { Remove-Item -LiteralPath $schemas -Recurse -Force }
        foreach ($folder in @('examples', 'adapters')) {
            $new = Join-Path $splintDir ".$folder.new"
            if (Test-Path -LiteralPath $new) { Remove-Item -LiteralPath $new -Recurse -Force }
            Copy-Item -LiteralPath (Join-Path $found $folder) -Destination $new -Recurse
            $place = Join-Path $splintDir $folder
            if (Test-Path -LiteralPath $place) { Remove-Item -LiteralPath $place -Recurse -Force }
            Move-Item -LiteralPath $new -Destination $place
        }
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }

    # What was running keeps running the build this replaced until it's started again, still signing.
    # So each agent here that's running now is started again, which runs this build in its place, as
    # install.sh does: splint decides that by the lock a running copy holds.
    $splint = Join-Path $bin 'splint.exe'
    $folders = @($splintDir) + @(Get-ChildItem -LiteralPath (Join-Path $splintDir 'profiles') -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath (Join-Path $folder 'run') -PathType Container)) { continue }
        if ($folder -eq $splintDir) {
            $said = Quietly { & $splint start --if-running }
        } else {
            $said = Quietly { & $splint --as (Split-Path -Leaf $folder) start --if-running }
        }
        if ($LASTEXITCODE -ne 0) {
            Say "Couldn't start what runs for $folder again: splint status there says why, and splint start runs $Version."
        } elseif ($said) {
            Say "Started what runs for $folder again, so it runs $Version."
        }
    }

    Say "Installed Splint $Version for $platform into $bin, after checking $checked."
    Say "splint verify, or this script with --verify, checks them again later."
    Say "Wherever a step says splint, run $splint"
    # Not `exit`, which would close the person's own PowerShell window, as this runs inside it.
    if ($controls) { & $splint controls @rest }
}

Install-Splint $args
} @args
