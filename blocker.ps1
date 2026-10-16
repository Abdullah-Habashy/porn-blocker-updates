<#
Porn site blocker (PowerShell edition, no Python needed) - forces a family-filtering
Private DNS and reports to an accountability partner on Telegram.

Fail-open: after every DNS change, name resolution is tested. If it fails, DNS goes
back to automatic so the internet never stays down because of this program.

The hosts-file blocklists (LIST_URLS) are kept but OFF by default: ~240k domains in
hosts makes the Windows DNS Client hang and took the internet down (5 Oct 2026).
Use -HostsMode only if you accept that risk.

Usage (asks for admin rights automatically):
    blocker.ps1                               install (DNS only)
    blocker.ps1 -Partner @name                install and link that Telegram user as partner
                                              (without it, the installer asks for the username)
    blocker.ps1 -ChatId Y [-BotToken X]       link a partner by chat id (and/or another bot)
    blocker.ps1 -HostsMode                    install with the hosts blocklists too (risky)
    blocker.ps1 -NoScreenshots                install without offering screenshot monitoring
    blocker.ps1 -Check                        periodic check (run by the scheduled task)
    blocker.ps1 -Remove                       remove everything (partner is notified)

Screenshot accountability (optional, off unless the user agrees at install): captured in the
interactive session and sent to the partner on Telegram every 30-300s, with a visible notice
each sign-in. -ScreenshotLoop and -FlushShots are internal, run by the scheduled tasks.
#>
param(
    [switch]$Check,
    [switch]$Remove,
    [switch]$HostsMode,
    [switch]$NoLockApps,
    [string]$Partner = "",
    [string]$BotToken = "",
    [string]$ChatId = "",
    [switch]$Elevated,       # set on the self-elevated relaunch, so a failed elevation stops instead of looping
    [switch]$NoScreenshots,  # install without offering the screenshot feature
    [int]$ShotMinSeconds = 0,# random interval bounds (0 = keep what config has, else the default)
    [int]$ShotMaxSeconds = 0,# e.g. -ShotMinSeconds 30 -ShotMaxSeconds 300
    [switch]$ScreenshotLoop, # internal: the per-user capture loop (runs in the interactive session)
    [switch]$FlushShots      # internal: SYSTEM sends and deletes the spooled screenshots
)

# Auto-update: every check downloads update.json (blocker.ps1 + its signature) from the public updates repo and
# installs it only if the RSA signature matches this key and the version is newer.
# publish.ps1 bumps this version and signs with the private key, which never leaves the publisher's PC.
$ScriptVersion = 202610160322
$UpdateBaseUrl = 'https://raw.githubusercontent.com/Abdullah-Habashy/porn-blocker-updates/main'
$UpdatePublicKey = '<RSAKeyValue><Modulus>1oBFE+xZMQ+A+c1a1SDzdZ6OikvOyNgzppMkdHkIPjbXRog/t9LCd+6AR31CdRGJbqycDAgtOROiyG+mTFiYZ/L64rySUvEPRiQIMzKCgfXT3hU5t1lE+8IWmL7MlkapsXvJhHcXLBV4yn3g3pDTlTN/7eFemM9c/tE4XF164DjtNAhUPN7XharGNnz3dr2j4Atcc1g2pJsl4HN3U01g9eMGSOtwxjia6bbgqu1PxvQn6nzDqFveOfimU9iQJPjCHyHlJq82XUBLkxhPHXgHFptVd6Sm6Rq96n7eU1eutEmDBcaW8TGj1M5lYY9/b5yevsg/hz+MsnUROHDPQo/zowEiUM3s7pOygEeVKYxgHHi6D8CqO8ooDNx4BhaugVme5MSvdudPenB4uuSZUwJx+sEhMgyJIo3zThqCBW5ONjilCD63RztnXEwTWqrugUSr+eLoI8U46GcOpvxiwmKiWAm5n6Gl/Inp2K+wU36nfZOB3Vg1l1/sEd7C+AldSpsJ</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'

# The Telegram bot token is not kept in this script: the installer reads it from bot_token.txt
# next to the script (or -BotToken) and saves it in the locked config.json
$TokenFileName = 'bot_token.txt'

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Blocklist sources for -HostsMode - JSON (like sites.json) or plain text (one domain per line or hosts format)
$ListUrls = @(
    'https://raw.githubusercontent.com/zhongyang/porn-site-list/master/sites.json',
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt',
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts',
    'https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts'
)

# Private DNS: Cloudflare for Families (blocks malware + adult content)
$DnsV4 = @('1.1.1.3', '1.0.0.3')
$DnsV6 = @('2606:4700:4700::1113', '2606:4700:4700::1003')
$DohTemplate = 'https://family.cloudflare-dns.com/dns-query'

# Names used to prove the internet still works after a DNS change.
# None of them may be in the SafeSearch hosts section - hosts would answer even with DNS broken.
$ProbeNames = @('www.microsoft.com', 'www.cloudflare.com', 'www.wikipedia.org')

# Browser policies: keep Secure DNS on, but locked to the family-filtering provider
$BrowserPolicies = @(
    @('HKLM:\SOFTWARE\Policies\Google\Chrome', 'DnsOverHttpsMode', 'secure', 'String'),
    @('HKLM:\SOFTWARE\Policies\Google\Chrome', 'DnsOverHttpsTemplates', $DohTemplate, 'String'),
    @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'DnsOverHttpsMode', 'secure', 'String'),
    @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'DnsOverHttpsTemplates', $DohTemplate, 'String'),
    @('HKLM:\SOFTWARE\Policies\BraveSoftware\Brave', 'DnsOverHttpsMode', 'secure', 'String'),
    @('HKLM:\SOFTWARE\Policies\BraveSoftware\Brave', 'DnsOverHttpsTemplates', $DohTemplate, 'String'),
    @('HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS', 'Enabled', 1, 'DWord'),
    @('HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS', 'ProviderURL', $DohTemplate, 'String'),
    @('HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS', 'Locked', 1, 'DWord')
)

# Browser policies that stay on even when DNS fails open: SafeSearch,
# no proxy (so proxy-based "VPN" extensions stop working), and Brave's built-in Tor and VPN off.
# Edge Secure Network (its built-in VPN) has no policy - Edge turns it off once any policy is set.
$NoProxy = '{"ProxyMode": "direct"}'
$GuardPolicies = @(
    @('HKLM:\SOFTWARE\Policies\Google\Chrome', 'ForceGoogleSafeSearch', 1, 'DWord'),
    @('HKLM:\SOFTWARE\Policies\Google\Chrome', 'ProxySettings', $NoProxy, 'String'),
    @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'ForceGoogleSafeSearch', 1, 'DWord'),
    @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'ForceBingSafeSearch', 2, 'DWord'),
    @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'ProxySettings', $NoProxy, 'String'),
    @('HKLM:\SOFTWARE\Policies\BraveSoftware\Brave', 'ForceGoogleSafeSearch', 1, 'DWord'),
    @('HKLM:\SOFTWARE\Policies\BraveSoftware\Brave', 'ProxySettings', $NoProxy, 'String'),
    @('HKLM:\SOFTWARE\Policies\BraveSoftware\Brave', 'TorDisabled', 1, 'DWord'),
    @('HKLM:\SOFTWARE\Policies\BraveSoftware\Brave', 'BraveVPNDisabled', 1, 'DWord'),
    @('HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Proxy', 'Mode', 'none', 'String'),
    @('HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Proxy', 'Locked', 1, 'DWord'),
    # ForceYouTubeRestrict used to be here. YouTube's Restricted Mode hides the
    # comments of every video at both levels, which made YouTube unreadable, so
    # it was dropped on 13 October 2026. SafeSearch, the host block, the DNS
    # filter and the rest are untouched. See $RetiredPolicies below: installed
    # copies clear the leftover value on their next run.
    # No incognito / InPrivate / private windows (1 = disabled), so the history stays visible
    @('HKLM:\SOFTWARE\Policies\Google\Chrome', 'IncognitoModeAvailability', 1, 'DWord'),
    @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'InPrivateModeAvailability', 1, 'DWord'),
    @('HKLM:\SOFTWARE\Policies\BraveSoftware\Brave', 'IncognitoModeAvailability', 1, 'DWord'),
    @('HKLM:\SOFTWARE\Policies\Mozilla\Firefox', 'DisablePrivateBrowsing', 1, 'DWord')
)

# Values an older version used to set and this one does not. Every run deletes them, so an
# existing install drops them on its next check instead of carrying them for ever.
$RetiredPolicies = @(
    @('HKLM:\SOFTWARE\Policies\Google\Chrome', 'ForceYouTubeRestrict'),
    @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'ForceYouTubeRestrict'),
    @('HKLM:\SOFTWARE\Policies\BraveSoftware\Brave', 'ForceYouTubeRestrict')
)

# SafeSearch for every browser, including Firefox and Opera that have no policy for it: hosts
# points the search / YouTube names at the providers' own SafeSearch addresses. The addresses
# are looked up fresh on every check; the fallback IP is used only when the lookup fails.
$SsBegin = '# >>> porn-blocker safesearch BEGIN'
$SsEnd = '# <<< porn-blocker safesearch END'
$SafeSearchMap = @(
    @('forcesafesearch.google.com', '216.239.38.120', @('google.com', 'www.google.com',
        'google.com.eg', 'www.google.com.eg', 'google.com.sa', 'www.google.com.sa', 'google.ae', 'www.google.ae')),
    # The YouTube line pointed www.youtube.com at restrict.youtube.com, which forces Restricted
    # Mode for every browser at the network level - the same feature as the ForceYouTubeRestrict
    # policy, enforced a second way. Both were dropped on 13 October 2026 because Restricted Mode
    # hides the comments of every video. Google SafeSearch and Bing below are untouched, and the
    # next run rewrites the hosts block without the YouTube names.
    @('strict.bing.com', '150.171.27.16', @('bing.com', 'www.bing.com')),
    @('safe.duckduckgo.com', $null, @('duckduckgo.com', 'www.duckduckgo.com'))
)

# Firewall: plain DNS / DNS-over-TLS (53, 853) may only go to the family servers, so no program
# can ask another resolver directly. Written as "everything except" ranges because a Windows
# block rule always beats an allow rule.
$FwGroup = 'PornBlocker'
$FwDnsRule = 'PornBlocker-DNS'
$FwDohRule = 'PornBlocker-DoH'
$NonFamilyRanges = @(
    '0.0.0.0-1.0.0.2', '1.0.0.4-1.1.1.2', '1.1.1.4-255.255.255.255',
    '::-2606:4700:4700::1002', '2606:4700:4700::1004-2606:4700:4700::1112',
    '2606:4700:4700::1114-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
)
# Public DoH / DoT resolvers, blocked on 443 and 853 only (ping to 8.8.8.8 keeps working),
# so a browser without our policies can't switch its Secure DNS to one of them
$DohResolverIps = @(
    '8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844',
    '1.1.1.1', '1.0.0.1', '1.1.1.2', '1.0.0.2',
    '2606:4700:4700::1111', '2606:4700:4700::1001', '2606:4700:4700::1112', '2606:4700:4700::1002',
    '9.9.9.9', '149.112.112.112', '9.9.9.10', '149.112.112.10', '9.9.9.11', '149.112.112.11',
    '2620:fe::fe', '2620:fe::9', '2620:fe::10', '2620:fe::11',
    '208.67.222.222', '208.67.220.220', '208.67.222.123', '208.67.220.123',
    '94.140.14.14', '94.140.15.15', '94.140.14.140', '94.140.14.141', '94.140.14.15', '94.140.15.16',
    '45.90.28.0/24', '45.90.30.0/24', '76.76.2.0/24', '76.76.10.0/24',
    '194.242.2.0/24', '185.228.168.0/24', '185.228.169.0/24', '185.222.222.222', '45.11.45.11'
)

# Domains the family filter must block; if one resolves to a real address, DNS is being intercepted
$ProbeBlocked = @('pornhub.com', 'xvideos.com')

# App lock (on unless installed with -NoLockApps): Software Restriction Policies for standard users (administrators are excluded).
# Programs run only from Windows and Program Files, so portable browsers / Tor / VPNs can't start.
$SaferKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
# LNK and URL are left out on purpose - they would block every shortcut on the desktop
$SaferTypes = @('ADE', 'ADP', 'BAS', 'BAT', 'CHM', 'CMD', 'COM', 'CPL', 'CRT', 'EXE', 'HLP', 'HTA',
    'INF', 'INS', 'ISP', 'MDB', 'MDE', 'MSC', 'MSI', 'MSP', 'MST', 'OCX', 'PCD', 'PIF', 'REG', 'SCR',
    'SHS', 'VB', 'WSC')
$SaferAllow = @(
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d01}', $env:SystemRoot, 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d02}', $env:ProgramFiles, 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d03}', ${env:ProgramFiles(x86)}, 'String'),
    # per-user, expanded for each user at run time
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d04}', '%LOCALAPPDATA%\Microsoft\OneDrive', 'ExpandString'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d05}', '%LOCALAPPDATA%\Microsoft\WindowsApps', 'ExpandString')
)
# Folders inside Windows that standard users can write to - closed again
$SaferDeny = @(
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d11}', (Join-Path $env:SystemRoot 'Temp'), 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d12}', (Join-Path $env:SystemRoot 'Tasks'), 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d13}', (Join-Path $env:SystemRoot 'tracing'), 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d14}', (Join-Path $env:SystemRoot 'System32\Tasks'), 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d15}', (Join-Path $env:SystemRoot 'System32\spool\drivers\color'), 'String'),
    # Browsers with a built-in VPN or no policies we set (Opera, Vivaldi, Yandex, UC), and Tor/Psiphon,
    # blocked by file name wherever they are installed - even by an admin into Program Files
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d21}', 'opera.exe', 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d22}', 'vivaldi.exe', 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d23}', 'browser.exe', 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d24}', 'UCBrowser.exe', 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d25}', 'tor.exe', 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d26}', 'psiphon3.exe', 'String'),
    # Gecko browsers, blocked for a different reason than the ones above: Content Guard is a
    # Chromium extension, and ExtensionInstallForcelist exists only for Chrome, Edge and Brave.
    # Firefox would need its own add-on, signed by Mozilla. So on Firefox the whole keyword
    # filter and the YouTube allow list are simply absent - DNS, SafeSearch and private windows
    # are locked there, and nothing reads the text of a page. A browser that is 90% covered is
    # the one the user ends up in, so the family does not run for standard users at all.
    #
    # Tor Browser's own binary is firefox.exe, not tor.exe: the tor.exe rule above blocks the
    # daemon, this one blocks the browser.
    #
    # The Firefox policies elsewhere in this script stay: administrators are exempt from the
    # app lock, so an admin's Firefox is still locked down as far as policy can do it.
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d27}', 'firefox.exe', 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d28}', 'librewolf.exe', 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d29}', 'waterfox.exe', 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d2a}', 'palemoon.exe', 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d2b}', 'basilisk.exe', 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d2c}', 'mullvadbrowser.exe', 'String'),
    @('{8d3a3c0e-5b1f-4f6c-9a1e-0b6c2f1a7d2d}', 'seamonkey.exe', 'String')
)
# Store / packaged apps run from Program Files\WindowsApps, which the path rules allow, so standard
# users may not install them at all (an admin still can, from an elevated context)
# Leading comma: a single-element @( @(...) ) is flattened by PowerShell into a 4-field
# scalar array, which Set-Policies would then iterate field by field. The comma keeps it
# as one entry so BlockNonAdminUserInstall is actually written.
$AppLockPolicies = @(
    , @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx', 'BlockNonAdminUserInstall', 1, 'DWord')
)

# Content Guard: the browser extension that reads the ADDRESS AND THE TEXT of every page and
# takes the page away when it matches keywords.txt. It is the only layer that can block an
# article about the subject sitting on an ordinary domain - DNS sees host names, hosts needs
# exact names, and Chromium's URLBlocklist has no substring matching at all (*xample.com is
# not even a valid pattern), so no other layer here can see a word inside a page.
#
# Force-installed through policy, which is also what stops the monitored user switching it
# off: Chrome, Edge and Brave all refuse to let anyone remove a force-installed extension.
#
# The ID is derived from the signing key in %USERPROFILE%\.porn-blocker\extension_key.pem and
# is printed by build-extension.ps1. A new key means a new ID, and then this policy silently
# installs nothing - which is why that key must be backed up and never regenerated.
$ExtensionId = 'hfdidmojdonclaiggdckfiijfannodbb'
$ExtensionUpdateUrl = 'https://raw.githubusercontent.com/Abdullah-Habashy/porn-blocker-updates/main/content-guard-updates.xml'
# Each vendor keeps its forcelist as numbered string values under its own key, so the value
# name is '1' rather than the single named value the other policies use.
$ExtensionForcelistKeys = @(
    'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist',
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist',
    'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist'
)

$HostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$InstallDir = Join-Path $env:ProgramData 'PornBlocker'
$InstalledScript = Join-Path $InstallDir 'blocker.ps1'
$ConfigFile = Join-Path $InstallDir 'config.json'
$StateFile = Join-Path $InstallDir 'state.json'
$LogFile = Join-Path $InstallDir 'blocker.log'
$BackupFile = Join-Path $InstallDir 'block_backup.txt'
$TaskName = 'PornSiteBlocker'
$Begin = '# >>> porn-site-blocker BEGIN'
$End = '# <<< porn-site-blocker END'
$DomainsPerLine = 9
$Skip = @('localhost', 'localhost.localdomain', 'local', 'broadcasthost', '0.0.0.0', 'ip6-localhost')
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

# Screenshot accountability (opt-in, with the user's consent at install). Captured in the
# interactive session - SYSTEM can't see the desktop - to a spool folder; SYSTEM then sends each
# shot to the partner and deletes it, so the bot token never has to be readable from the user's
# session. The spool grants standard users WRITE ONLY (no read, no delete): they can't peek at or
# delete shots before they are sent, but the token is not here anyway.
$ShotSpool       = Join-Path $env:ProgramData 'PBShots'
$ShotTaskCapture = "$TaskName-Shots"
$ShotTaskFlush   = "$TaskName-Flush"
$ShotMinDefault  = 30
$ShotMaxDefault  = 300
$ShotMaxAgeHours = 6     # SYSTEM drops unsent shots older than this (privacy + disk)


# ---------- helpers ----------

function Write-Log([string]$Message) {
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    try {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch {}
}

function Read-JsonFile([string]$Path) {
    $h = @{}
    if (Test-Path $Path) {
        try {
            $o = Get-Content -Path $Path -Raw | ConvertFrom-Json
            $o.PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value }
        } catch {}
    }
    return $h
}

function Save-JsonFile([string]$Path, [hashtable]$Data) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $Data | ConvertTo-Json | Set-Content -Path $Path -Encoding UTF8
}

function Get-Today { (Get-Date).ToString('yyyy-MM-dd') }

function Protect-InstallDir {
    # ProgramData lets every user create files in subfolders and read them, and this folder
    # holds the bot token and a script SYSTEM runs - so only SYSTEM and Administrators get access.
    # SIDs, not names, so it works on any Windows language.
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    try {
        # 'Continue' because icacls stderr under 'Stop' would throw before the exit code is read
        $ErrorActionPreference = 'Continue'
        $out = icacls $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C /Q 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Log "Locking $InstallDir failed (icacls exit $LASTEXITCODE): $out" }
    } catch {
        Write-Log "Locking $InstallDir failed: $($_.Exception.Message)"
    }
}


# ---------- Telegram ----------

function Send-Partner([string]$Text) {
    $cfg = Read-JsonFile $ConfigFile
    if (-not $cfg.bot_token -or -not $cfg.chat_id) { return $false }
    $device = if ($cfg.device_name) { $cfg.device_name } else { $env:COMPUTERNAME }
    try {
        Invoke-RestMethod -Method Post -Uri "https://api.telegram.org/bot$($cfg.bot_token)/sendMessage" `
            -Body @{ chat_id = $cfg.chat_id; text = "[$device]`n$Text" } -TimeoutSec 30 | Out-Null
        return $true
    } catch {
        Write-Log "Telegram send failed: $($_.Exception.Message)"
        return $false
    }
}

function Find-PartnerChat([string]$Token, [string]$Username) {
    # Looks for a private message to the bot from @Username. No offset is sent, so updates
    # are never confirmed and other installs pairing at the same time still see theirs.
    try {
        $updates = (Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates" -TimeoutSec 30).result
    } catch {
        return $null
    }
    foreach ($u in @($updates)) {
        $m = $u.message
        if ($m -and $m.chat.type -eq 'private' -and $m.from.username -and
            $m.from.username.ToLowerInvariant() -eq $Username) {
            return $m.chat
        }
    }
    return $null
}

function Connect-Partner([hashtable]$Cfg) {
    # Asks for the partner's Telegram username and waits for them to press Start on the bot.
    $token = $Cfg.bot_token
    $answer = $Partner
    if (-not $answer) {
        Write-Host ''
        Write-Host '=== Accountability partner (Telegram) ==='
        $answer = Read-Host "Partner's Telegram username (e.g. @name), or press Enter to skip"
    }
    $username = ($answer.Trim() -replace '^(https?://)?(t\.me/|telegram\.me/)', '').TrimStart('@').ToLowerInvariant()
    if (-not $username) {
        Write-Log 'No partner given - blocking without monitoring.'
        return
    }
    try {
        $bot = (Invoke-RestMethod -Uri "https://api.telegram.org/bot$token/getMe" -TimeoutSec 30).result.username
    } catch {
        Write-Log "Telegram unreachable: $($_.Exception.Message) - blocking without monitoring."
        return
    }
    Write-Host ''
    Write-Host "Send this link to @$username and ask them to press START:"
    Write-Host "    https://t.me/$bot" -ForegroundColor Cyan
    Write-Host '(If they already started the bot before, they just send it any message.)'
    Write-Host 'Waiting up to 10 minutes... press Ctrl+C to skip.'
    $deadline = (Get-Date).AddMinutes(10)
    while ((Get-Date) -lt $deadline) {
        $chat = Find-PartnerChat $token $username
        if ($chat) {
            $Cfg.chat_id = [string]$chat.id
            $Cfg.partner = $username
            Save-JsonFile $ConfigFile $Cfg
            Write-Log "Partner linked: @$username"
            Send-Partner ("You are now the accountability partner for this device (Windows user: $env:USERNAME).`n" +
                'You will get a message every day. If a day passes with no message, the blocker was removed or stopped.') | Out-Null
            return
        }
        Start-Sleep -Seconds 3
    }
    Write-Log "Partner @$username did not press Start in time - blocking without monitoring. Run the installer again to link."
}

function Set-PartnerConfig {
    $cfg = Read-JsonFile $ConfigFile
    # -BotToken, else bot_token.txt next to this script, else the token saved by an earlier install
    $tokenFile = Join-Path (Split-Path -Parent $PSCommandPath) $TokenFileName
    if ($BotToken) { $cfg.bot_token = $BotToken }
    elseif (Test-Path $tokenFile) { $cfg.bot_token = ([IO.File]::ReadAllText($tokenFile)).Trim() }
    if (-not $cfg.device_name) { $cfg.device_name = $env:COMPUTERNAME }
    $cfg.hosts_mode = [bool]$HostsMode
    Save-JsonFile $ConfigFile $cfg
    if (-not $cfg.bot_token) {
        Write-Log "No Telegram bot token: $tokenFile does not exist and -BotToken was not given. Blocking works, but without partner monitoring - put $TokenFileName next to blocker.ps1 and run the installer again."
        return
    }
    if ($ChatId) {
        $cfg.chat_id = $ChatId
        Save-JsonFile $ConfigFile $cfg
    } elseif ($Partner -or -not $cfg.chat_id) {
        # Reinstalling keeps the existing partner unless a new one is given with -Partner
        Connect-Partner $cfg
    } else {
        Write-Log "Keeping existing partner @$($cfg.partner)."
    }
}


# ---------- Private DNS (fail-open) ----------

function Test-NameResolution {
    # Goes through the system resolver, with a hard timeout per name so it can never hang
    try { Clear-DnsClientCache } catch {}
    foreach ($name in $ProbeNames) {
        try {
            $task = [System.Net.Dns]::GetHostAddressesAsync($name)
            if ($task.Wait(5000) -and $task.Result.Count -gt 0) { return $true }
        } catch {}
    }
    return $false
}

function Test-NetworkUp {
    # Connected adapter with a default route - checked without DNS, so a broken DNS can't fake "offline"
    $up = @(Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object ifIndex)
    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction SilentlyContinue |
        Where-Object { $up -contains $_.ifIndex })
    return $routes.Count -gt 0
}

function Test-FilterActive {
    # $false when a domain the family filter blocks resolves to a real address (DNS intercepted)
    try { Clear-DnsClientCache } catch {}
    foreach ($name in $ProbeBlocked) {
        try {
            $task = [System.Net.Dns]::GetHostAddressesAsync($name)
            if (-not $task.Wait(5000)) { continue }
            foreach ($ip in $task.Result) {
                if ($ip.ToString() -notin @('0.0.0.0', '::')) { return $false }
            }
        } catch {}
    }
    return $true
}

function Set-Policies([object[]]$List) {
    foreach ($p in $List) {
        try {
            if (-not (Test-Path $p[0])) { New-Item -Path $p[0] -Force | Out-Null }
            New-ItemProperty -Path $p[0] -Name $p[1] -Value $p[2] -PropertyType $p[3] -Force | Out-Null
        } catch {
            Write-Log "Policy $($p[0])\$($p[1]) failed: $($_.Exception.Message)"
        }
    }
}

function Remove-Policies([object[]]$List) {
    foreach ($p in $List) {
        Remove-ItemProperty -Path $p[0] -Name $p[1] -ErrorAction SilentlyContinue
    }
}

function Set-FirewallRules([bool]$BlockDns) {
    # Recreated each time so a deleted or edited rule comes back as written here
    try {
        Remove-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue
        $dnsEnabled = if ($BlockDns) { 'True' } else { 'False' }
        foreach ($proto in @('TCP', 'UDP')) {
            New-NetFirewallRule -Name "$FwDnsRule-$proto" -DisplayName "$FwDnsRule-$proto" -Group $FwGroup `
                -Direction Outbound -Action Block -Protocol $proto -RemotePort 53, 853 `
                -RemoteAddress $NonFamilyRanges -Enabled $dnsEnabled | Out-Null
            New-NetFirewallRule -Name "$FwDohRule-$proto" -DisplayName "$FwDohRule-$proto" -Group $FwGroup `
                -Direction Outbound -Action Block -Protocol $proto -RemotePort 443, 853 `
                -RemoteAddress $DohResolverIps | Out-Null
        }
    } catch {
        Write-Log "Firewall rules failed: $($_.Exception.Message)"
    }
}

function Disable-DnsFirewallRule {
    # Fail-open: automatic DNS (the router) must be reachable on port 53
    foreach ($proto in @('TCP', 'UDP')) {
        Disable-NetFirewallRule -Name "$FwDnsRule-$proto" -ErrorAction SilentlyContinue
    }
}

function Set-ContentGuard {
    # Writes the forcelist entry for each browser. Only the one value is touched, so another
    # force-installed extension already listed by someone else keeps its slot.
    foreach ($key in $ExtensionForcelistKeys) {
        try {
            if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
            New-ItemProperty -Path $key -Name '1' -Value "$ExtensionId;$ExtensionUpdateUrl" `
                -PropertyType String -Force | Out-Null
        } catch {
            Write-Log "Content Guard policy $key failed: $($_.Exception.Message)"
        }
    }
}

function Test-ContentGuard {
    # The policy can read as perfectly correct while the extension does not exist anywhere.
    # It is installed FROM A URL, and a URL that answers 404 installs nothing - silently. That
    # is exactly what happened between 14 October and 15 October 2026: every forcelist value was
    # in place, every log line was clean, and no browser had the extension at all, so no page
    # text was ever filtered. Setting the policy is therefore not evidence that it works.
    #
    # So this asks the only question that matters: would a browser following this policy
    # actually get the extension? Returns $null when it cannot tell, which is not the same as
    # a failure and must not raise an alarm.
    if (-not (Test-NetworkUp)) { return $null }
    try {
        $r = Invoke-WebRequest -Uri $ExtensionUpdateUrl -UseBasicParsing -TimeoutSec 20
        if ([int]$r.StatusCode -ne 200) { return "the update manifest answered $([int]$r.StatusCode)." }
        $xml = "$($r.Content)"
        if ($xml -notmatch [regex]::Escape($ExtensionId)) {
            return "the update manifest does not mention extension id $ExtensionId - the signing key changed, so the policy installs nothing."
        }
        $codebase = [regex]::Match($xml, "codebase='([^']+)'").Groups[1].Value
        if (-not $codebase) { return 'the update manifest has no codebase address.' }
        # The manifest can be published while the package beside it is not.
        $crx = Invoke-WebRequest -Uri $codebase -UseBasicParsing -TimeoutSec 40
        if ([int]$crx.StatusCode -ne 200) { return "the extension package answered $([int]$crx.StatusCode)." }
        if ($crx.RawContentLength -lt 1000) { return "the extension package is only $($crx.RawContentLength) bytes." }
    } catch {
        return "the extension could not be fetched: $($_.Exception.Message)"
    }
    return ''   # empty string = all well
}

function Clear-ContentGuard {
    foreach ($key in $ExtensionForcelistKeys) {
        # Only remove the value if it is ours: on a managed PC someone else's extension may
        # be sitting in slot 1, and deleting that would be sabotage rather than cleanup.
        $v = (Get-ItemProperty -Path $key -Name '1' -ErrorAction SilentlyContinue).'1'
        if ($v -and $v -like "$ExtensionId;*") {
            Remove-ItemProperty -Path $key -Name '1' -ErrorAction SilentlyContinue
        }
    }
}

function Set-AppLock {
    Set-Policies $AppLockPolicies
    try {
        if (-not (Test-Path $SaferKey)) { New-Item -Path $SaferKey -Force | Out-Null }
        $v = @{ DefaultLevel = 0; PolicyScope = 1; TransparentEnabled = 1; AuthenticodeEnabled = 0; PornBlocker = 1 }
        foreach ($k in $v.Keys) { New-ItemProperty -Path $SaferKey -Name $k -Value $v[$k] -PropertyType DWord -Force | Out-Null }
        New-ItemProperty -Path $SaferKey -Name 'ExecutableTypes' -Value $SaferTypes -PropertyType MultiString -Force | Out-Null
        # 262144 = Unrestricted, 0 = Disallowed
        foreach ($set in @(@('262144', $SaferAllow), @('0', $SaferDeny))) {
            foreach ($r in $set[1]) {
                $key = Join-Path $SaferKey "$($set[0])\Paths\$($r[0])"
                if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
                New-ItemProperty -Path $key -Name 'ItemData' -Value $r[1] -PropertyType $r[2] -Force | Out-Null
                New-ItemProperty -Path $key -Name 'SaferFlags' -Value 0 -PropertyType DWord -Force | Out-Null
            }
        }
    } catch {
        Write-Log "App lock failed: $($_.Exception.Message)"
    }
}

function Clear-AppLock {
    Remove-Policies $AppLockPolicies
    # Only removes a policy this program wrote - never someone else's restriction policy
    if ((Get-ItemProperty -Path $SaferKey -Name 'PornBlocker' -ErrorAction SilentlyContinue).PornBlocker -eq 1) {
        Remove-Item -Path $SaferKey -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log 'App lock removed.'
    }
}

function Test-DnsEnforced {
    $adapters = @(Get-NetAdapter | Where-Object Status -eq 'Up')
    if ($adapters.Count -eq 0) { return $false }
    foreach ($a in $adapters) {
        $servers = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses)
        if ($servers.Count -eq 0) { return $false }
        foreach ($s in $servers) { if ($DnsV4 -notcontains $s) { return $false } }
    }
    return $true
}

function Set-PrivateDns {
    # Returns $true if the DNS settings had to be changed
    $changed = -not (Test-DnsEnforced)
    foreach ($s in ($DnsV4 + $DnsV6)) {
        try {
            Add-DnsClientDohServerAddress -ServerAddress $s -DohTemplate $DohTemplate `
                -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction Stop | Out-Null
        } catch {
            Set-DnsClientDohServerAddress -ServerAddress $s -DohTemplate $DohTemplate `
                -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction SilentlyContinue | Out-Null
        }
    }
    foreach ($a in @(Get-NetAdapter | Where-Object Status -eq 'Up')) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses ($DnsV4 + $DnsV6)
        } catch {
            Write-Log "Private DNS on '$($a.Name)' failed: $($_.Exception.Message)"
        }
    }
    Set-Policies $BrowserPolicies
    Set-FirewallRules $true
    return $changed
}

function Reset-PrivateDns {
    foreach ($a in @(Get-NetAdapter)) {
        try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses } catch {}
    }
    Disable-DnsFirewallRule
    try { Clear-DnsClientCache } catch {}
    Remove-Policies $BrowserPolicies
}

function Invoke-PrivateDnsSafely([hashtable]$State) {
    # Applies Private DNS; if names stop resolving, reverts to automatic (fail-open).
    # Returns 'ok', 'changed' (was tampered with, now restored), 'failopen' or 'offline'.
    if (-not (Test-NetworkUp)) {
        Write-Log 'No connected network - skipping DNS.'
        return 'offline'
    }
    # Applied before testing: a new adapter (e.g. USB tethering) gets DHCP DNS, which the
    # firewall blocks, so testing first would look "offline" and never get fixed
    $changed = Set-PrivateDns
    Start-Sleep -Seconds 2
    if (Test-NameResolution) {
        $State.dns_failopen = $false
        if ($changed) { return 'changed' } else { return 'ok' }
    }
    Reset-PrivateDns
    Start-Sleep -Seconds 2
    if (-not (Test-NameResolution)) {
        # Automatic DNS fails too, so the internet itself is down - keep the filter on
        Set-PrivateDns | Out-Null
        Write-Log 'No name resolution with either DNS - internet seems down, keeping Private DNS.'
        return 'offline'
    }
    Write-Log 'Name resolution failed only with Private DNS - left on automatic DNS (fail-open).'
    $State.dns_failopen = $true
    return 'failopen'
}


# ---------- hosts blocklists (only with -HostsMode) ----------

function Get-Domains {
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $ok = 0
    foreach ($url in $ListUrls) {
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add('User-Agent', 'porn-site-blocker')
            $wc.Encoding = [System.Text.Encoding]::UTF8
            $text = $wc.DownloadString($url)
        } catch {
            Write-Log "Download failed $url : $($_.Exception.Message)"
            continue
        }
        $before = $set.Count
        $raw = New-Object 'System.Collections.Generic.List[string]'
        if ($text.TrimStart().StartsWith('[')) {
            foreach ($item in ($text | ConvertFrom-Json)) {
                if ($item -is [string]) { $raw.Add($item) }
                else {
                    if ($item.domain) { $raw.Add($item.domain) }
                    if ($item.parent_domain) { $raw.Add($item.parent_domain) }
                }
            }
        } else {
            foreach ($line in ($text -split "`r?`n")) {
                $l = $line
                $i = $l.IndexOf('#')
                if ($i -ge 0) { $l = $l.Substring(0, $i) }
                $l = $l.Trim()
                if (-not $l -or $l.StartsWith('!')) { continue }
                # hosts format: "0.0.0.0 domain" - take the domain
                $parts = $l -split '\s+'
                if ($parts.Count -gt 1) { $raw.Add($parts[1]) } else { $raw.Add($parts[0]) }
            }
        }
        foreach ($d0 in $raw) {
            $d = $d0.Trim().ToLowerInvariant().TrimEnd('.')
            foreach ($prefix in @('http://', 'https://', '*.')) {
                if ($d.StartsWith($prefix)) { $d = $d.Substring($prefix.Length) }
            }
            $slash = $d.IndexOf('/')
            if ($slash -ge 0) { $d = $d.Substring(0, $slash) }
            if (-not $d -or ($Skip -contains $d) -or $d.Contains(' ') -or -not $d.Contains('.')) { continue }
            [void]$set.Add($d)
            # hosts has no wildcards, so add the common www. form
            if (-not $d.StartsWith('www.') -and $d.Split('.').Count -eq 2) { [void]$set.Add("www.$d") }
        }
        $ok++
        Write-Log "$url -> +$($set.Count - $before)"
    }
    if ($set.Count -eq 0) { throw 'All sources failed - hosts file left untouched.' }
    $list = New-Object string[] $set.Count
    $set.CopyTo($list)
    [Array]::Sort($list, [StringComparer]::Ordinal)
    return [pscustomobject]@{ Domains = $list; Ok = $ok }
}

function Read-Hosts {
    $outside = New-Object 'System.Collections.Generic.List[string]'
    $block = New-Object 'System.Collections.Generic.List[string]'
    $inside = $false
    foreach ($line in [IO.File]::ReadAllLines($HostsFile)) {
        $s = $line.Trim()
        if ($s -eq $Begin) { $inside = $true }
        elseif ($s -eq $End) { $inside = $false }
        elseif ($inside) { $block.Add($s) }
        else { $outside.Add($line) }
    }
    while ($outside.Count -gt 0 -and -not $outside[$outside.Count - 1].Trim()) { $outside.RemoveAt($outside.Count - 1) }
    return [pscustomobject]@{ Outside = $outside.ToArray(); Block = $block.ToArray() }
}

function Get-BlockHash([string[]]$Lines) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Lines -join "`n"))
    return -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
}

function Write-Hosts([string[]]$Outside, [string[]]$Block) {
    $all = New-Object 'System.Collections.Generic.List[string]'
    if ($Outside) { $all.AddRange($Outside) }
    if ($Block -and $Block.Count -gt 0) {
        $all.Add('')
        $all.Add($Begin)
        $all.AddRange($Block)
        $all.Add($End)
    }
    attrib -R $HostsFile | Out-Null
    [IO.File]::WriteAllLines($HostsFile, $all.ToArray(), $Utf8NoBom)
    ipconfig /flushdns | Out-Null
}

function Update-Block([hashtable]$State) {
    $r = Get-Domains
    $h = Read-Hosts
    # Windows DNS Client crawls with a huge hosts file, so put 9 domains per line (the max it reads)
    $block = New-Object 'System.Collections.Generic.List[string]'
    for ($i = 0; $i -lt $r.Domains.Length; $i += $DomainsPerLine) {
        $n = [Math]::Min($DomainsPerLine, $r.Domains.Length - $i)
        $block.Add('0.0.0.0 ' + [string]::Join(' ', $r.Domains, $i, $n))
    }
    $block = $block.ToArray()
    Write-Hosts $h.Outside $block
    [IO.File]::WriteAllLines($BackupFile, $block, $Utf8NoBom)
    $State.count = $r.Domains.Length
    $State.hash = Get-BlockHash $block
    $State.updated = Get-Today
    $State.sources_ok = $r.Ok
    Save-JsonFile $StateFile $State
    Write-Log "Blocked $($r.Domains.Length) domains ($($block.Length) hosts lines) from $($r.Ok)/$($ListUrls.Count) sources."
}

function Restore-Block {
    # Restores the block offline from the local backup
    $h = Read-Hosts
    Write-Hosts $h.Outside ([IO.File]::ReadAllLines($BackupFile))
}

function Clear-HostsBlock {
    # Removes our section from hosts (also cleans up after older versions)
    try {
        $h = Read-Hosts
        if ($h.Block.Count -gt 0) {
            Write-Hosts $h.Outside @()
            Write-Log 'Removed the blocklist section from hosts.'
        }
    } catch {
        Write-Log "Could not clean hosts: $($_.Exception.Message)"
    }
}

function Read-SafeSearchHosts {
    $outside = New-Object 'System.Collections.Generic.List[string]'
    $section = New-Object 'System.Collections.Generic.List[string]'
    $inside = $false
    foreach ($line in [IO.File]::ReadAllLines($HostsFile)) {
        $s = $line.Trim()
        if ($s -eq $SsBegin) { $inside = $true }
        elseif ($s -eq $SsEnd) { $inside = $false }
        elseif ($inside) { $section.Add($s) }
        else { $outside.Add($line) }
    }
    while ($outside.Count -gt 0 -and -not $outside[$outside.Count - 1].Trim()) { $outside.RemoveAt($outside.Count - 1) }
    return [pscustomobject]@{ Outside = $outside.ToArray(); Section = $section.ToArray() }
}

function Write-SafeSearchHosts([string[]]$Outside, [string[]]$Section) {
    $all = New-Object 'System.Collections.Generic.List[string]'
    if ($Outside) { $all.AddRange($Outside) }
    if ($Section -and $Section.Count -gt 0) {
        $all.Add('')
        $all.Add($SsBegin)
        $all.AddRange($Section)
        $all.Add($SsEnd)
    }
    attrib -R $HostsFile | Out-Null
    [IO.File]::WriteAllLines($HostsFile, $all.ToArray(), $Utf8NoBom)
    ipconfig /flushdns | Out-Null
}

function Remove-RetiredSafeSearchLines([string[]]$Section) {
    # Drops lines for names this version no longer manages - which is how the YouTube
    # Restricted Mode entries leave a machine that an older version already wrote them to.
    #
    # This cannot wait for the normal rewrite below: that one gives up early whenever a
    # lookup fails, and keeps the existing section exactly as it is. On a PC that is offline
    # at every check, or whose DNS failed open, "no longer written" would have meant
    # "pinned to restrict.youtube.com for ever".
    $managed = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($m in $SafeSearchMap) { foreach ($n in $m[2]) { [void]$managed.Add($n) } }
    $keep = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in $Section) {
        # A hosts line is "<ip> <name> [name...]"
        $names = @(($line -split '\s+' | Where-Object { $_ }) | Select-Object -Skip 1)
        $stillManaged = @($names | Where-Object { $managed.Contains($_) })
        # Keep the line if any of its names is still ours; drop it only when all of them are retired
        if ($names.Count -eq 0 -or $stillManaged.Count -gt 0) { $keep.Add($line) }
    }
    return $keep.ToArray()
}

function Get-SafeSearchLines {
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $allResolved = $true
    foreach ($m in $SafeSearchMap) {
        $ips = @()
        foreach ($type in @('A', 'AAAA')) {
            # -DnsOnly skips hosts, so the lookup never reads back our own entries
            try {
                $ips += @(Resolve-DnsName -Name $m[0] -Type $type -DnsOnly -QuickTimeout -ErrorAction Stop |
                    Where-Object Type -eq $type | ForEach-Object IPAddress)
            } catch {}
        }
        if ($ips.Count -eq 0) {
            $allResolved = $false
            if ($m[1]) { $ips = @($m[1]) }
        }
        foreach ($ip in @($ips | Sort-Object -Unique)) { $lines.Add("$ip $($m[2] -join ' ')") }
    }
    return [pscustomobject]@{ Lines = $lines.ToArray(); AllResolved = $allResolved }
}

function Set-SafeSearchHosts {
    try {
        $r = Get-SafeSearchLines
        $lines = $r.Lines
        $h = Read-SafeSearchHosts
        # Retired names go first and unconditionally, before the early return below
        $cleaned = Remove-RetiredSafeSearchLines $h.Section
        if ($cleaned.Count -ne $h.Section.Count) {
            Write-SafeSearchHosts $h.Outside $cleaned
            Write-Log "Removed $($h.Section.Count - $cleaned.Count) retired SafeSearch hosts line(s) - YouTube Restricted Mode is no longer forced."
            $h = Read-SafeSearchHosts
        }
        # A failed lookup (offline, DNS failing open) keeps the entries already there; fallback IPs only fill an empty section
        if (-not $r.AllResolved -and $h.Section.Count -gt 0) { return }
        if ($lines.Count -eq 0 -or ($h.Section -join "`n") -ceq ($lines -join "`n")) { return }
        Write-SafeSearchHosts $h.Outside $lines
        Write-Log "SafeSearch entries written to hosts ($($lines.Count) lines)."
    } catch {
        Write-Log "SafeSearch hosts entries failed: $($_.Exception.Message)"
    }
}

function Clear-SafeSearchHosts {
    try {
        $h = Read-SafeSearchHosts
        if ($h.Section.Count -gt 0) {
            Write-SafeSearchHosts $h.Outside @()
            Write-Log 'Removed the SafeSearch section from hosts.'
        }
    } catch {
        Write-Log "Could not remove the SafeSearch section from hosts: $($_.Exception.Message)"
    }
}


# ---------- scheduling ----------

function Register-BlockerTask {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`" -Check"
    $hourly = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
    $boot = New-ScheduledTaskTrigger -AtStartup
    # On every network connect (NetworkProfile event 10000), so a new adapter such as USB
    # tethering gets the filter within seconds instead of at the next hourly run
    $eventClass = Get-CimClass -Namespace 'Root/Microsoft/Windows/TaskScheduler' -ClassName 'MSFT_TaskEventTrigger'
    $network = New-CimInstance -CimClass $eventClass -ClientOnly -Property @{
        Enabled      = $true
        Delay        = 'PT15S'
        Subscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational">' +
            '<Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[(EventID=10000)]]</Select>' +
            '</Query></QueryList>'
    }
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($hourly, $boot, $network) `
        -Principal $principal -Settings $settings -Force | Out-Null
    Write-Log "Scheduled task '$TaskName' (hourly + at boot + on network connect)."
}

function Unregister-BlockerTask {
    foreach ($name in @($TaskName, "$TaskName-Boot", $ShotTaskCapture, $ShotTaskFlush)) {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    }
}


# ---------- auto-update ----------

function Update-Self([hashtable]$State) {
    # Replaces the installed script with a newer signed version. The new code runs from the next check.
    # Script and signature come in one file, so a CDN cache can never pair a new script with an old signature
    try {
        $wc = New-Object Net.WebClient
        $wc.Headers['Cache-Control'] = 'no-cache'
        $pkg = $wc.DownloadString("$UpdateBaseUrl/update.json") | ConvertFrom-Json
        $bytes = [Convert]::FromBase64String($pkg.script)
        $sig = [Convert]::FromBase64String($pkg.signature)
    } catch {
        Write-Log "Update check skipped: could not read $UpdateBaseUrl/update.json - $($_.Exception.Message)"
        return
    }
    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($UpdatePublicKey)
    if (-not $rsa.VerifyData($bytes, 'SHA256', $sig)) {
        Write-Log "[ERROR] Update rejected: the signature in $UpdateBaseUrl/update.json does not match the publisher key."
        if ($State.update_sig_notified -ne (Get-Today)) {
            if (Send-Partner 'ALERT: a blocker update with an invalid signature was downloaded and rejected.') { $State.update_sig_notified = Get-Today }
        }
        return
    }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if ($text -notmatch '(?m)^\$ScriptVersion = (\d+)\s*$') {
        Write-Log '[ERROR] Update rejected: the signed blocker.ps1 has no $ScriptVersion line.'
        return
    }
    $newVersion = [int64]$Matches[1]
    if ($newVersion -le $ScriptVersion) { return }

    $newFile = Join-Path $InstallDir 'blocker.new.ps1'
    [IO.File]::WriteAllBytes($newFile, $bytes)
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($newFile, [ref]$null, [ref]$errors)
    if ($errors.Count -gt 0) {
        Remove-Item $newFile -Force -ErrorAction SilentlyContinue
        Write-Log "[ERROR] Update $newVersion rejected: $($errors.Count) syntax error(s), first: $($errors[0].Message) (line $($errors[0].Extent.StartLineNumber))."
        return
    }
    Copy-Item -Path $InstalledScript -Destination (Join-Path $InstallDir 'blocker.prev.ps1') -Force
    Move-Item -Path $newFile -Destination $InstalledScript -Force
    Write-Log "Updated from version $ScriptVersion to $newVersion (previous copy kept as blocker.prev.ps1)."
    Send-Partner "Blocker updated to version $newVersion." | Out-Null
}


# ---------- screenshots (accountability, opt-in) ----------

function Protect-ShotSpool {
    # SYSTEM and Administrators get full control; standard users get WRITE ONLY (no read, no
    # delete) so they can't view or remove shots before SYSTEM sends them. SIDs for any language.
    New-Item -ItemType Directory -Force -Path $ShotSpool | Out-Null
    try {
        $ErrorActionPreference = 'Continue'
        icacls $ShotSpool /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)W' /T /C /Q 2>&1 | Out-Null
    } catch { Write-Log "Locking $ShotSpool failed: $($_.Exception.Message)" }
}

function Save-Screenshot {
    # Captures every monitor to one JPEG in the spool. Best-effort: returns $null on any failure.
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        $vs = [System.Windows.Forms.SystemInformation]::VirtualScreen
        if ($vs.Width -le 0 -or $vs.Height -le 0) { return $null }
        $bmp = New-Object System.Drawing.Bitmap $vs.Width, $vs.Height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($vs.Location, [System.Drawing.Point]::Empty, $vs.Size)
        $g.Dispose()
        $codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' } | Select-Object -First 1
        $ep = New-Object System.Drawing.Imaging.EncoderParameters 1
        $ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality, [long]60)
        $name = '{0}_{1}.jpg' -f $env:USERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss_fff')
        $bmp.Save((Join-Path $ShotSpool $name), $codec, $ep)
        $bmp.Dispose()
        return $true
    } catch { return $null }
}

function Show-ShotNotice {
    # One visible, non-blocking notice per session so the user always knows monitoring is on.
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        $ni = New-Object System.Windows.Forms.NotifyIcon
        $ni.Icon = [System.Drawing.SystemIcons]::Information
        $ni.Visible = $true
        $ni.BalloonTipTitle = 'Accountability monitoring is active'
        $ni.BalloonTipText = 'This computer takes periodic screenshots and sends them to your accountability partner. You agreed to this when it was installed.'
        $ni.ShowBalloonTip(15000)
        Start-Sleep -Seconds 16
        $ni.Visible = $false
        $ni.Dispose()
    } catch {}
}

function Invoke-ScreenshotLoop {
    # Runs in the user's interactive session (scheduled task, at logon) with standard rights, so it
    # can't read the locked config. It keeps going while its own task exists and stops when SYSTEM
    # removes that task (on disable or remove). The interval comes from the task's own arguments.
    $min = if ($ShotMinSeconds -gt 0) { $ShotMinSeconds } else { $ShotMinDefault }
    $max = if ($ShotMaxSeconds -gt 0) { $ShotMaxSeconds } else { $ShotMaxDefault }
    if ($min -lt 5) { $min = 5 }
    if ($max -lt $min) { $max = $min }
    Show-ShotNotice
    while ($true) {
        if (-not (Get-ScheduledTask -TaskName $ShotTaskCapture -ErrorAction SilentlyContinue)) { break }
        Save-Screenshot | Out-Null
        Start-Sleep -Seconds (Get-Random -Minimum $min -Maximum ($max + 1))
    }
}

function Send-Photo([string]$Token, [string]$Chat, [string]$Path, [string]$Caption) {
    try {
        Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds(60)
        $form = New-Object System.Net.Http.MultipartFormDataContent
        $form.Add((New-Object System.Net.Http.StringContent $Chat), 'chat_id')
        if ($Caption) { $form.Add((New-Object System.Net.Http.StringContent $Caption), 'caption') }
        $bytes = [IO.File]::ReadAllBytes($Path)
        $fileContent = New-Object System.Net.Http.ByteArrayContent (, $bytes)
        $fileContent.Headers.ContentType = New-Object System.Net.Http.Headers.MediaTypeHeaderValue 'image/jpeg'
        $form.Add($fileContent, 'photo', [IO.Path]::GetFileName($Path))
        $resp = $client.PostAsync("https://api.telegram.org/bot$Token/sendPhoto", $form).Result
        $ok = $resp.IsSuccessStatusCode
        $client.Dispose()
        return [bool]$ok
    } catch { return $false }
}

function Invoke-FlushShots {
    # Runs as SYSTEM (scheduled task, at boot). Sends spooled shots to the partner and deletes them.
    while ($true) {
        $cfg = Read-JsonFile $ConfigFile
        if ($cfg.screenshots -ne $true) { break }
        if ($cfg.bot_token -and $cfg.chat_id) {
            $device = if ($cfg.device_name) { $cfg.device_name } else { $env:COMPUTERNAME }
            foreach ($f in @(Get-ChildItem -Path $ShotSpool -Filter '*.jpg' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)) {
                if ($f.LastWriteTime -lt (Get-Date).AddHours(-$ShotMaxAgeHours)) {
                    Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
                    continue
                }
                if (Send-Photo $cfg.bot_token $cfg.chat_id $f.FullName "[$device] $($f.BaseName)") {
                    Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
                } else {
                    break   # network / API down - try again next cycle
                }
            }
        }
        Start-Sleep -Seconds 30
    }
}

function Set-ShotTasks([hashtable]$Cfg) {
    # Keeps the capture (user session) and flush (SYSTEM) tasks in sync with the config.
    if ($Cfg.screenshots -eq $true) {
        Protect-ShotSpool
        $min = if ($Cfg.shot_min) { [int]$Cfg.shot_min } else { $ShotMinDefault }
        $max = if ($Cfg.shot_max) { [int]$Cfg.shot_max } else { $ShotMaxDefault }
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
        $capAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`" -ScreenshotLoop -ShotMinSeconds $min -ShotMaxSeconds $max"
        $capPrincipal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
        Register-ScheduledTask -TaskName $ShotTaskCapture -Action $capAction -Trigger (New-ScheduledTaskTrigger -AtLogOn) `
            -Principal $capPrincipal -Settings $settings -Force | Out-Null
        $flAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`" -FlushShots"
        $flPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $ShotTaskFlush -Action $flAction -Trigger (New-ScheduledTaskTrigger -AtStartup) `
            -Principal $flPrincipal -Settings $settings -Force | Out-Null
        if ((Get-ScheduledTask -TaskName $ShotTaskFlush -ErrorAction SilentlyContinue).State -ne 'Running') {
            Start-ScheduledTask -TaskName $ShotTaskFlush -ErrorAction SilentlyContinue
        }
        if ((Get-ScheduledTask -TaskName $ShotTaskCapture -ErrorAction SilentlyContinue).State -ne 'Running') {
            Start-ScheduledTask -TaskName $ShotTaskCapture -ErrorAction SilentlyContinue
        }
        Write-Log "Screenshot monitoring on (every $min-$max s, sent to the partner)."
    } else {
        Unregister-ScheduledTask -TaskName $ShotTaskCapture -Confirm:$false -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $ShotTaskFlush -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Get-ShotConsent {
    # Decides the screenshot setting at install - explicit, informed consent is required.
    $cfg = Read-JsonFile $ConfigFile
    if ($ShotMinSeconds -gt 0) { $cfg.shot_min = $ShotMinSeconds }
    if ($ShotMaxSeconds -gt 0) { $cfg.shot_max = $ShotMaxSeconds }
    if (-not $cfg.shot_min) { $cfg.shot_min = $ShotMinDefault }
    if (-not $cfg.shot_max) { $cfg.shot_max = $ShotMaxDefault }

    if ($NoScreenshots) {
        $cfg.screenshots = $false
    } elseif ($cfg.ContainsKey('screenshots')) {
        # a reinstall keeps the earlier decision (like the partner)
    } elseif ([Environment]::UserInteractive) {
        Write-Host ''
        Write-Host '=== Screenshot accountability (optional) ===' -ForegroundColor Cyan
        Write-Host 'If you turn this on, this computer will take a screenshot of the whole screen'
        Write-Host "every $($cfg.shot_min)-$($cfg.shot_max) seconds and send it to your accountability partner on Telegram."
        Write-Host 'A notice appears each time you sign in, so you always know it is active.'
        $ans = Read-Host 'Type YES to enable screenshot monitoring, or press Enter to skip'
        if ($ans.Trim().ToUpper() -eq 'YES') {
            $cfg.screenshots = $true
            $cfg.shot_consent = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Write-Host 'Screenshot monitoring enabled. Thank you.' -ForegroundColor Green
        } else {
            $cfg.screenshots = $false
            Write-Host 'Screenshot monitoring skipped.'
        }
    } else {
        $cfg.screenshots = $false
    }
    Save-JsonFile $ConfigFile $cfg
    return $cfg
}


# ---------- commands ----------

function Set-Guards([hashtable]$Cfg) {
    # The parts that don't depend on DNS working, so they stay on through fail-open
    Set-Policies $GuardPolicies
    # Policies this version no longer sets: cleared so a machine that was set up by an older
    # version does not keep them forever (nothing here was ever set by anything else).
    Remove-Policies $RetiredPolicies
    # Keyword filtering of the page text itself, through the force-installed extension
    Set-ContentGuard
    Set-SafeSearchHosts
    # Missing key (installs from before the app lock) counts as on
    Clear-AppLock
}

function Invoke-Install {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    if ($PSCommandPath -ne $InstalledScript) { Copy-Item -Path $PSCommandPath -Destination $InstalledScript -Force }
    Protect-InstallDir
    $cfg = Read-JsonFile $ConfigFile
    $cfg.hosts_mode = [bool]$HostsMode
    $cfg.lock_apps = -not $NoLockApps
    Save-JsonFile $ConfigFile $cfg
    $state = Read-JsonFile $StateFile
    if ($HostsMode) { Update-Block $state } else { Clear-HostsBlock }
    Set-Guards $cfg
    if ($cfg.lock_apps) { Write-Log 'App lock on: standard users run programs only from Windows / Program Files (after they sign in again).' }
    $dns = Invoke-PrivateDnsSafely $state
    switch ($dns) {
        'failopen' { Write-Log 'Private DNS did not work on this network - left on automatic DNS for now.' }
        'offline' { Write-Log 'Offline - Private DNS will be applied by the next check.' }
        default { Write-Log "Private DNS set to Cloudflare for Families ($($DnsV4 -join ', ')), internet verified." }
    }
    Unregister-BlockerTask
    Register-BlockerTask
    $state.heartbeat = Get-Today
    Save-JsonFile $StateFile $state
    Write-Log "Blocking is active. Files in $InstallDir"
    # Partner linking goes last: skipping it with Ctrl+C must not leave the block half-installed
    Set-PartnerConfig
    Send-Partner "Blocker installed (Private DNS: $dns)." | Out-Null
    # Screenshot accountability: ask the user, then apply and tell the partner either way
    $cfg = Get-ShotConsent
    Set-ShotTasks $cfg
    if ($cfg.screenshots -eq $true) {
        Send-Partner "Screenshot monitoring is ON (every $($cfg.shot_min)-$($cfg.shot_max)s, with the user's consent)." | Out-Null
    } else {
        Send-Partner 'Screenshot monitoring is off.' | Out-Null
    }
    Write-Log 'Install complete.'
}

function Invoke-Check {
    # Also locks installs made before the folder was protected
    Protect-InstallDir
    $state = Read-JsonFile $StateFile
    $cfg = Read-JsonFile $ConfigFile

    # 0) first run of a new version: re-register the task, in case its triggers changed
    if ($state.applied_version -ne $ScriptVersion) {
        Register-BlockerTask
        $state.applied_version = $ScriptVersion
        Write-Log "Version $ScriptVersion active."
    }
    # Only the installed copy updates itself - never a copy run by hand from a setup folder
    if ($PSCommandPath -eq $InstalledScript) { Update-Self $state }

    # 1) hosts: blocklists only in hosts mode, otherwise make sure hosts stays clean
    if ($cfg.hosts_mode) {
        $h = Read-Hosts
        if ($h.Block.Count -eq 0 -or (Get-BlockHash $h.Block) -ne $state.hash) {
            Write-Log 'hosts block removed or modified - restoring.'
            try { Restore-Block } catch { Update-Block $state }
            Send-Partner 'ALERT: the hosts block was removed or modified. It has been restored.' | Out-Null
        }
        if ($state.updated -ne (Get-Today)) {
            try { Update-Block $state } catch { Write-Log "Update failed: $($_.Exception.Message)" }
        }
    } else {
        Clear-HostsBlock
    }

    # 2) DNS: re-apply, verify, fail open if it breaks the internet
    Set-Guards $cfg
    $wasFailOpen = [bool]$state.dns_failopen
    $dns = Invoke-PrivateDnsSafely $state
    if ($dns -eq 'changed' -and -not $wasFailOpen) {
        Write-Log 'DNS settings changed - Private DNS restored.'
        Send-Partner 'ALERT: the DNS settings were changed. Private DNS has been restored.' | Out-Null
    } elseif ($dns -eq 'failopen' -and $state.failopen_notified -ne (Get-Today)) {
        if (Send-Partner 'NOTE: Private DNS broke name resolution on this network, so DNS was set back to automatic. It will retry every hour.') {
            $state.failopen_notified = Get-Today
        }
    }

    # 3) the filter must actually filter: names resolve but blocked sites too = DNS intercepted
    if ($dns -in @('ok', 'changed') -and -not (Test-FilterActive)) {
        Write-Log 'Private DNS is set but blocked sites still resolve - DNS is being intercepted.'
        if ($state.intercept_notified -ne (Get-Today)) {
            if (Send-Partner 'ALERT: Private DNS is set, but adult sites still resolve on this network - something (often the router) is intercepting DNS. The filter is NOT working right now.') {
                $state.intercept_notified = Get-Today
            }
        }
    }

    # 3b) the keyword / YouTube filter must actually be installable, not merely configured
    $guard = Test-ContentGuard
    if ($null -eq $guard) {
        # no network: nothing was learned, so nothing is claimed
    } elseif ($guard -eq '') {
        $state.guard_fails = 0
    } else {
        $state.guard_fails = [int]$state.guard_fails + 1
        Write-Log "Content Guard not available: $guard (consecutive failures: $($state.guard_fails))"
        # Two checks in a row, so one flaky hour is not an alarm, but a real outage still is.
        if ([int]$state.guard_fails -ge 2 -and $state.guard_notified -ne (Get-Today)) {
            if (Send-Partner ("ALERT: the page-content filter (keywords and the YouTube channel list) " +
                    "is NOT installed on this device and cannot install itself: $guard " +
                    "DNS filtering is unaffected, but page text is not being filtered.")) {
                $state.guard_notified = Get-Today
            }
        }
    }

    # 4) daily heartbeat to the partner
    if ($state.heartbeat -ne (Get-Today)) {
        if (Send-Partner "Blocker running (Private DNS: $dns).") {
            $state.heartbeat = Get-Today
        }
    }

    # 5) screenshots: keep the capture + flush tasks matching the config (re-registers and
    #    restarts a crashed loop when on; removes the tasks when off)
    Set-ShotTasks $cfg

    Save-JsonFile $StateFile $state
}

function Invoke-Remove {
    Send-Partner 'ALERT: the remove command was run - the block is being removed from this device.' | Out-Null
    Clear-HostsBlock
    Clear-SafeSearchHosts
    Reset-PrivateDns
    Remove-Policies $GuardPolicies
    Remove-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue
    Clear-ContentGuard
    Clear-AppLock
    # Turn screenshots off in the config first so any running capture/flush loop stops, then
    # delete the tasks and the spool
    $cfg = Read-JsonFile $ConfigFile
    $cfg.screenshots = $false
    Save-JsonFile $ConfigFile $cfg
    Unregister-BlockerTask
    Remove-Item -Path $ShotSpool -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log 'Block removed: DNS automatic, browser policies, SafeSearch hosts entries, firewall rules, app lock and Store-install block gone, keyword extension unforced, screenshots off, tasks and spool deleted.'
}


# ---------- main (skipped when dot-sourced) ----------

if ($MyInvocation.InvocationName -ne '.') {
    # The capture loop runs in the user's interactive session with standard rights - it must not
    # try to elevate. It is launched only by its own SYSTEM-created scheduled task.
    if ($ScreenshotLoop) { Invoke-ScreenshotLoop; exit }

    $principalNow = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principalNow.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ($Elevated) {
            Write-Host "ERROR: relaunched with administrator rights, but Windows still reports this process as not elevated (user: $env:USERNAME)." -ForegroundColor Red
            Write-Host 'Stopping instead of relaunching again. Sign in with an Administrator account and run the installer again.' -ForegroundColor Red
            Start-Sleep -Seconds 30
            exit 1
        }
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated')
        if ($Check) { $argList += '-Check' }
        if ($Remove) { $argList += '-Remove' }
        if ($HostsMode) { $argList += '-HostsMode' }
        if ($NoLockApps) { $argList += '-NoLockApps' }
        if ($Partner) { $argList += @('-Partner', $Partner) }
        if ($BotToken) { $argList += @('-BotToken', $BotToken) }
        if ($ChatId) { $argList += @('-ChatId', $ChatId) }
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
        exit
    }
    try {
        if ($FlushShots) { Invoke-FlushShots }
        elseif ($Remove) { Invoke-Remove }
        elseif ($Check) { Invoke-Check }
        else { Invoke-Install }
    } catch {
        Write-Log "[ERROR] $($_.Exception.Message)"
        if (-not $Check) { Start-Sleep -Seconds 10 }
        exit 1
    }
    if (-not $Check) { Start-Sleep -Seconds 5 }
}
