[CmdletBinding(DefaultParameterSetName = 'File')]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'File')]
  [string]$TargetFile,

  [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
  [ValidatePattern('^[A-Fa-f0-9]{40}$')]
  [string]$CertificateSha1
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Public-Text([object]$Value) {
  if ($null -eq $Value) { return $null }
  $text = [string]$Value
  if ($text.Length -gt 2048 -or $text -match '[\x00-\x1f\x7f]') {
    throw 'Invalid public certificate metadata'
  }
  return $text
}

try {
  if (-not $IsWindows -or -not [Environment]::Is64BitProcess -or
      [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') {
    throw 'Native Windows x64 PowerShell is required'
  }

  if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
    # Read only the requested public certificate. No private-key access,
    # credential discovery, whole-store enumeration, or credential output.
    $certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $CertificateSha1.ToUpperInvariant())
    $codeSigning = @($certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' }).Count -gt 0
    [pscustomobject]@{
      thumbprint = $certificate.Thumbprint.ToUpperInvariant()
      subject = Public-Text $certificate.Subject
      publisherName = Public-Text ($certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false))
      codeSigning = $codeSigning
      notBefore = $certificate.NotBefore.ToUniversalTime().ToString('o')
      notAfter = $certificate.NotAfter.ToUniversalTime().ToString('o')
      currentlyValid = ($certificate.NotBefore -le [DateTime]::Now -and $certificate.NotAfter -ge [DateTime]::Now)
    } | ConvertTo-Json -Compress
    exit 0
  }

  $item = Get-Item -LiteralPath $TargetFile
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Signature target must be an ordinary file'
  }
  $signature = Get-AuthenticodeSignature -LiteralPath $item.FullName
  $signer = $signature.SignerCertificate
  $timestamp = $signature.TimeStamperCertificate
  [pscustomobject]@{
    status = [string]$signature.Status
    signatureType = [string]$signature.SignatureType
    signerSubject = if ($signer) { Public-Text $signer.Subject } else { $null }
    signerThumbprint = if ($signer) { $signer.Thumbprint.ToUpperInvariant() } else { $null }
    publisherName = if ($signer) { Public-Text ($signer.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)) } else { $null }
    timestampSubject = if ($timestamp) { Public-Text $timestamp.Subject } else { $null }
    timestampThumbprint = if ($timestamp) { $timestamp.Thumbprint.ToUpperInvariant() } else { $null }
  } | ConvertTo-Json -Compress
} catch {
  # Do not let native/provider diagnostics or credential-bearing environment
  # values reach the caller's logs. The JS caller also discards raw output.
  [Console]::Error.WriteLine('Windows public certificate/signature inspection failed.')
  exit 1
}
