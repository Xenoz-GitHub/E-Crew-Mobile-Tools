/*
 * Forensic Toolkit - bundled offline YARA rules (YARA-lite subset).
 * These are original, generic detection patterns for payload triage.
 * Supported subset: text/hex/regex strings, nocase|wide|ascii|fullword,
 * and/or/not, $id, #id, @id, filesize, integer compares, any|all|N of them.
 */

rule base64_dotnet_stub_header
{
    meta:
        author = "ForensicToolkit"
        description = "Base64-encoded .NET PE stub ('This program cannot be run in DOS mode')"
        severity = "medium"
    strings:
        $b64 = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGU" nocase
        $b64b = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9T"
    condition:
        any of them
}

rule webshell_php_eval_base64
{
    meta:
        author = "ForensicToolkit"
        description = "PHP webshell pattern: eval(base64_decode(...))"
        severity = "high"
    strings:
        $a = "eval(base64_decode(" nocase
        $b = "eval (base64_decode(" nocase
        $c = "assert(base64_decode(" nocase
        $d = "preg_replace('/.*/e'" nocase
    condition:
        any of them
}

rule powershell_encoded_command
{
    meta:
        author = "ForensicToolkit"
        description = "Encoded PowerShell execution (common dropper stage)"
        severity = "high"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "-enc " nocase
        $c = "FromBase64String" nocase
        $d = "powershell" nocase fullword
        $e = "-nop " nocase
    condition:
        2 of them
}

rule js_obfuscated_atob_chain
{
    meta:
        author = "ForensicToolkit"
        description = "JavaScript obfuscation: atob + document.write / eval"
        severity = "medium"
    strings:
        $a = "atob(" nocase
        $b = "document.write(" nocase
        $c = "String.fromCharCode(" nocase
        $d = "unescape(" nocase
    condition:
        2 of them
}

rule android_dynamic_dex
{
    meta:
        author = "ForensicToolkit"
        description = "Android dynamic code loading indicators"
        severity = "medium"
    strings:
        $a = "DexClassLoader" ascii
        $b = "PathClassLoader" ascii
        $c = "loadDex" ascii
        $d = "dalvik.system" ascii
        $e = "Runtime.getRuntime().exec" ascii
    condition:
        2 of them
}

rule qr_phishing_lure
{
    meta:
        author = "ForensicToolkit"
        description = "QR/phishing social-engineering lure combined with a link"
        severity = "medium"
    strings:
        $lure1 = "verify your account" nocase
        $lure2 = "unusual activity" nocase
        $lure3 = "confirm your identity" nocase
        $lure4 = "your account will be suspended" nocase
        $lure5 = "scan to claim" nocase
        $lure6 = "update your payment" nocase
        $url1 = "http://" nocase
        $url2 = "https://" nocase
    condition:
        any of ($lure*) and any of ($url*)
}

rule credential_param_harvest
{
    meta:
        author = "ForensicToolkit"
        description = "Credential parameters embedded in a URL or payload"
        severity = "medium"
    strings:
        $a = "password=" nocase
        $b = "passwd=" nocase
        $c = "pwd=" nocase
        $d = "user_login=" nocase
        $e = "api_key=" nocase
        $f = "otp=" nocase
        $g = "cvv=" nocase
    condition:
        any of them
}

rule suspicious_crypto_wallet_prompt
{
    meta:
        author = "ForensicToolkit"
        description = "Crypto wallet connection lure (drainer infrastructure pattern)"
        severity = "high"
    strings:
        $a = "connect your wallet" nocase
        $b = "seed phrase" nocase
        $c = "recovery phrase" nocase
        $d = "approve this transaction" nocase
        $e = "sign in with ethereum" nocase
    condition:
        2 of them
}

rule shell_reverse_connect
{
    meta:
        author = "ForensicToolkit"
        description = "Reverse shell / bind shell command fragments"
        severity = "critical"
    strings:
        $a = "bash -i >& /dev/tcp/" nocase
        $b = "nc -e /bin/sh" nocase
        $c = "socket.connect((" ascii
        $d = "/dev/tcp/" ascii
        $e = "Runtime.getRuntime().exec" ascii
        $f = "subprocess.Popen" ascii
    condition:
        any of them
}

rule pem_private_key_exposure
{
    meta:
        author = "ForensicToolkit"
        description = "Private key material in payload"
        severity = "high"
    strings:
        $a = "-----BEGIN RSA PRIVATE KEY-----"
        $b = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $c = "-----BEGIN EC PRIVATE KEY-----"
        $d = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    condition:
        any of them
}

rule ipv4_with_ports_suspicious
{
    meta:
        author = "ForensicToolkit"
        description = "Raw IP:port C2 style endpoints (heuristic, informational)"
        severity = "info"
    strings:
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{2,5}/
    condition:
        #ip > 2
}
