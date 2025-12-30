# Auto-Elevation PowerShell Script - Compatible with Remote Pipeline Execution
<#
.SYNOPSIS
    Configurazione automatica Scan to Folder per Windows 11 Pro
.DESCRIPTION
    Script PowerShell per automatizzare la configurazione completa della funzione 
    "Scan to Folder" per scanner di rete, compatibile con ambienti locali e domini AD.
.AUTHOR
    Kiro AI Assistant
.VERSION
    2.0
#>

# Configurazione console
$Host.UI.RawUI.WindowTitle = "Configurazione Scan to Folder - Windows 11 Pro"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "Green"
Clear-Host

# Variabili globali
$ScanFolder = "C:\Scansioni"
$ScanUser = "scanner"
$ScanPassword = ""  # Sarà richiesta interattivamente
$DomainMode = $false
$CurrentDomain = ""
$DesktopPath = [Environment]::GetFolderPath("Desktop")

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "    CONFIGURAZIONE SCAN TO FOLDER v2.0" -ForegroundColor Cyan
Write-Host "    Compatible con Windows 11 Pro" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Avvio script PowerShell in corso..." -ForegroundColor Yellow
Write-Host "[INFO] Verifica privilegi amministratore..." -ForegroundColor Yellow

# Auto-elevazione privilegi amministratore (metodo ultra-robusto)
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host ""
    Write-Host "🔐 ELEVAZIONE PRIVILEGI RICHIESTA" -ForegroundColor Yellow -BackgroundColor DarkBlue
    Write-Host ""
    Write-Host "⚡ Tentativo di auto-elevazione in corso..." -ForegroundColor Cyan
    Write-Host "👉 Accettare la richiesta UAC quando appare" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        # Crea sempre un file temporaneo per garantire compatibilità
        $TempScriptPath = "$env:TEMP\ConfiguraScanToFolder_$(Get-Date -Format 'yyyyMMddHHmmss').ps1"
        
        # Salva lo script completo
        if ($MyInvocation.MyCommand.Path) {
            # Script eseguito da file - copia il file
            Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $TempScriptPath -Force
        }
        else {
            # Script da pipeline - salva il contenuto
            $ScriptContent = $MyInvocation.MyCommand.ScriptBlock.ToString()
            # Aggiungi marker per identificare esecuzione elevata
            $ScriptContent = "`$env:ELEVATED_EXECUTION = 'TRUE'`n" + $ScriptContent
            [System.IO.File]::WriteAllText($TempScriptPath, $ScriptContent, [System.Text.Encoding]::UTF8)
        }
        
        # Crea comando PowerShell completo come singola stringa
        $PSCommand = "-NoProfile -ExecutionPolicy Bypass -File `"$TempScriptPath`""
        
        # Avvio processo elevato con WindowStyle Normal per vedere output
        $Process = Start-Process -FilePath "powershell.exe" `
            -ArgumentList $PSCommand `
            -Verb RunAs `
            -WindowStyle Normal `
            -PassThru
        
        if ($Process) {
            Write-Host "[OK] Nuova finestra PowerShell avviata con privilegi elevati" -ForegroundColor Green
            Write-Host ""
            Write-Host "===============================================" -ForegroundColor Cyan
            Write-Host "   MONITORAGGIO ESECUZIONE SCRIPT" -ForegroundColor Cyan
            Write-Host "===============================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "✓ La configurazione prosegue nella nuova finestra elevata" -ForegroundColor White
            Write-Host "✓ Questa finestra rimane aperta per monitoraggio" -ForegroundColor White
            Write-Host "✓ Chiudere questa finestra quando la configurazione è completata" -ForegroundColor White
            Write-Host ""
            Write-Host "[INFO] PID processo elevato: $($Process.Id)" -ForegroundColor Gray
            Write-Host ""
            
            # Attendi completamento processo elevato
            Write-Host "Attendere completamento configurazione..." -ForegroundColor Yellow
            $Process.WaitForExit()
            
            # Cleanup file temporaneo
            Start-Sleep -Seconds 2
            if (Test-Path $TempScriptPath) {
                Remove-Item -Path $TempScriptPath -Force -ErrorAction SilentlyContinue
            }
            
            Write-Host ""
            Write-Host "[OK] Configurazione completata" -ForegroundColor Green
            Write-Host "Premere Enter per chiudere questa finestra..." -ForegroundColor Yellow
            Read-Host
        }
        else {
            throw "Impossibile avviare processo elevato"
        }
        
        exit 0
        
    }
    catch {
        Write-Host ""
        Write-Host "[ERRORE] Auto-elevazione fallita: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "SOLUZIONE MANUALE:" -ForegroundColor Yellow
        Write-Host "═══════════════════" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "1. Cliccare col tasto destro sull'icona PowerShell" -ForegroundColor White
        Write-Host "2. Selezionare 'Esegui come amministratore'" -ForegroundColor White
        Write-Host "3. Eseguire i seguenti comandi:" -ForegroundColor White
        Write-Host ""
        Write-Host "   Set-ExecutionPolicy Bypass -Scope Process -Force" -ForegroundColor Cyan
        Write-Host "   .\ConfiguraScanToFolder.ps1" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Oppure copiare e incollare l'intero script nella finestra elevata" -ForegroundColor White
        Write-Host ""
        Read-Host "Premere Enter per chiudere"
        exit 1
    }
}

Write-Host "[OK] Privilegi amministratore verificati" -ForegroundColor Green

# Funzione per gestire errori
function Write-ErrorAndExit {
    param([string]$Message)
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host "[ERRORE] CONFIGURAZIONE INTERROTTA" -ForegroundColor Red
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host $Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Configurazione fallita. Dettagli:" -ForegroundColor Yellow
    Write-Host "- Utente: $ScanUser" -ForegroundColor Yellow
    Write-Host "- Cartella: $ScanFolder" -ForegroundColor Yellow
    Write-Host "- Modalita: $(if($DomainMode){'Dominio'}else{'Locale'})" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Premere Enter per chiudere"
    exit 1
}

# Richiesta password per utente scanner
Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "    CONFIGURAZIONE PASSWORD UTENTE" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Inserire la password per l'utente 'scanner':" -ForegroundColor Yellow
Write-Host "(La password deve essere sicura per motivi di sicurezza)" -ForegroundColor Gray
Write-Host ""

do {
    # Prima richiesta password
    $ScanPassword = Read-Host "Password per utente scanner" -AsSecureString
    $ScanPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ScanPassword))
    
    # Verifica lunghezza minima
    if ($ScanPasswordPlain.Length -lt 6) {
        Write-Host "[ERRORE] La password deve essere di almeno 6 caratteri!" -ForegroundColor Red
        Write-Host ""
        continue
    }
    
    # Seconda richiesta per conferma
    Write-Host ""
    $ScanPasswordConfirm = Read-Host "Conferma password per utente scanner" -AsSecureString
    $ScanPasswordConfirmPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ScanPasswordConfirm))
    
    # Verifica corrispondenza password
    if ($ScanPasswordPlain -ne $ScanPasswordConfirmPlain) {
        Write-Host ""
        Write-Host "[ERRORE] Le password non corrispondono! Riprovare." -ForegroundColor Red
        Write-Host ""
        # Pulisci le variabili per sicurezza
        $ScanPasswordPlain = ""
        $ScanPasswordConfirmPlain = ""
        continue
    }
    
    # Password valida e confermata
    Write-Host ""
    Write-Host "[OK] Password confermata e configurata" -ForegroundColor Green
    
    # Pulisci la variabile di conferma per sicurezza
    $ScanPasswordConfirmPlain = ""
    break
    
} while ($true)
Write-Host ""

# Rileva dominio automaticamente
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "    RILEVAMENTO CONFIGURAZIONE SISTEMA" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Rilevamento configurazione sistema..." -ForegroundColor Yellow

try {
    $ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $CurrentDomain = $ComputerSystem.Domain
    
    if ($CurrentDomain -eq "WORKGROUP" -or $CurrentDomain -eq $env:COMPUTERNAME) {
        $IsDomain = $false
        Write-Host "[INFO] Sistema rilevato: WORKGROUP (ambiente locale)" -ForegroundColor Yellow
    }
    else {
        $IsDomain = $true
        Write-Host "[INFO] Sistema rilevato: DOMINIO ($CurrentDomain)" -ForegroundColor Yellow
        
        # Verifica esistenza utente scanner nel dominio
        Write-Host "[INFO] Verifica esistenza utente '$ScanUser' nel dominio..." -ForegroundColor Yellow
        try {
            $ADUser = Get-ADUser -Identity $ScanUser -ErrorAction Stop
            Write-Host "[OK] Utente '$ScanUser' trovato nel dominio $CurrentDomain" -ForegroundColor Green
        }
        catch {
            Write-Host "[INFO] Utente '$ScanUser' NON trovato nel dominio $CurrentDomain" -ForegroundColor Yellow
        }
    }
}
catch {
    $IsDomain = $false
    $CurrentDomain = "WORKGROUP"
    Write-Host "[INFO] Sistema rilevato: WORKGROUP (ambiente locale - fallback)" -ForegroundColor Yellow
}

# Menu selezione modalità
Write-Host ""
Write-Host "Seleziona modalita di configurazione:" -ForegroundColor Cyan
Write-Host "[0] Utente locale (predefinito)" -ForegroundColor White
Write-Host "[1] Utente di dominio" -ForegroundColor White
Write-Host "[2] Inserisci dominio manualmente" -ForegroundColor White
Write-Host ""

do {
    $Choice = Read-Host "Inserisci scelta [0-2]"
} while ($Choice -notin @("0", "1", "2", ""))

switch ($Choice) {
    "1" {
        if (-not $IsDomain) {
            Write-Host "[ATTENZIONE] Sistema non in dominio, uso modalita locale" -ForegroundColor Yellow
            $DomainMode = $false
        }
        else {
            $DomainMode = $true
        }
    }
    "2" {
        $ManualDomain = Read-Host "Inserisci nome dominio"
        if ($ManualDomain) {
            $CurrentDomain = $ManualDomain
            $DomainMode = $true
        }
    }
    default {
        $DomainMode = $false
    }
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "    INIZIO CONFIGURAZIONE" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

# STEP 1: Gestione utente Scanner
Write-Host ""
Write-Host "[STEP 1] Ricerca e configurazione utente $ScanUser" -ForegroundColor Cyan

if ($DomainMode) {
    Write-Host "[INFO] Modalita dominio attiva - Dominio: $CurrentDomain" -ForegroundColor Yellow
    Write-Host "[INFO] Verifica esistenza utente nel dominio..." -ForegroundColor Yellow
    
    try {
        # Verifica utente nel dominio
        $ADUser = Get-ADUser -Identity $ScanUser -ErrorAction Stop
        Write-Host "[INFO] Utente $ScanUser trovato nel dominio $CurrentDomain" -ForegroundColor Yellow
        Write-Host "[INFO] Verifica appartenenza ai gruppi necessari..." -ForegroundColor Yellow
        
        # Aggiungi utente ai gruppi locali
        try {
            Add-LocalGroupMember -Group "Users" -Member "$CurrentDomain\$ScanUser" -ErrorAction SilentlyContinue
            Write-Host "[INFO] Aggiunta utente dominio al gruppo Administrators..." -ForegroundColor Yellow
            Add-LocalGroupMember -Group "Administrators" -Member "$CurrentDomain\$ScanUser" -ErrorAction SilentlyContinue
            Add-LocalGroupMember -Group "Network Configuration Operators" -Member "$CurrentDomain\$ScanUser" -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "[ATTENZIONE] Possibili problemi nell'aggiunta ai gruppi locali" -ForegroundColor Yellow
        }
        
        Write-Host "[OK] Utente dominio configurato per accesso di rete" -ForegroundColor Green
        $FinalUsername = "$CurrentDomain\$ScanUser"
    }
    catch {
        Write-Host "[ATTENZIONE] Utente $ScanUser non trovato nel dominio o RSAT non installato" -ForegroundColor Yellow
        Write-Host "[INFO] Creazione utente locale come fallback..." -ForegroundColor Yellow
        $DomainMode = $false
    }
}

if (-not $DomainMode) {
    Write-Host "[INFO] Modalita locale attiva" -ForegroundColor Yellow
    
    # Verifica utente locale
    try {
        $LocalUser = Get-LocalUser -Name $ScanUser -ErrorAction Stop
        Write-Host "[INFO] Utente locale $ScanUser gia esistente" -ForegroundColor Yellow
        Write-Host "[INFO] Aggiornamento password e configurazione..." -ForegroundColor Yellow
        
        # Aggiorna password e configurazione
        $SecurePassword = ConvertTo-SecureString $ScanPasswordPlain -AsPlainText -Force
        Set-LocalUser -Name $ScanUser -Password $SecurePassword -PasswordNeverExpires $true -UserMayChangePassword $false
        
        # Abilita utente se disabilitato
        if (-not $LocalUser.Enabled) {
            Write-Host "[INFO] Abilitazione utente disabilitato..." -ForegroundColor Yellow
            Enable-LocalUser -Name $ScanUser
        }
    }
    catch {
        Write-Host "[INFO] Creazione nuovo utente locale $ScanUser..." -ForegroundColor Yellow
        
        try {
            $SecurePassword = ConvertTo-SecureString $ScanPasswordPlain -AsPlainText -Force
            New-LocalUser -Name $ScanUser -Password $SecurePassword -Description "Utente per scanner di rete" -PasswordNeverExpires -UserMayNotChangePassword
            Write-Host "[OK] Utente locale creato con successo" -ForegroundColor Green
        }
        catch {
            Write-ErrorAndExit "Impossibile creare l'utente locale: $($_.Exception.Message)"
        }
    }
    
    # Aggiungi utente ai gruppi necessari
    Write-Host "[INFO] Configurazione gruppi utente..." -ForegroundColor Yellow
    try {
        Add-LocalGroupMember -Group "Users" -Member $ScanUser -ErrorAction SilentlyContinue
        Write-Host "[INFO] Aggiunta utente al gruppo Administrators..." -ForegroundColor Yellow
        Add-LocalGroupMember -Group "Administrators" -Member $ScanUser -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "[ATTENZIONE] Possibili problemi nell'aggiunta ai gruppi" -ForegroundColor Yellow
    }
    
    # Nascondi utente dalla schermata di login
    Write-Host "[INFO] Nascondo utente dalla schermata di login..." -ForegroundColor Yellow
    try {
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $RegPath -Name $ScanUser -Value 0 -Type DWord
    }
    catch {
        Write-Host "[ATTENZIONE] Impossibile nascondere utente dalla schermata di login" -ForegroundColor Yellow
    }
    
    $FinalUsername = "$env:COMPUTERNAME\$ScanUser"
    Write-Host "[OK] Utente locale configurato completamente" -ForegroundColor Green
}

# Verifica finale dell'utente
Write-Host "[INFO] Verifica finale configurazione utente..." -ForegroundColor Yellow
if ($DomainMode) {
    Write-Host "[INFO] Utente finale: $CurrentDomain\$ScanUser" -ForegroundColor Yellow
    Write-Host "[OK] Configurazione utente dominio completata" -ForegroundColor Green
}
else {
    try {
        Get-LocalUser -Name $ScanUser -ErrorAction Stop | Out-Null
        Write-Host "[OK] Utente $ScanUser verificato e pronto" -ForegroundColor Green
    }
    catch {
        Write-ErrorAndExit "Problema con la configurazione utente locale"
    }
}

# STEP 2: Creazione cartella Scansioni
Write-Host ""
Write-Host "[STEP 2] Configurazione cartella $ScanFolder" -ForegroundColor Cyan

if (Test-Path $ScanFolder) {
    Write-Host "[INFO] Cartella esistente trovata" -ForegroundColor Yellow
}
else {
    Write-Host "[INFO] Creazione cartella..." -ForegroundColor Yellow
    try {
        New-Item -Path $ScanFolder -ItemType Directory -Force | Out-Null
        Write-Host "[OK] Cartella creata con successo" -ForegroundColor Green
    }
    catch {
        Write-ErrorAndExit "Impossibile creare la cartella: $($_.Exception.Message)"
    }
}

# STEP 3: Impostazione permessi NTFS
Write-Host ""
Write-Host "[STEP 3] Configurazione permessi NTFS (Blindati)" -ForegroundColor Cyan

try {
    # Identifica l'utente corrente che sta eseguendo lo script
    $CurrentUserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Host "[INFO] Utente corrente rilevato: $CurrentUserIdentity" -ForegroundColor Yellow
    
    # 1. Imposta proprietario
    Write-Host "[INFO] Impostazione proprietario cartella: $CurrentUserIdentity..." -ForegroundColor Yellow
    icacls $ScanFolder /setowner "$CurrentUserIdentity" /T | Out-Null

    # 2. Resetta e disabilita ereditarietà, rimuovendo tutti i permessi ereditati (/inheritance:r)
    #    Concede Full Control all'utente corrente
    Write-Host "[INFO] Rimozione permessi ereditati e assegnazione controllo completo a $CurrentUserIdentity..." -ForegroundColor Yellow
    icacls $ScanFolder /inheritance:r /grant "${CurrentUserIdentity}:(OI)(CI)F" /T | Out-Null
    
    if ($DomainMode) {
        Write-Host "[INFO] Aggiunta permessi Modifica per utente scanner (Dominio)..." -ForegroundColor Yellow
        # Utente Scanner (Dominio): Modifica (M) -> Lettura/Scrittura
        icacls $ScanFolder /grant "${CurrentDomain}\${ScanUser}:(OI)(CI)M" /T | Out-Null
    }
    else {
        Write-Host "[INFO] Aggiunta permessi Modifica per utente scanner (Locale)..." -ForegroundColor Yellow
        # Utente Scanner (Locale): Modifica (M) -> Lettura/Scrittura
        icacls $ScanFolder /grant "${ScanUser}:(OI)(CI)M" /T | Out-Null
    }
    
    Write-Host "[OK] Permessi NTFS configurati: Solo $CurrentUserIdentity e Scanner hanno accesso" -ForegroundColor Green
}
catch {
    Write-Host "[ATTENZIONE] Possibili problemi con i permessi NTFS: $($_.Exception.Message)" -ForegroundColor Yellow
}

# STEP 4: Condivisione cartella
Write-Host ""
Write-Host "[STEP 4] Configurazione condivisione di rete" -ForegroundColor Cyan
Write-Host "[INFO] Rimozione condivisioni esistenti..." -ForegroundColor Yellow

# Rimuovi condivisione esistente
try {
    Remove-SmbShare -Name "Scansioni" -Force -ErrorAction SilentlyContinue
}
catch {
    # Ignora errori se la condivisione non esiste
}

Write-Host "[INFO] Creazione nuova condivisione con accesso ristretto..." -ForegroundColor Yellow
try {
    # Per la condivisione, dobbiamo assicurarci che l'utente corrente sia incluso
    if (-not $CurrentUserIdentity) {
        $CurrentUserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }

    if ($DomainMode) {
        # Share permissions: Full Control to Current User and Scanner ONLY
        New-SmbShare -Name "Scansioni" -Path $ScanFolder -FullAccess @("${CurrentDomain}\${ScanUser}", "$CurrentUserIdentity") | Out-Null
    }
    else {
        # Share permissions: Full Control to Current User and Scanner ONLY
        New-SmbShare -Name "Scansioni" -Path $ScanFolder -FullAccess @("$ScanUser", "$CurrentUserIdentity") | Out-Null
    }
    Write-Host "[OK] Condivisione creata (Accesso: $CurrentUserIdentity, Scanner)" -ForegroundColor Green
}
catch {
    Write-ErrorAndExit "Impossibile creare la condivisione: $($_.Exception.Message)"
}

# STEP 5: Creazione collegamento desktop
Write-Host ""
Write-Host "[STEP 5] Creazione collegamento desktop" -ForegroundColor Cyan

try {
    $ShortcutPath = Join-Path $DesktopPath "Scansioni.lnk"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $ScanFolder
    $Shortcut.Save()
    Write-Host "[OK] Collegamento creato sul desktop" -ForegroundColor Green
}
catch {
    Write-Host "[ATTENZIONE] Impossibile creare il collegamento: $($_.Exception.Message)" -ForegroundColor Yellow
}

# STEP 6: Configurazione SMB
Write-Host ""
Write-Host "[STEP 6] Configurazione protocollo SMB" -ForegroundColor Cyan
Write-Host "[INFO] Attivazione SMB 1.0/CIFS..." -ForegroundColor Yellow

try {
    # Abilita SMB 1.0 usando DISM
    Write-Host "[INFO] Abilitazione SMB 1.0 Client..." -ForegroundColor Yellow
    $null = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/enable-feature", "/featurename:SMB1Protocol-Client", "/all", "/norestart" -Wait -WindowStyle Hidden
    
    Write-Host "[INFO] Abilitazione SMB 1.0 Server..." -ForegroundColor Yellow
    $null = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/enable-feature", "/featurename:SMB1Protocol-Server", "/all", "/norestart" -Wait -WindowStyle Hidden
    
    # Configurazione registro per SMB 1.0
    Write-Host "[INFO] Configurazione servizi SMB 1.0..." -ForegroundColor Yellow
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Disabilita rimozione automatica SMB 1.0
    Write-Host "[INFO] Disabilitazione rimozione automatica SMB 1.0..." -ForegroundColor Yellow
    
    # CHIAVE PRINCIPALE: Disabilita la spunta "Rimozione automatica SMB 1.0" in Programmi e Funzionalità
    $SMBAutoRemovalKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    Set-ItemProperty -Path $SMBAutoRemovalKey -Name "SMB1" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Disabilita esplicitamente l'auto-removal di SMB 1.0
    $OptionalFeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OptionalFeatures"
    if (-not (Test-Path $OptionalFeaturesPath)) {
        New-Item -Path $OptionalFeaturesPath -Force | Out-Null
    }
    
    # Chiave specifica per SMB 1.0 auto-removal
    $SMB1AutoRemovalPath = "$OptionalFeaturesPath\SMB1Protocol"
    if (-not (Test-Path $SMB1AutoRemovalPath)) {
        New-Item -Path $SMB1AutoRemovalPath -Force | Out-Null
    }
    Set-ItemProperty -Path $SMB1AutoRemovalPath -Name "AutoRemoval" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    
    # Configurazione tramite DISM per disabilitare auto-removal
    Write-Host "[INFO] Configurazione DISM per prevenire auto-removal..." -ForegroundColor Yellow
    try {
        # Usa DISM per configurare la feature senza auto-removal
        $null = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/enable-feature", "/featurename:SMB1Protocol", "/all", "/norestart" -Wait -WindowStyle Hidden
        
        # Configura il registro per impedire la rimozione automatica
        $WindowsFeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing"
        if (-not (Test-Path $WindowsFeaturesPath)) {
            New-Item -Path $WindowsFeaturesPath -Force | Out-Null
        }
        Set-ItemProperty -Path $WindowsFeaturesPath -Name "LocalSourcePath" -Value "" -Type String -ErrorAction SilentlyContinue
        
        # Impedisce Windows Update di rimuovere SMB 1.0
        $ComponentBasedServicingPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
        Set-ItemProperty -Path $ComponentBasedServicingPath -Name "DisableWUfBAutoScan" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        
    }
    catch {
        Write-Host "[ATTENZIONE] Impossibile configurare DISM per auto-removal: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Configurazione aggiuntiva per Windows 10/11
    $SMBClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
    Set-ItemProperty -Path $SMBClientPath -Name "Start" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $SMBClientPath -Name "AutoRemoval" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    
    Write-Host "[OK] SMB 1.0 configurato e protetto dalla rimozione automatica" -ForegroundColor Green
}
catch {
    Write-Host "[ATTENZIONE] Possibili problemi con la configurazione SMB: $($_.Exception.Message)" -ForegroundColor Yellow
}

# STEP 7: Configurazione Firewall
Write-Host ""
Write-Host "[STEP 7] Configurazione regole Firewall" -ForegroundColor Cyan
Write-Host "[INFO] Abilitazione condivisione file e stampanti..." -ForegroundColor Yellow

try {
    # Abilita regole firewall per condivisione file
    Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True -ErrorAction SilentlyContinue
    Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -ErrorAction SilentlyContinue
    
    Write-Host "[OK] Regole firewall configurate" -ForegroundColor Green
}
catch {
    Write-Host "[ATTENZIONE] Possibili problemi con la configurazione firewall: $($_.Exception.Message)" -ForegroundColor Yellow
}

# STEP 8: Riepilogo finale
Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "    CONFIGURAZIONE COMPLETATA" -ForegroundColor Cyan
# Rileva indirizzo IP del computer
Write-Host "[INFO] Rilevamento indirizzo IP..." -ForegroundColor Yellow
try {
    # Metodo 1: Ottieni IP dell'interfaccia di rete attiva
    $NetworkAdapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.MediaType -eq "802.3" } | Select-Object -First 1
    if ($NetworkAdapter) {
        $IPAddress = (Get-NetIPAddress -InterfaceIndex $NetworkAdapter.InterfaceIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" }).IPAddress
    }
    
    # Metodo 2: Fallback con WMI se il primo metodo fallisce
    if (-not $IPAddress) {
        $IPAddress = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.DefaultIPGateway -ne $null }).IPAddress | Where-Object { $_ -notlike "169.254.*" -and $_ -ne "127.0.0.1" } | Select-Object -First 1
    }
    
    # Metodo 3: Ultimo fallback con Test-Connection
    if (-not $IPAddress) {
        $IPAddress = (Test-Connection -ComputerName $env:COMPUTERNAME -Count 1).IPV4Address.IPAddressToString
    }
    
    if (-not $IPAddress) {
        $IPAddress = "Non rilevato"
    }
}
catch {
    $IPAddress = "Errore rilevamento"
}

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "RIEPILOGO CONFIGURAZIONE:" -ForegroundColor White
Write-Host "-------------------------" -ForegroundColor White
Write-Host "Cartella scansioni: $ScanFolder" -ForegroundColor Yellow
Write-Host "Condivisione di rete: \\$env:COMPUTERNAME\Scansioni" -ForegroundColor Yellow
Write-Host "Indirizzo IP computer: $IPAddress" -ForegroundColor Yellow

if ($DomainMode) {
    Write-Host "Modalita: Dominio ($CurrentDomain)" -ForegroundColor Yellow
    Write-Host "Utente scanner: $CurrentDomain\$ScanUser" -ForegroundColor Yellow
    Write-Host "Utente verificato: SI (dominio)" -ForegroundColor Green
}
else {
    Write-Host "Modalita: Locale (WORKGROUP)" -ForegroundColor Yellow
    Write-Host "Utente scanner: $env:COMPUTERNAME\$ScanUser" -ForegroundColor Yellow
    Write-Host "Utente verificato: SI (locale)" -ForegroundColor Green
}

Write-Host "Password utente: $ScanPasswordPlain" -ForegroundColor Yellow
Write-Host "SMB 1.0: Attivato" -ForegroundColor Green
Write-Host "Firewall: Configurato" -ForegroundColor Green
Write-Host "Collegamento desktop: Creato" -ForegroundColor Green
Write-Host ""
Write-Host "INFORMAZIONI PER LO SCANNER:" -ForegroundColor White
Write-Host "---------------------------" -ForegroundColor White
Write-Host "Percorso di rete: \\$env:COMPUTERNAME\Scansioni" -ForegroundColor Cyan
Write-Host "Percorso IP alternativo: \\$IPAddress\Scansioni" -ForegroundColor Cyan
Write-Host "Indirizzo IP: $IPAddress" -ForegroundColor Cyan

if ($DomainMode) {
    Write-Host "Username: $CurrentDomain\$ScanUser" -ForegroundColor Cyan
    Write-Host "(Formato alternativo: $ScanUser@$CurrentDomain)" -ForegroundColor Gray
}
else {
    Write-Host "Username: $ScanUser" -ForegroundColor Cyan
    Write-Host "(Formato alternativo: $env:COMPUTERNAME\$ScanUser)" -ForegroundColor Gray
}

Write-Host "Password: $ScanPasswordPlain" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Riavvio consigliato per completare la configurazione SMB" -ForegroundColor Yellow
Write-Host ""

# Opzione riavvio
do {
    $RebootChoice = Read-Host "Riavviare ora? [S/N]"
} while ($RebootChoice -notin @("S", "s", "N", "n", ""))

if ($RebootChoice -in @("S", "s")) {
    Write-Host ""
    Write-Host "Riavvio programmato in 10 secondi..." -ForegroundColor Yellow
    Write-Host "Premere Ctrl+C per annullare se necessario" -ForegroundColor Yellow
    
    try {
        # Usa il cmdlet PowerShell nativo per il riavvio
        Restart-Computer -Delay 10 -Force -Confirm:$false
    }
    catch {
        # Fallback con shutdown.exe se Restart-Computer fallisce
        try {
            & shutdown.exe /r /t 10 /c "Riavvio per completare configurazione Scan to Folder"
            Write-Host ""
            Write-Host "Attendere il riavvio automatico..." -ForegroundColor Yellow
        }
        catch {
            Write-Host "[ERRORE] Impossibile programmare il riavvio: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
else {
    Write-Host ""
    Write-Host "[IMPORTANTE] Ricorda di riavviare il sistema per completare la configurazione SMB" -ForegroundColor Yellow
    Write-Host ""
}

# Fine script
Write-Host ""
Write-Host "===============================================" -ForegroundColor Green
Write-Host "    CONFIGURAZIONE COMPLETATA CON SUCCESSO" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Lo script PowerShell ha terminato l'esecuzione." -ForegroundColor White
Write-Host "Premere Enter per chiudere questa finestra..." -ForegroundColor White
Read-Host
