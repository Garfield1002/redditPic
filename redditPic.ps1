
function get-DismalLockscreen{
    param (
    [string[]]$subreddits = @(),
    [string]$dismalFolder = (join-path $env:APPDATA "\reddit_backgrounds\"),
    [int]$nsfw = 0,
    [switch]$showpic
    )

    # do the stuffs
    # installation hoo-hah
    if (! (test-path $dismalFolder)){mkdir $dismalFolder}
    $redditPic = Join-Path $dismalFolder "greatDismal.jpg"

    if ($install){
        install-GreatDismal -subreddits $subreddits -dismalFolder $dismalFolder -scriptPath $scriptPath -nsfw $nsfw;
    }

    if ($showpic) {
        #user wants to see the current pic
        Invoke-Item $redditPic
    } else {
        #get the pic and set the screen
        get-redditPicFortheDay -subreddits $subreddits -redditPic $redditPic -nsfw $nsfw;
    }
}

function get-redditPicFortheDay {
    param (
    [string[]]$subreddits = @(),
    [string]$redditPic,
    [int]$nsfw = 0
    )
    Write-Host "getting a new background"

    if ($subreddits.Length -eq 0){
        $subreddits = @(
        "WarplanePorn",
        "TankPorn"
        );
    }
    $picfortheday = $subreddits[(Get-Random($subreddits.Length))];
    $result = Invoke-RestMethod -URi  ("https://www.reddit.com/r/{0}/new.json?limit=25" -f $picfortheday) -Method Get;
    $result = $result.data.children | Sort-Object {Get-Random};
    foreach ($child in $result){
        $post = $child.data
        if ((! $post.over_18) -or $nsfw){
            if($post.post_hint = "image"){
                $photogURL = $post.url;
                break;
            }
        }
    }
    Write-Host ("Attempting to download at: {0}" -f $photogURL)
    (New-Object Net.webclient).DownloadFile($photogURL, $redditPic)

    Set-LockscreenWallpaper -LockScreenImageValue $redditPic;
}

function Set-LockscreenWallpaper {
    # this was adapted from
    # https://abcdeployment.wordpress.com/2017/04/20/how-to-set-custom-backgrounds-for-desktop-and-lockscreen-in-windows-10-creators-update-v1703-with-powershell/
    # The Script sets custom background Images for the Lock Screen by leveraging the new feature of PersonalizationCSP that is only available in
    # the Windows 10 v1703 aka Creators Update and later build versions #
    # Applicable only for Windows 10 v1703 and later build versions #

    param(
    [string]$LockScreenImageValue
    )

    $RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"

    $LockScreenPath = "LockScreenImagePath"
    $LockScreenStatus = "LockScreenImageStatus"
    $LockScreenUrl = "LockScreenImageUrl"
    $StatusValue = "1"

    If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){

        IF(!(Test-Path $RegKeyPath))
        
        {
            
            New-Item -Path $RegKeyPath -Force | Out-Null
            
            New-ItemProperty -Path $RegKeyPath -Name $LockScreenStatus -Value $StatusValue -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $RegKeyPath -Name $LockScreenPath -Value $LockScreenImageValue -PropertyType STRING -Force | Out-Null
            New-ItemProperty -Path $RegKeyPath -Name $LockScreenUrl -Value $LockScreenImageValue -PropertyType STRING -Force | Out-Null
            
        }
        
        ELSE {
            
            New-ItemProperty -Path $RegKeyPath -Name $LockScreenStatus -Value $value -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $RegKeyPath -Name $LockScreenPath -Value $LockScreenImageValue -PropertyType STRING -Force | Out-Null
            New-ItemProperty -Path $RegKeyPath -Name $LockScreenUrl -Value $LockScreenImageValue -PropertyType STRING -Force | Out-Null
        }
    }
}

function install-GreatDismal {
    param(
    [string]$dismalFolder = (join-path $env:APPDATA "\great dismal\"),
    [bool]$nsfw = $FALSE,
    [string[]]$subreddits = @()
    )
    # check to see if user is admin
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        # is admin, we're good to install
        $divider = "`n" + ("-" * (Get-Host).ui.rawui.windowsize.width) + "`n"; # trick to make a row of dashes the width of the window
        write-host ($divider) -foregroundColor "yellow"
        Write-Host "This will install GreatDismal on your machine and it will download a random dismal login screen every time you log in" -ForegroundColor DarkYellow
        Write-Host "Note that the contents of the pictures are beyond the control of the developer, and may be " -NoNewline -ForegroundColor DarkYellow
        Write-Host "unsafe for work." -ForegroundColor DarkYellow -BackgroundColor DarkRed
        write-host ($divider) -foregroundColor "yellow"

        # define the workstation unlock as the trigger
        $stateChangeTrigger = Get-CimClass -Namespace ROOT\Microsoft\Windows\TaskScheduler -ClassName MSFT_TaskSessionStateChangeTrigger
        $trigger = New-CimInstance -CimClass $stateChangeTrigger -Property @{
            StateChange = 8  # TASK_SESSION_STATE_CHANGE_TYPE.TASK_SESSION_UNLOCK (taskschd.h)
        } -ClientOnly
        
        # Create a task scheduler event
        $argument = "-WindowStyle Hidden -command `"import-module 'GreatDismal'; get-DismalLockscreen -logfile {0} -dismalFolder {1}{2}{3}{4}{5}`"" -f `
            $logfile, `
            $dismalFolder, `
            $(if ($adjectives.Length -gt 0){" -adjectives ({0})" -f ($adjectives -join ", ")} else {""}), `
            $(if ($nouns.Length -gt 0){" -nouns ({0})" -f ($nouns -join ", ")} else {""}), `
            $(if ($phoneHome){" -checkForUpdates"} else {""}), `
            $(if ($safeSearch -gt 0){" -safeSearch " + $safeSearch} else {""})
        $action = New-ScheduledTaskAction -id "GreatDismal" -execute 'Powershell.exe' -Argument $argument
        $settings = New-ScheduledTaskSettingsSet -Hidden -StartWhenAvailable -RunOnlyIfNetworkAvailable
        Write-Host "for this script to work it needs elevated privileges" -BackgroundColor DarkBlue
        $Credential = Test-Credential
        if ($Credential){
            # actually install the shiz
            Write-Host "Username checks out." -ForegroundColor Green
            write-GDLog "Unregistering existing scheduled task" -logfile $logfile -nolog $nolog
            Unregister-ScheduledTask -TaskName "greatDismal" -ErrorAction SilentlyContinue
            Register-ScheduledTask `
            -TaskName "greatDismal" `
            -User $Credential.username `
            -Action $action `
            -Settings $settings `
            -Trigger $trigger -RunLevel Highest `
            -Password $Credential.GetNetworkCredential().Password `
            -taskPath "\pureandapplied\"
        }
        if ($? -and (Get-ScheduledTask -TaskName "GreatDismal" -ErrorAction SilentlyContinue)){
            write-GDLog "GreatDismal is installed" -colour "Green" -logFile $logfile -nolog $nolog
        } else {
            throw "Bollocks. Something went wrong. Computers suck."
        }
    }  else {
        # not admin
        Write-Host "You need run this script as an Admin to install it" -BackgroundColor Red -ForegroundColor Yellow
        throw "Computer says no."
    }
}

function uninstall-GreatDismal {
    param(
    [string]$logfile,
    [string]$dismalFolder
    )
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        $RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
        remove-item -Path $RegKeyPath -Force -Recurse| Out-Null;
        Unregister-ScheduledTask -TaskName "greatDismal" -ErrorAction SilentlyContinue;
        Remove-Item  $dismalFolder -Recurse -ErrorAction SilentlyContinue;
        $scriptPath = (get-item $myInvocation.ScriptName).Directory
        # remove-module doesn't seem to work for psgallery modules. So we do it manually
        # just check that we're actually removing the greatdismal folder
        if ($scriptPath.name -eq "GreatDismal"){
            Write-host "You have to manually remove the module now. Just delete the GreatDismal folder." -BackgroundColor Yellow -ForegroundColor Red
            Invoke-Item $scriptPath; #open the folder containing the module folder (usually ~\Documents\WindowsPowershell\Modules)
        }
    } else {
        Write-host "you need to run this script as admin to uninstall it" -BackgroundColor Red -ForegroundColor Yellow
        throw "Computer says no."
    }

}