# This code is VERY VERY VERY heavily based on Great Dismal (https://blob.pureandapplied.com.au/greatdismal/)
# Check out stibinator's original work on github: https://github.com/stibinator/GreatDismal


function get-RedditLockscreen{
    param (
    [string[]]$subreddits = @(),
    [string]$redditpicFolder = (join-path $env:APPDATA "\reddit_backgrounds\"),
    [int]$nsfw = 0,
    [string]$sort = "new",
    [string]$logfile = (join-path $redditpicFolder "log.txt"),
    [string]$cfgfile = (join-path $redditpicFolder "config.json"),
    [switch]$showpic,
    [switch]$showlog,
    [switch]$config,
    [switch]$uninstall
    )

    # do the stuffs
    # installation hoo-hah
    if (! (test-path $redditpicFolder)){mkdir $redditpicFolder}
    if (! (test-path $cfgfile)){set-content $cfgfile '{ "subreddits":["wallpaper"], "nsfw":0, "sort":"new" }'}
    $redditPic = Join-Path $redditpicFolder "redditPic.jpg"

    if ($install){
        install-RedditLockscreen -subreddits $subreddits -redditpicFolder $redditpicFolder -scriptPath $scriptPath -nsfw $nsfw;
    } elseif ($showpic) {
        #user wants to see the current pic
        Invoke-Item $redditPic
    } elseif ($showLog){
        #user wants to see the log
        Get-Content $logfile
    } elseif ($uninstall){
        #user wants to see the log
        uninstall-RedditLockscreen -redditpicFolder $redditpicFolder;
    } elseif ($config){
        #user wants to see the log
        Invoke-Item $cfgfile;
    }else {
        #get the pic and set the screen
        if($subreddits -eq @()){
            $cfg = Get-Content $cfgfile | ConvertFrom-Json;
            $subreddits = $cfg.subreddits;
            $nsfw = $cfg.nsfw;
            $sort = $cfg.sort;
        }
        get-redditPicFortheDay -subreddits $subreddits -redditPic $redditPic -nsfw $nsfw -logfile $logfile -sort $sort;
    }
}

function get-redditPicFortheDay {
    param (
    [string[]]$subreddits = @(),
    [string]$redditPic,
    [int]$nsfw = 0,
    [string]$logfile,
    [string]$sort
    )
    Write-Host "getting a new background"

    if ($subreddits.Length -eq 0){
        $subreddits = @(
        "wallpaper"
        );
    }
    $subredditfortheday = $subreddits[(Get-Random($subreddits.Length))];
    $result = Invoke-RestMethod -URi  ("https://www.reddit.com/r/{0}/{1}.json?limit=10" -f $subredditfortheday, $sort) -Method Get;
    $result = $result.data.children | Sort-Object {Get-Random};

    write-Log ("looking for pics on {0}, found {1}" -f $subredditfortheday,  $result.length) -logFile $logfile

    foreach ($child in $result){
        $post = $child.data
        if ((! $post.over_18) -or $nsfw){
            if($post.post_hint = "image"){
                $photoURL = $post.url;
                $photoTitle = $post.title;
                $photoAuthor= $post.author;
                break;
            }
        }
    }
    if ($photoURL){
        Write-Host ("Attempting to download at: {0}" -f $photoURL);
        (New-Object Net.webclient).DownloadFile($photoURL, $redditPic);
        Set-LockscreenWallpaper -LockScreenImageValue $redditPic;
        write-Log ("downloaded `"{0}`" at {1} posted by {2}" -f $photoTitle, $photoURL, $photoAuthor) -logFile $logfile;
    }
    else {
        Write-Host ("Did not find anything on " -f $subredditfortheday);
    }

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

function install-RedditLockscreen {
    param(
    [string]$redditpicFolder = (join-path $env:APPDATA "\reddit_backgrounds\"),
    [string]$logfile = (join-path $env:APPDATA "\reddit_backgrounds\log.txt")
    )
    # check to see if user is admin
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        # is admin, we're good to install
        $divider = "`n" + ("-" * (Get-Host).ui.rawui.windowsize.width) + "`n"; # trick to make a row of dashes the width of the window
        write-host ($divider) -foregroundColor "yellow"
        Write-Host "This will install RedditLockscreen on your machine and it will download a random reddit login screen every day" -ForegroundColor DarkYellow
        Write-Host "Note that the contents of the pictures are beyond the control of the developer, and may be " -NoNewline -ForegroundColor DarkYellow
        Write-Host "unsafe for work." -ForegroundColor DarkYellow -BackgroundColor DarkRed
        write-host ($divider) -foregroundColor "yellow"

        # define the workstation unlock as the trigger
        $trigger = New-ScheduledTaskTrigger -Daily -At 12pm;

        # Create a task scheduler event
        $argument = "-WindowStyle Hidden -command `"import-module 'RedditLockscreen'; get-RedditLockscreen -logfile {0} -redditpicFolder {1}" -f $logfile, $redditpicFolder
        $action = New-ScheduledTaskAction -id "redditLockscreen" -execute 'Powershell.exe' -Argument $argument
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable
        Write-Host "For this script to work it needs elevated privileges." -BackgroundColor DarkBlue
        $Credential = Test-Credential
        if ($Credential){
            # actually install the shiz
            Write-Host "Username checks out." -ForegroundColor Green
            write-Log "Unregistering existing scheduled task" -logfile $logfile
            Unregister-ScheduledTask -TaskName "redditLock" -ErrorAction SilentlyContinue
            Register-ScheduledTask `
            -TaskName "redditLockscreen" `
            -User $Credential.username `
            -Action $action `
            -Settings $settings `
            -Trigger $trigger -RunLevel Highest `
            -Password $Credential.GetNetworkCredential().Password `
            -taskPath "\reddit_backgrounds\"
        }
        if ($? -and (Get-ScheduledTask -TaskName "redditLockscreen" -ErrorAction SilentlyContinue)){
            write-Log "RedditLockscreen is installed" -colour "Green" -logFile $logfile
        } else {
            throw "Bollocks. Something went wrong. Computers suck."
        }
    }  else {
        # not admin
        Write-Host "You need run this script as an Admin to install it" -BackgroundColor Red -ForegroundColor Yellow
        throw "Computer says no."
    }
}

function uninstall-RedditLockscreen {
    param(
        [string]$redditpicFolder
    )
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        $RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
        remove-item -Path $RegKeyPath -Force -Recurse| Out-Null;
        Unregister-ScheduledTask -TaskName "redditLock" -ErrorAction SilentlyContinue;
        Remove-Item  $redditpicFolder -Recurse -ErrorAction SilentlyContinue;
        $scriptPath = (get-item $myInvocation.ScriptName).Directory
        # remove-module doesn't seem to work for psgallery modules. So we do it manually
        # just check that we're actually removing the greatdismal folder
        if ($scriptPath.name -eq "RedditLockscreen"){
            Write-host "You have to manually remove the module now. Just delete the RedditLockscreen folder." -BackgroundColor Yellow -ForegroundColor Red
            Invoke-Item $scriptPath; #open the folder containing the module folder (usually ~\Documents\WindowsPowershell\Modules)
        }
    } else {
        Write-host "you need to run this script as admin to uninstall it" -BackgroundColor Red -ForegroundColor Yellow
        throw "Computer says no."
    }

}
function Test-Credential {
    # check password, allowing multiple attemps
    $againWithThePassword = $true;
    $usernameChecksOut = $false;
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$env:COMPUTERNAME)

    while ((! $usernameChecksOut) -and $againWithThePassword){
        $Credential = Get-Credential -ErrorAction SilentlyContinue
        if ($null -eq $Credential){
            Write-Warning "You didn't give me any credentials. I can't help you if you won't help me."
            $againWithThePassword = ((read-host "Again with the password? Y/n").ToLower() -ne "n")
        } else {
            $usernameChecksOut = $DS.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().Password)
            if ($usernameChecksOut){
                return $Credential
            } else {
                Write-Warning "Username and / or password is incorrect. Soz.";
                $againWithThePassword = ((read-host "Again with the password? Y/n").ToLower() -eq "n")
            }
        }
        if (! $againWithThePassword){
            return $false
        }
        Start-Sleep 1
    }
}

function write-Log  {
    param (
    [string]$Msg,
    [string]$colour = "White",
    [string]$logfile
    )

    if (($null -ne $logfile) -and ("" -ne $logfile)){
        $date = Get-date -f "dd/MM/yyyy HH:mm:ss"
        if (! (test-path $logfile )){set-content $logfile "Reddit Lock Log"}
        # trim the log if it gets too long 64k is long enough right?
        if ((get-item $logfile).length -gt 64kb){
            # get the last 20 lines
            $oldlog = (Get-Content $logfile)[-20..-1]
            Set-Content $logfile ("Reddit Lock Log`n" + $date + "-> " + "Trimmed log")
            Add-Content $logfile $oldlog
        }
        add-content $logfile ("" + $date + "-> " + $msg)
    }
    Write-Host $Msg -foregroundColor $colour
}