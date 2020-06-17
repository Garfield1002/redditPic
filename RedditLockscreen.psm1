# This code is heavily based on Great Dismal (https://blob.pureandapplied.com.au/greatdismal/)
# Check out stibinator's original work on github: https://github.com/stibinator/GreatDismal


# The main function
function RedditLockscreen{
    param (
    [string[]]$subreddit = @(),
    [switch]$nsfw,
    [string]$sort,
    [string]$localFolder = (join-path $env:APPDATA "\Reddit backgrounds\"),
    [string]$logfile = (join-path $localFolder "log.txt"),
    [string]$cfgfile = (join-path $localFolder "config.json"),
    [switch]$install,
    [switch]$showpic,
    [switch]$showlog,
    [switch]$config,
    [switch]$uninstall,
    [switch]$list,
    [string[]]$add= @(),
    [string[]]$remove= @(),
    [switch]$help
    )

    # if the folder where the images will be stored does not exists, creates one
    if (! (test-path $localFolder)){mkdir $localFolder}
    # if the config file is missing initializes a new one
    if (! (test-path $cfgfile)){set-content $cfgfile '{ "subreddits":["wallpaper"], "nsfw":0, "sort":"new" }'}
    $redditPic = Join-Path $localFolder "redditPic.jpg"

    if ($install)       { install-RedditLockscreen }
    elseif ($help)      {funHelp}
    elseif ($showpic)   { Invoke-Item $redditPic }
    elseif ($showLog)   { Get-Content $logfile }
    elseif ($uninstall) { uninstall-RedditLockscreen -localFolder $localFolder}
    elseif ($config)    { Invoke-Item $cfgfile }
    elseif ($list)      {$cfg = Get-Content $cfgfile | ConvertFrom-Json; Write-Host 'Current Subreddits: '-ForegroundColor Yellow -BackgroundColor Black; Write-Host $cfg.subreddits -BackgroundColor Black}
    elseif ($add.Length -ne 0){
        $cfg = Get-Content $cfgfile | ConvertFrom-Json;
        $cfg.subreddits += $add.ToLower();
        $cfg.subreddits = $cfg.subreddits | Select-Object -Unique;
        set-content $cfgfile ($cfg | ConvertTo-Json);
        Write-Host ('Successfuly added {0} to your subreddits'-f $add) -ForegroundColor Green -BackgroundColor Black;
    } elseif ($remove.Length -ne 0){
        $cfg = Get-Content $cfgfile | ConvertFrom-Json;
        $cfg.subreddits -= $cfg.subreddits | Where-Object { ! ($remove -contains $_)};
        set-content $cfgfile ($cfg | ConvertTo-Json);
        Write-Host ('Successfuly removed {0} from your subreddits'-f $remove) -ForegroundColor Green -BackgroundColor Black;
    } else {
        # finds a post to use as lock screen
        Write-Host "fetching a post"

        # if no subreddits where specified, loads the config
        $cfg = Get-Content $cfgfile | ConvertFrom-Json;
        if($subreddit.Length -eq 0){$subreddit = $cfg.subreddits;}
        if(!$nsfw){$nsfw = ($cfg.nsfw -eq 1);}
        if($null -eq $sort){$sort = $cfg.sort;}

        # chooses a random subreddit to load the post from
        $subredditfortheday = $subreddit[(Get-Random($subreddit.Length))];

        # shuffles the 10 first results
        $result = Invoke-RestMethod -URi  ("https://www.reddit.com/r/{0}/{1}.json?limit=10" -f $subredditfortheday, $sort) -Method Get;
        $result = $result.data.children | Sort-Object {Get-Random};

        foreach ($child in $result){
            $post = $child.data
            # checks if the user accepts nsfw content
            if ((! $post.over_18) -or $nsfw){
                if($post.post_hint = "image"){
                    # saves the information from th future lock screen
                    $photoURL = $post.url;
                    $photoTitle = $post.title;
                    $photoAuthor= $post.author;
                    break;
                }
            }
        }
        if ($photoURL){
            Write-Host ("Attempting to download at: {0}" -f $photoURL);
            # downloads the picture
            (New-Object Net.webclient).DownloadFile($photoURL, $redditPic);
            # sets the lockscreen wallpaper
            Set-LockscreenWallpaper -LockScreenImageValue $redditPic;
            logger ("Sucessfully downloaded `"{0}`" at {1} posted by {2} on {3}" -f $photoTitle, $photoURL, $photoAuthor, $subredditfortheday) -logFile $logfile;
        }
        else {
            Write-Host ("Nothing was found on {0} matching your requirements" -f $subredditfortheday);
        }
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
    [string]$localFolder = (join-path $env:APPDATA "\Reddit backgrounds\"),
    [string]$logfile = (join-path $env:APPDATA "\Reddit backgrounds\log.txt")
    )
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){

        $str = @('
        8888888b.               888      888 d8b 888         888                       888
        888   Y88b              888      888 Y8P 888         888                       888
        888    888              888      888     888         888                       888
        888   d88P .d88b.   .d88888  .d88888 888 888888      888      .d88b.   .d8888b 888  888 .d8888b   .d8888b 888d888 .d88b.   .d88b.  88888b.
        8888888P" d8P  Y8b d88" 888 d88" 888 888 888         888     d88""88b d88P"    888 .88P 88K      d88P"    888P"  d8P  Y8b d8P  Y8b 888 "88b
        888 T88b  88888888 888  888 888  888 888 888         888     888  888 888      888888K  "Y8888b. 888      888    88888888 88888888 888  888
        888  T88b Y8b.     Y88b 888 Y88b 888 888 Y88b.       888     Y88..88P Y88b.    888 "88b      X88 Y88b.    888    Y8b.     Y8b.     888  888
        888   T88b "Y8888   "Y88888  "Y88888 888  "Y888      88888888 "Y88P"   "Y8888P 888  888  88888P"  "Y8888P 888     "Y8888   "Y8888  888  888

        ')
        Write-Host $str -ForegroundColor Green
        #write-host ("Author: Garfield1002")
        write-host ("Source Code: https://github.com/Garfield1002/redditPic")
        Write-Host
        Write-Host ("This script will install RedditLockscreen on your machine and will download random reddit login screens for you")-ForegroundColor 2
        Write-Host ("Once installed, use the command ") -ForegroundColor 2 -NoNewline
        Write-Host ("RedditLockscreen -help") -BackgroundColor DarkGray -NoNewline
        Write-Host (" for help") -ForegroundColor 2
        Write-Host ("These images are downloaded directly from reddit so use at your own risk") -ForegroundColor 2
        Write-Host

        # define the workstation unlock as the trigger
        # $trigger = New-ScheduledTaskTrigger -Daily -At 12pm;

        # create a task scheduler event
        $argument = "-WindowStyle Hidden -command `"import-module 'RedditLockscreen'; RedditLockscreen -logfile {0} -localFolder {1}" -f $logfile, $localFolder

        # prompts the user for an administrator access
        Write-Host "For this script to work it needs elevated privileges." -BackgroundColor DarkBlue
        $Credential = Test-Credential

        if ($Credential){
            Write-Host "Username checks out." -ForegroundColor Green

            # if a previous task existed, unregisters it
            logger "Unregistering existing scheduled task" -logfile $logfile
            Unregister-ScheduledTask -TaskName "redditLock" -ErrorAction SilentlyContinue

            # adds a new task to the task scheduler which will be called whenever the user logs on
            Register-ScheduledTask `
            -TaskName   "redditLockscreen" `
            -User       $Credential.username `
            -Action     (New-ScheduledTaskAction -id "redditLockscreen" -execute 'Powershell.exe' -Argument $argument)`
            -Settings   (New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable) `
            -Trigger    (New-ScheduledTaskTrigger -AtLogOn) `
            -RunLevel   Highest `
            -Password   $Credential.GetNetworkCredential().Password `
            -taskPath   "\Reddit backgrounds\";
            RedditLockscreen
        }
        if ($? -and (Get-ScheduledTask -TaskName "redditLockscreen" -ErrorAction SilentlyContinue)){
            logger "RedditLockscreen has sucessfuly been installed" -colour "Green" -logFile $logfile
        } else {
            throw "Installation failed"
        }
    }  else {
        Write-Host "You need run this script as an Admin to install it" -ForegroundColor Red
        throw "Call an admin"
    }
}

function uninstall-RedditLockscreen {
    param(
        [string]$localFolder
    )
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        # reverts the changes that where done in the registry
        $RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
        remove-item -Path $RegKeyPath -Force -Recurse| Out-Null;
        Unregister-ScheduledTask -TaskName "redditLock" -ErrorAction SilentlyContinue;

        # Deletes the local folders including background, cfg and log
        Remove-Item  $localFolder -Recurse -ErrorAction SilentlyContinue;

        # Manually removes the module
        $scriptPath = (get-item $myInvocation.ScriptName).Directory
        if ($scriptPath.name -eq "RedditLockscreen"){
            Write-host "You have to manually remove the module now. Just delete the RedditLockscreen folder." -ForegroundColor Red
            Invoke-Item $scriptPath;
        }
    } else {
        # user is missing admin rights
        Write-host "You need administrator rights to uninstall this script" -ForegroundColor Red
        throw "Call an admin!"
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
            Write-Warning "Please enter something"
            $againWithThePassword = ((read-host "Try again with the password? Y/n").ToLower() -ne "n")
        } else {
            $usernameChecksOut = $DS.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().Password)
            if ($usernameChecksOut){
                return $Credential
            } else {
                Write-Warning "Username and / or password is incorrect.";
                $againWithThePassword = ((read-host "Try again with the password? Y/n").ToLower() -eq "n")
            }
        }
        if (! $againWithThePassword){
            return $false
        }
        Start-Sleep 1
    }
}

function logger  {
    param (
    [string]$Msg,
    [string]$logfile
    )
    if (($null -ne $logfile) -and ("" -ne $logfile)){
        $date = Get-date -f "dd/MM/yyyy HH:mm:ss"
        if (! (test-path $logfile )){set-content $logfile "Reddit Lock Log"}
        add-content $logfile ("" + $date + ": " + $msg)
    }
}

function funHelp {
    Write-Host
    Write-Host 'This is a listing of everything you can pass to RedditLockscreen' -BackgroundColor Black
    Write-Host
    Write-Host('Usage: RedditLockscreen [-help] [-install] [-showpic] [-showlog] [-config] [-uninstall] [[-subreddit] [-sort] [-nsfw]]') -ForegroundColor Yellow -BackgroundColor Black
    Write-Host
    Write-Host 'Commands' -ForegroundColor Green -BackgroundColor Black
    Write-Host
    Write-Host('No args             Fetches a lockscreen image on reddit') -BackgroundColor Black
    Write-Host('-help               Dislay help') -BackgroundColor Black
    Write-Host('-install            Installs the RedditLockscreen script') -BackgroundColor Black
    Write-Host('-showpic            Display the current lockscreen') -BackgroundColor Black
    Write-Host('-showlog            Display the log') -BackgroundColor Black
    Write-Host('-config             Open the configuration file') -BackgroundColor Black
    Write-Host('-list               List subreddits in config') -BackgroundColor Black
    Write-Host('-add xxx            Add a subreddit to the config') -BackgroundColor Black
    Write-Host('-remove xxx         Remove a subreddit from the config') -BackgroundColor Black
    Write-Host('-uninstall          Uninstall the RedditLockscreen script') -BackgroundColor Black
    Write-Host('-subreddit xxx      Specify which subreddit to pick from') -BackgroundColor Black
    Write-Host('-sort new|hot       Specify reddit''s sorting method') -BackgroundColor Black
    Write-Host('-nsfw               Specify if nfsw content should be used') -BackgroundColor Black
    Write-Host
    Write-Host('For more information, feel free to go read the README.md at https://github.com/Garfield1002/redditPic/README.MD') -BackgroundColor Black
}

Export-ModuleMember -Function RedditLockscreen;
