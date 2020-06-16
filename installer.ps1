
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
$RedditLockscreenModuleFolder = (join-path $env:PSModulePath "\RedditLockscreen\")
    if (! (test-path $RedditLockscreenModuleFolder)){
        mkdir $RedditLockscreenModuleFolder
    }
    Write-Host ("Successfuly created file at: {0}" -f $RedditLockscreenModuleFolder) -ForegroundColor Green

    Copy-Item ".\RedditLockscreen.psm1" -Destination $RedditLockscreenModuleFolder
    Write-Host ("Successfuly copied module to : {0}" -f $RedditLockscreenModuleFolder) -ForegroundColor Green
    Invoke-Expression ("&'{0}' -install" -f (join-path $RedditLockscreenModuleFolder "RedditLockscreen.psm1"))
}  else {
    # not admin
    Write-Host "You need run this script as an Admin to install it" -BackgroundColor Red -ForegroundColor Yellow
    throw "Computer says no."
}