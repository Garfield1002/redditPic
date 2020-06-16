
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "-----Moving files-----" -ForegroundColor Yellow
    $RedditLockscreenModuleFolder = (join-path $env:PSModulePath.Split(";")[0] "\RedditLockscreen\")
    Write-Host $RedditLockscreenModuleFolder
    if (! (test-path $RedditLockscreenModuleFolder)){
        mkdir $RedditLockscreenModuleFolder
    }
    Write-Host ("Successfuly created file at: {0}" -f $RedditLockscreenModuleFolder) -ForegroundColor Green

    Copy-Item ".\RedditLockscreen.psm1" -Destination $RedditLockscreenModuleFolder
    Write-Host ("Successfuly copied module to : {0}" -f $RedditLockscreenModuleFolder) -ForegroundColor Green
    if ((get-module -listavailable).name.Contains("RedditLockscreen")){
        Write-Host "-----Launching Installation-----" -ForegroundColor Yellow
        RedditLockscreen -install
    } else {
        throw "installation failed"
    }

}  else {
    # not admin
    Write-Host "You need run this script as an Admin to install it" -BackgroundColor Red -ForegroundColor Yellow
    throw "Computer says no."
}