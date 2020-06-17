# Reddit Lockscreen

![Release](https://img.shields.io/github/v/release/Garfield1002/redditPic?include_prereleases)
![Downloads](https://img.shields.io/github/downloads/Garfield1002/https://img.shields.io/github/v/release/Garfield1002/redditPic?include_prereleases/total)
![Liscence](https://img.shields.io/github/license/Garfield1002/redditPic)

Sets images fetched on reddit as lockscreen.

## Description

This script will automatically download a new lockscreen from reddit every time you log in.
It will require **admin rights** in order to work.
Remember, these images are pulled directly from reddit, so if you like your lockcreen **upvote the post** and give credit where it is due.
(You can find the link to the post in the [logfile](####`-showlog`).

This script was inspired by stibinator's [The Great Dismal](https://github.com/stibinator/GreatDismal).

## Table of content

* [Requirements](#Requirements)
* [Install](#Install)
* [Usage](#Usage)
* [Uninstall](#Uninstall)

## Requirements

* Powershell 5+
* Admin rights
Works for Windows 10 (build 1703 or later)

## Install

### Quick Version

1. Clone the repo or download archive from [releases](https://github.com/Garfield1002/redditPic/releases)
2. Execute in an elevated instance of `Windows PowerShell`:

```powershell
.\installer.ps1
```

Then follow instructions.

### Detailed Installation Guide

If you have never used `PowerShell`, this is for you.

First Clone the repo or download archive from [releases](https://github.com/Garfield1002/redditPic/releases).

In the `Search Bar`, type in `PowerShell` and click on `Run As Administrator`.

Once in `PowerShell`, run `Set-Location "C:\Users\ ...\Downloads\reddit pics\"` (the path to your download)

Now run `.\installer.ps1`

From there on, simply follow instructions.

## Usage

You can run the utility at any given time to try and find a new background.

In `Windows PowerShell`:

```powershell
RedditLockscreen [-help] [-install] [-showpic] [-showlog] [-config] [-uninstall] [[-subreddit] [-sort] [-nsfw]]
```

In `Command Prompt`:

```bat
powershell RedditLockscreen [-help] [-install] [-showpic] [-showlog] [-config] [-list] [-add] [-remove] [-uninstall] [[-subreddit] [-sort] [-nsfw]]
```

Naturally, both need admin rights.

Use `RedditLockscreen -help` for help or visit the [wiki](https://github.com/Garfield1002/redditPic/wiki/RedditLockscreen) for more details.

## Uninstall

Run `RedditLockscreen -uninstall`

You will be asked to manually delete the module folder.
