#!/usr/bin/env bash
# One-time setup: install the GitHub CLI and sign in through the browser (no passwords typed here).
set -e
if ! command -v gh >/dev/null 2>&1; then
  echo "Installing the GitHub CLI."
  echo "Type YOUR UBUNTU password below and press Enter (nothing appears while you type; that is normal)."
  if ! { sudo apt-get update -qq && sudo apt-get install -y gh; }; then
    echo "Install did not finish (password not entered in time, or wrong). Run this script again." >&2
    exit 1
  fi
fi
if ! gh auth status >/dev/null 2>&1; then
  echo
  echo "Signing in to GitHub: a one-time code appears below. Press Enter, then paste the code in the browser page that opens."
  BROWSER="cmd.exe /c start" gh auth login --hostname github.com --git-protocol https --web
fi
gh auth setup-git
echo
gh auth status 2>&1 | grep -E "Logged in|account" || true
echo "Done: GitHub sign-in is set up. You can close this tab."
