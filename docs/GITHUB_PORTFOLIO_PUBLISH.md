# Publish SOCForge without exposing a live SOC

1. Sign in to GitHub and create an **empty public** repository named `SOCForge` under user `mscs7` (avoid adding README or license in GitHub because the archive includes them).
2. Extract `SOCForge_GitHub_Ready.zip`, and in its `SOCForge` folder run:

   ```bash
   git init
   git add .
   git commit -m "Publish SOCForge personal SOC automation lab"
   git branch -M main
   git remote add origin https://github.com/mscs7/SOCForge.git
   git push -u origin main
   ```

   Authenticate using Git Credential Manager/GitHub CLI or SSH as appropriate. Never put tokens in chat or repository files.
3. Verify `https://github.com/mscs7/SOCForge` shows the README, source, tests and screenshots. GitHub Actions will run the tests after push if enabled.
4. Apply the separate portfolio patch to the current `mscs7.github.io` repo, then publish it.

**Important:** The public GitHub Pages preview at `projects/socforge/` is static and synthetic. The local FastAPI service is not publicly hosted. Do not expose this unauthenticated demo service on the internet. `.env`, databases and secrets are excluded by `.gitignore`.
