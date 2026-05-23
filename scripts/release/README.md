# Building and Distributing Enclave Bridge

This directory contains scripts to build, sign, notarize, and package Enclave Bridge for distribution.

## Distribution Methods

### Direct Distribution (DMG)
For distributing outside the Mac App Store via your website, GitHub, etc.
- Uses Developer ID certificates
- Requires notarization
- Creates a `.dmg` installer

### Mac App Store
For distributing through the Mac App Store.
- Uses 3rd Party Mac Developer certificates
- Requires provisioning profile
- Creates a `.pkg` for upload to App Store Connect

## Prerequisites

### 1. Apple Developer Account
- Enroll at https://developer.apple.com/programs/
- Cost: $99/year

### 2. Certificates

#### For Direct Distribution (DMG):
1. Go to https://developer.apple.com/account/resources/certificates/list
2. Click "+" to create a new certificate
3. Select "Developer ID Application"
4. Upload Certificate Signing Request (or create one with Keychain Access)
5. Download and install the certificate

#### For Mac App Store:
1. Create "Mac App Distribution" certificate (3rd Party Mac Developer Application)
2. Create "Mac Installer Distribution" certificate (3rd Party Mac Developer Installer)
3. Create a Mac App Store provisioning profile:
   - Go to https://developer.apple.com/account/resources/profiles/list
   - Click "+" and select "Mac App Store Connect"
   - Select your App ID and certificate
   - Download and double-click to install

### 3. App-Specific Password (for notarization)
1. Go to https://appleid.apple.com/account/manage
2. Sign in with your Apple ID
3. Under "Security" → "App-Specific Passwords", generate a new password
4. Save it (you'll need it once)

### 4. Set Environment Variables
```bash
export APPLE_ID="your@email.com"
export APPLE_TEAM_ID="XXXXXXXXXX"  # Find at developer.apple.com/account
```

### 5. Store Notarization Credentials
```bash
xcrun notarytool store-credentials "AC_PASSWORD" \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "xxxx-xxxx-xxxx-xxxx"  # Your app-specific password
```

## Quick Start

### Option 1: Build Everything for Direct Distribution
```bash
chmod +x scripts/release/*.sh
./scripts/release/build-all.sh
```

This runs all steps automatically and creates `build/EnclaveBridge.dmg`.

### Option 2: Build for Mac App Store
```bash
export APPLE_TEAM_ID="YOUR_TEAM_ID"
./scripts/release/5-build-for-app-store.sh
```

Creates `build/export/Enclave.pkg` for upload to App Store Connect.

### Option 3: Step by Step (Direct Distribution)

#### Step 1: Build the App
```bash
./scripts/release/1-build-app.sh
```
Creates `build/Build/Products/Release/Enclave.app`

#### Step 2: Sign the App
```bash
./scripts/release/2-sign-app.sh
```
Code signs with your Developer ID certificate

#### Step 3: Notarize with Apple
```bash
./scripts/release/3-notarize-app.sh
```
Submits to Apple for notarization (takes 5-10 minutes)

#### Step 4: Create DMG
```bash
./scripts/release/4-create-dmg.sh
```
Creates `build/EnclaveBridge.dmg`

## Utility Scripts

### Update Version
```bash
./scripts/bump-version.bsh 1.0.1
```
Updates version number in project files.

### Fix Certificate Trust
```bash
./scripts/release/fix-certificate-trust.sh
```
Troubleshoots certificate trust issues in Keychain.

## App Bundle Info

- **App Name**: Enclave
- **Display Name**: Enclave Bridge
- **Bundle ID**: com.JessicaMulein.EnclaveBridge
- **Category**: Developer Tools

## Troubleshooting

### "Developer ID Application certificate not found"
1. Download from https://developer.apple.com/account/resources/certificates/list
2. Double-click to install in Keychain Access
3. Run `./scripts/release/fix-certificate-trust.sh` if trust issues persist

### "Notarization credentials not found"
Run the store-credentials command from step 5 in Prerequisites.

### "Provisioning profile not found" (App Store only)
1. Create at https://developer.apple.com/account/resources/profiles/list
2. Select "Mac App Store Connect"
3. Download and double-click to install

### Gatekeeper blocks the app
The app needs to be notarized. Run the full build-all.sh pipeline.
