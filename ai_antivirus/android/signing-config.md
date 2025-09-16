# Google Play Store App Signing Configuration

## 🔐 Generate Release Keystore

### Step 1: Create Keystore
```bash
keytool -genkey -v -keystore release-key.keystore \
  -alias ai-antivirus \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000
```

### Step 2: Keystore Information
```
Keystore password: [SECURE_PASSWORD]
Key alias: ai-antivirus
Key password: [SECURE_KEY_PASSWORD]
CN: AI Defense Inc
OU: Mobile Security Division
O: AI Defense Inc
L: San Francisco
ST: California
C: US
```

## 📦 Build Signed APK

### Debug Build
```bash
./gradlew assembleDebug
```

### Release Build
```bash
# Set environment variables
export KEYSTORE_PASSWORD="your_keystore_password"
export KEY_ALIAS="ai-antivirus"
export KEY_PASSWORD="your_key_password"

# Build release APK
./gradlew assembleRelease

# Output: app/build/outputs/apk/release/app-release.apk
```

## 📦 Build App Bundle (Recommended)

```bash
# Build AAB for Play Store
./gradlew bundleRelease

# Output: app/build/outputs/bundle/release/app-release.aab
```

## ✅ Sign APK Manually

```bash
# Sign APK
jarsigner -verbose \
  -sigalg SHA256withRSA \
  -digestalg SHA-256 \
  -keystore release-key.keystore \
  app-release-unsigned.apk \
  ai-antivirus

# Verify signature
jarsigner -verify -verbose -certs app-release.apk

# Optimize with zipalign
zipalign -v -p 4 app-release-unsigned.apk app-release-aligned.apk

# Sign with apksigner (recommended)
apksigner sign \
  --ks release-key.keystore \
  --ks-key-alias ai-antivirus \
  --out app-release-signed.apk \
  app-release-aligned.apk

# Verify with apksigner
apksigner verify app-release-signed.apk
```

## 🎯 Google Play App Signing

### Enable Play App Signing
1. Go to Play Console
2. Select your app
3. Navigate to Setup > App integrity
4. Click on App signing
5. Upload your app signing key

### Upload Key (for updates)
```bash
# Generate upload key
keytool -genkey -v \
  -keystore upload-key.keystore \
  -alias upload \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000

# Export certificate
keytool -export -rfc \
  -keystore upload-key.keystore \
  -alias upload \
  -file upload_certificate.pem
```

## 🔒 Security Best Practices

### Keystore Security
- Store keystore in secure location
- Never commit keystore to version control
- Use strong passwords (min 16 characters)
- Enable 2FA on Play Console
- Backup keystore securely

### Environment Variables
```bash
# .env file (git ignored)
KEYSTORE_PATH=/secure/location/release-key.keystore
KEYSTORE_PASSWORD=StrongPassword123!@#
KEY_ALIAS=ai-antivirus
KEY_PASSWORD=StrongKeyPassword456$%^
```

### CI/CD Integration
```yaml
# GitHub Actions secrets
secrets:
  KEYSTORE_BASE64: ${{ secrets.KEYSTORE_BASE64 }}
  KEYSTORE_PASSWORD: ${{ secrets.KEYSTORE_PASSWORD }}
  KEY_ALIAS: ${{ secrets.KEY_ALIAS }}
  KEY_PASSWORD: ${{ secrets.KEY_PASSWORD }}
```

## 📊 Key Rotation

### When to Rotate
- Every 2-3 years
- After security breach
- When team members leave
- Before major releases

### Rotation Process
1. Generate new signing key
2. Upload to Play Console
3. Configure key rotation
4. Test thoroughly
5. Release update

## 🔍 Verification Commands

### Check APK Signature
```bash
# View certificate details
keytool -printcert -jarfile app-release.apk

# Check signature algorithm
apksigner verify --print-certs app-release.apk

# Verify with aapt
aapt dump badging app-release.apk | grep -E "package|launchable|application-label"
```

### Extract APK Certificate
```bash
# Extract CERT.RSA
unzip -p app-release.apk META-INF/CERT.RSA | \
  keytool -printcert | \
  grep -E "Owner|Issuer|Serial|Valid|SHA256"
```

## 🚀 Automated Release Pipeline

### Fastlane Configuration
```ruby
# Fastfile
platform :android do
  desc "Deploy to Google Play Store"
  lane :deploy do
    gradle(
      task: "bundle",
      build_type: "Release",
      properties: {
        "android.injected.signing.store.file" => ENV["KEYSTORE_PATH"],
        "android.injected.signing.store.password" => ENV["KEYSTORE_PASSWORD"],
        "android.injected.signing.key.alias" => ENV["KEY_ALIAS"],
        "android.injected.signing.key.password" => ENV["KEY_PASSWORD"]
      }
    )
    
    upload_to_play_store(
      track: "beta",
      release_status: "draft",
      skip_upload_metadata: false,
      skip_upload_images: false,
      skip_upload_screenshots: false
    )
  end
end
```

## 🔧 Troubleshooting

### Common Issues

1. **Keystore not found**
   - Ensure correct path in gradle.properties
   - Check environment variables

2. **Wrong password**
   - Verify keystore and key passwords
   - Check for special characters escaping

3. **Signature verification failed**
   - Ensure APK is properly aligned
   - Use apksigner instead of jarsigner

4. **Upload key mismatch**
   - Verify you're using correct upload key
   - Check Play Console configuration

## 📄 Required Files for Submission

- [ ] Signed APK or AAB
- [ ] 512x512 app icon
- [ ] Feature graphic (1024x500)
- [ ] Screenshots (min 2, max 8)
- [ ] Privacy policy URL
- [ ] App description
- [ ] Content rating questionnaire
- [ ] Target audience declaration
- [ ] Data safety form

## 🌐 Post-Release

### Monitor
- Crash reports in Play Console
- User reviews and ratings
- Installation statistics
- Revenue reports

### Respond
- Address critical issues immediately
- Respond to user reviews
- Release patches as needed
- Plan feature updates

---

**Security Note**: This configuration ensures your app meets Google Play Store security requirements and protects against tampering.