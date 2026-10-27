require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name             = "FingerprintcheckerReactNative"
  s.version          = package["version"]
  s.summary          = "React Native wrapper for the FingerPrintChecker iOS SDK."
  s.description      = "Thin React Native module over the native FingerPrintChecker iOS SDK, vendored under ios/FingerPrintChecker."
  s.homepage         = "https://github.com/AndrewYukon/FingerPrintChecker"
  s.license          = { :type => "Apache-2.0" }
  s.author           = { "FingerPrintChecker" => "support@fpchecker.com" }
  s.platforms        = { :ios => "14.0" }
  s.source           = { :git => "https://github.com/AndrewYukon/FingerPrintChecker.git", :tag => "react-native-v#{s.version}" }
  s.source_files     = "ios/**/*.{swift,m}"
  s.resource_bundles = { "FingerPrintCheckerPrivacy" => ["ios/FingerPrintChecker/Resources/PrivacyInfo.xcprivacy"] }
  s.swift_version    = "5.9"
  s.frameworks       = "CryptoKit", "DeviceCheck", "Security"
  s.pod_target_xcconfig = { "DEFINES_MODULE" => "YES" }

  install_modules_dependencies(s)
end
