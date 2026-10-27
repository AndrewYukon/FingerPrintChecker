Pod::Spec.new do |s|
  s.name             = 'fingerprintchecker'
  s.version          = '0.1.0'
  s.summary          = 'Flutter plugin for FingerPrintChecker.'
  s.description      = 'Thin Flutter wrapper over the native FingerPrintChecker iOS SDK, vendored under Classes/FingerPrintChecker.'
  s.homepage         = 'https://github.com/AndrewYukon/FingerPrintChecker'
  s.license          = { :type => 'MIT' }
  s.author           = { 'FingerPrintChecker' => 'support@fpchecker.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*.{swift,h,m}'
  s.resource_bundles = { 'FingerPrintCheckerPrivacy' => ['Classes/FingerPrintChecker/Resources/PrivacyInfo.xcprivacy'] }
  s.public_header_files = 'Classes/*.h'
  s.dependency 'Flutter'
  s.platform         = :ios, '14.0'
  s.swift_version    = '5.9'
  s.frameworks       = 'CryptoKit', 'DeviceCheck', 'Security'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
end
