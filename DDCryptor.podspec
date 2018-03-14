
Pod::Spec.new do |s|

  s.name         = "DDCryptor"
  s.version      = "0.0.1"
  s.summary      = "A set of cryptors, include RSA, MD5, Base64, DES some more..."

  s.homepage     = "https://github.com/longxdragon/DDCryptor"
  s.license      = "MIT"

  s.author       = { "longxdragon" => "longxdragon@163.com" }
  s.platform     = :ios, "7.0"

  s.source       = { :git => "https://github.com/longxdragon/DDCryptor.git", :tag => "#{s.version}" }
  s.source_files = "DDCryptor/DDCryptor/DDCryptor/*.{h,m}"
  
  s.framework    = "Foundation"
  s.requires_arc = true

  s.dependency 'OpenSSL-Universal', '~> 1.0'
  s.dependency 'GTMBase64', '~> 1.0.0'

  # s.static_framework = true

end
