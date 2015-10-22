# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ntlm/version'

Gem::Specification.new do |spec|
  spec.name          = "ruby-ntlm"
  spec.version       = NTLM::VERSION
  spec.authors       = ["MATSUYAMA Kengo"]
  spec.email         = ["macksx@gmail.com"]
  spec.summary       = %q{NTLM implementation for Ruby.}
  spec.description   = %q{NTLM implementation for Ruby.}
  spec.homepage      = "http://github.com/macks/ruby-ntlm"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.5"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "test-unit"
end
