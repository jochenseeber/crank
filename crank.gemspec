require File.expand_path("../lib/crank/version", __FILE__)

Gem::Specification.new do |s|
  s.required_ruby_version = "~> 2.2"
  s.name = "crank"
  s.version = Crank::VERSION
  s.date = "2017-03-08"
  s.summary = "Automated headless Ubuntu installation on servers"
  s.description = "Use crank to install Ubuntu on headless servers over the network, fully automated"
  s.authors = ["Jochen Seeber"]
  s.email = "jochen@seeber.me"
  s.files = Dir["lib/**/*.rb", "bin/crank", "files/**/*.eruby"]
  s.executables = ["crank"]
  s.homepage = "https://github.com/jochenseeber/crank"
  s.license = "BSD 2-Clause"
  s.require_paths = ["lib"]

  s.add_runtime_dependency "andand", "~> 1.3"
  s.add_runtime_dependency "base32", "~> 0.3"
  s.add_runtime_dependency "commander", "~> 4.4"
  s.add_runtime_dependency "erubis", "~> 2.7"
  s.add_runtime_dependency "facets", "~> 3.1"
  s.add_runtime_dependency "ipaddress", "~> 0.8"
  s.add_runtime_dependency "jsonpath", "~> 0.5"
  s.add_runtime_dependency "rest-client", "~> 2.0"
  s.add_runtime_dependency "rye", "~> 0.9"
  s.add_runtime_dependency "unix-crypt", "~> 1.3"

  s.add_development_dependency "bundler", ">= 1.0.0"
end
