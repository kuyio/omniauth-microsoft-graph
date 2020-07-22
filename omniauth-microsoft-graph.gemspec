require File.expand_path(
  File.join('..', 'lib', 'omniauth', 'microsoft_graph', 'version'),
  __FILE__
)

Gem::Specification.new do |spec|
  spec.name          = "omniauth-microsoft-graph"
  spec.version       = Omniauth::MicrosoftGraph::VERSION
  spec.authors       = ["Nicolas Bettenburg"]
  spec.email         = ["nicbet@kuy.io"]

  spec.summary       = %q{Authentication with Microsoft Graph via Azure AD}
  spec.homepage      = "https://github.com/kuyio/omniauth-microsoft-graph"
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.3.0")


  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/kuyio/omniauth-microsoft-graph"
  spec.metadata["changelog_uri"] = "https://github.com/kuyio/omniauth-microsoft-graph/CHANGELOG"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Runtime Dependencies
  spec.add_runtime_dependency 'omniauth', '>= 1.1.1'
  spec.add_runtime_dependency 'omniauth-oauth2', '>= 1.6'

  # Development Dependencies
  spec.add_development_dependency 'rake', '~> 12.0'
  spec.add_development_dependency 'rspec', '~> 3.6'
  spec.add_development_dependency 'rubocop', '~> 0.49'
end
