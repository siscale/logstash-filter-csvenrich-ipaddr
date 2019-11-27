Gem::Specification.new do |s|
  s.name          = 'logstash-filter-csvenrich-ipaddr'
  s.version       = '0.2.0'
  s.licenses      = ['Apache (2.0)']
  s.summary       = 'CSV enrich with IP ranges'
  s.description   = 'Enriches events with information from a CSV file. Match an IP field from the event with a column that contains IPs or IP ranges. Settings: file_path - path to CSV file, ip_column - 0-indexed CSV column, ip_field - event field containing an IP, map_field - extract and rename columns of interest from CSV'
  s.authors       = ['Matei B']
  s.email         = 'mateibm@users.noreply.github.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency "ipaddr", "~> 1.2"
  s.add_development_dependency 'logstash-devutils'
end
