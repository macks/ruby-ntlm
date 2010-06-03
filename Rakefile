require 'rubygems'
require 'rake'
require 'jeweler'
require 'rake/testtask'

task :default => :test

Jeweler::Tasks.new do |gem|
  gem.name = 'ruby-ntlm'
  gem.summary = %Q{NTLM implementation for Ruby}
  gem.description = %Q{NTLM implementation for Ruby.}
  gem.email = 'macksx@gmail.com'
  gem.homepage = 'http://github.com/macks/ruby-ntlm'
  gem.authors = ['MATSUYAMA Kengo']
end

Rake::TestTask.new(:test) do |task|
  task.libs << 'lib:test'
  task.pattern = 'test/**/*_test.rb'
  task.verbose = true
end

begin
  require 'rcov/rcovtask'
  Rcov::RcovTask.new do |task|
    task.libs << 'lib:test'
    task.pattern = 'test/**/*_test.rb'
    task.verbose = true
  end
rescue LoadError
  task :rcov do
    abort 'rcov is not available.'
  end
end
