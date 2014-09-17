# vim: set ft=ruby:

require "bundler/gem_tasks"
require 'rake/testtask'

Rake::TestTask.new(:test) do |task|
  task.libs << 'lib:test'
  task.pattern = 'test/**/*_test.rb'
  task.verbose = true
  task.warning = true
end
