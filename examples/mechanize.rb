$LOAD_PATH << File.dirname(__FILE__) + '/lib'
require 'rubygems'
require 'ntlm/mechanize'

mech = Mechanize.new
mech.auth('Domain\\User', 'Password')
mech.get('http://www.example.com/index.html')

puts mech.page.body
