ruby-ntlm
=========

ruby-ntlm is NTLM client implementation for Ruby.
This library supports NTLM v1 only.


Usage
-----

### HTTP ###

    require 'ntlm/http'
    http = Net::HTTP.new('www.example.com')
    request = Net::HTTP::Get.new('/')
    request.ntlm_auth('User', 'Domain', 'Password')
    response = http.request(request)

### HTTP (using Mechanize) ###

    require 'ntlm/mechanize'
    mech = Mechanize.new
    mech.auth('Domain\\User', 'Password')
    mech.get('http://www.example.com/index.html')

### IMAP ###

    require 'ntlm/imap'
    imap = Net::IMAP.new('imap.example.com')
    imap.authenticate('NTLM', 'User', 'Domain', 'Password')

### SMTP ###

    require 'ntlm/smtp'
    smtp = Net::SMTP.new('smtp.example.com')
    smtp.start('localhost.localdomain', 'Domain\\User', 'Password', :ntlm) do |smtp|
      smtp.send_mail(mail_body, from_addr, to_addr)
    end


Author
------

MATSUYAMA Kengo (<macksx@gmail.com>)


License
-------

MIT License.

Copyright (c) 2010 MATSUYAMA Kengo


References
----------

 * [MS-NLMP][]: NT LAN Manager (NTLM) Authentication Protocol Specification
   [MS-NLMP]: http://msdn.microsoft.com/en-us/library/cc236621%28PROT.13%29.aspx
