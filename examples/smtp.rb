require 'ntlm/smtp'

from_addr = 'from@example.com'
to_addr = 'to@example.com'

mail_body = <<-EOS
From: #{from_addr}
To: #{to_addr}
Subject: Example
Content-Type: text/plain

Hello world!
EOS

smtp = Net::SMTP.new('smtp.example.com')
smtp.start('localhost.localdomain', 'Domain\\User', 'Password', :ntlm) do |smtp|
  smtp.send_mail(mail_body, from_addr, to_addr)
end
