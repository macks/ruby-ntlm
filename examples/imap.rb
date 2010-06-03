require 'ntlm/imap'

imap = Net::IMAP.new('imap.example.com')
abort 'NTLM authentication is not supported.' unless imap.capability.include?('AUTH=NTLM')
imap.authenticate('NTLM', 'User', 'Domain', 'Password')

imap.select('INBOX')
uids = imap.uid_search(['ALL'])
data = imap.uid_fetch(uids[0], 'BODY[]')
print data.first.attr['BODY[]']
