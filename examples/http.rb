require 'ntlm'
require 'net/http'

Net::HTTP.start('www.example.com') do |http|
  request = Net::HTTP::Get.new('/')
  request['authorization'] = 'NTLM ' + NTLM.negotiate.to_base64

  response = http.request(request)

  # The connection must be keep-alive!

  challenge = response['www-authenticate'][/NTLM (.*)/, 1].unpack('m').first
  request['authorization'] = 'NTLM ' + NTLM.authenticate(challenge, 'User', 'Domain', 'Password').to_base64

  response = http.request(request)

  p response
  print response.body
end
