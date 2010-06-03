require 'ntlm.so'
require 'net/http'

Net::HTTP.start('host.localdomain') do |http|
  request = Net::HTTP::Get.new('/')
  request['authorization'] = 'NTLM ' + [NTLM.negotiate].pack('m').delete("\r\n")

  response = http.request(request)

  # Connection is keep-alive!

  challenge = response['www-authenticate'][/NTLM (.*)/, 1].unpack('m').first
  auth_response = NTLM.authenticate(challenge, 'User@Domain', 'Password')
  request['authorization'] = 'NTLM ' + [auth_response].pack('m').delete("\r\n")

  response = http.request(request)

  p response
  print response.body
end
