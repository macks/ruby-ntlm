require 'ntlm/http'

http = Net::HTTP.new('www.example.com')
request = Net::HTTP::Get.new('/')
request.ntlm_auth('User', 'Domain', 'Password')
response = http.request(request)

p response
print response.body
