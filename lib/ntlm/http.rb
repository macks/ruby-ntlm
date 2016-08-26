require 'ntlm'
require 'net/http'

module Net

  module HTTPHeader
    attr_reader :ntlm_auth_params

    def ntlm_auth(user, domain, password)
      @ntlm_auth_params = [user, domain, password]
    end
  end

  class HTTP

    unless method_defined?(:request_without_ntlm_auth)
      alias request_without_ntlm_auth request
    end

    def request(req, body = nil, &block)
      unless req.ntlm_auth_params
        return request_without_ntlm_auth(req, body, &block)
      end

      unless started?
        start do
          req.delete('connection')
          return request(req, body, &block)
        end
      end

      # Negotiation
      req['authorization'] = 'NTLM ' + ::NTLM.negotiate.to_base64
      res = request_without_ntlm_auth(req, body)
      challenge = res['www-authenticate'][/NTLM (.*)/, 1].unpack('m').first rescue nil

      if challenge && res.code == '401'
        # Authentication
        user, domain, password = req.ntlm_auth_params
        req['authorization'] = 'NTLM ' + ::NTLM.authenticate(challenge, user, domain, password).to_base64
        req.body_stream.rewind if req.body_stream
        request_without_ntlm_auth(req, body, &block)  # We must re-use the connection.
      else
        yield res if block_given?
        res
      end
    end

  end # HTTP

end # Net
