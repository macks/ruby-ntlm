require 'ntlm'
require 'net/smtp'

module Net
  class SMTP

    def capable_ntlm_auth?
      auth_capable?('NTLM')
    end

    def auth_ntlm(user, secret)
      check_auth_args(user, secret)
      if user.index('\\')
        domain, user = user.split('\\', 2)
      else
        domain = ''
      end

      res = critical {
        r = get_response("AUTH NTLM #{::NTLM.negotiate.to_base64}")
        check_auth_continue(r)
        challenge = r.string.split(/ /, 2).last.unpack('m').first
        get_response(::NTLM.authenticate(challenge, user, domain, secret).to_base64)
      }
      check_auth_response(res)
      res
    end

  end # SMTP
end # Net
