require 'ntlm'
require 'net/imap'

module Net
  class IMAP
    class ResponseParser
      def continue_req
        match(T_PLUS)
        if lookahead.symbol == T_CRLF
          return ContinuationRequest.new(ResponseText.new(nil, ''), @str)
        else
          match(T_SPACE)
          return ContinuationRequest.new(resp_text, @str)
        end
      end
    end # ResponseParser

    class NTLMAuthenticator
      def initialize(user, domain, password)
        @user, @domain, @password = user, domain, password
        @state = 0
      end

      def process(data)
        case (@state += 1)
        when 1
          ::NTLM.negotiate.to_s
        when 2
          ::NTLM.authenticate(data, @user, @domain, @password).to_s
        end
      end
    end # NTLMAuthenticator

    add_authenticator 'NTLM', NTLMAuthenticator

  end # IMAP
end  # Net
