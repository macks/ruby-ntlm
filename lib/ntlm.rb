# vim: set et sw=2 sts=2:

require 'ntlm/util'
require 'ntlm/message'

module NTLM

  begin
    Version = File.read(File.dirname(__FILE__) + '/../VERSION').strip
  rescue
    Version = 'unknown'
  end

  def self.negotiate(args = {})
    Message::Negotiate.new(args)
  end

  def self.authenticate(challenge_message, user, domain, password, options = {})
    challenge = Message::Challenge.parse(challenge_message)

    opt = options.merge({
      :ntlm_v2_session => challenge.has_flag?(:NEGOTIATE_EXTENDED_SECURITY),
    })
    nt_response, lm_response = Util.ntlm_v1_response(challenge.challenge, password, opt)

    Message::Authenticate.new(
      :user        => user,
      :domain      => domain,
      :lm_response => lm_response,
      :nt_response => nt_response
    )
  end

end # NTLM
