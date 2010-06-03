# vim: set et sw=2 sts=2:

require File.dirname(__FILE__) + '/test_helper'

class AuthenticationTest < Test::Unit::TestCase

  include NTLM::TestUtility
  include NTLM::Util

  def setup
    @challenge = hex_to_bin("4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00 38 00 00 00 05 82 01 00 11 11 11 11 11 11 11 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 44 00 6f 00 6d 00 61 00 69 00 6e 00")
  end

  def test_negotiate
    assert_equal(hex_to_bin("4e 54 4c 4d 53 53 50 00 01 00 00 00 07 82 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"), NTLM.negotiate.to_s)
  end

  def test_authenticate
    assert_equal(hex_to_bin("4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00 58 00 00 00 18 00 18 00 70 00 00 00 0c 00 0c 00 88 00 00 00 08 00 08 00 94 00 00 00 00 00 00 00 9c 00 00 00 00 00 00 00 00 00 00 00 05 82 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 21 b0 c5 31 28 0e ed 8d 32 c3 1b ce b2 19 5a fd 58 2b b7 8e a0 d5 f2 78 8d 76 96 b7 58 49 16 14 2d 09 f0 a0 1f f2 35 10 be 2c ff 96 82 e0 e3 3b 44 00 6f 00 6d 00 61 00 69 00 6e 00 55 00 73 00 65 00 72 00"), NTLM.authenticate(@challenge, 'User', 'Domain', 'Password').to_s)

    challenge = NTLM::Message::Challenge.parse(@challenge)
    challenge.set(:NEGOTIATE_EXTENDED_SECURITY)

    assert_equal(hex_to_bin("4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00 58 00 00 00 18 00 18 00 70 00 00 00 0c 00 0c 00 88 00 00 00 08 00 08 00 94 00 00 00 00 00 00 00 9c 00 00 00 00 00 00 00 00 00 00 00 05 82 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 22 22 22 22 22 22 22 22 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c2 1e db 62 54 34 d2 13 34 1a 04 3d f3 01 6d f3 01 c9 32 b4 ae 97 1e ac 44 00 6f 00 6d 00 61 00 69 00 6e 00 55 00 73 00 65 00 72 00"), NTLM.authenticate(challenge.to_s, 'User', 'Domain', 'Password', :client_challenge => "\x22" * 8).to_s)
  end

end
