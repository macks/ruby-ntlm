# vim: set et sw=2 sts=2:

require File.dirname(__FILE__) + '/test_helper'

class FunctionTest < Test::Unit::TestCase
  # Test pattern is borrowed from pyton-ntlm

  include NTLM::TestUtility
  include NTLM::Util

  def setup
    @server_challenge = hex_to_bin('01 23 45 67 89 ab cd ef')
    @client_challenge = "\xaa" * 8
    @time = "\0" * 8
    @workstation = 'COMPUTER'
    @server_name = 'Server'
    @user = 'User'
    @domain = 'Domain'
    @password = 'Password'
    @random_session_key = "\55" * 16
  end

  def test_lm_v1_hash
    assert_equal(hex_to_bin("e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d"), lm_v1_hash(@password))
  end

  def test_nt_v1_hash
    assert_equal(hex_to_bin("a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52"), nt_v1_hash(@password))
  end

  def test_ntlm_v1_response
    nt_response, lm_response = ntlm_v1_response(@server_challenge, @password)
    assert_equal(hex_to_bin("67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84 1f 94"), nt_response, 'nt_response')
    assert_equal(hex_to_bin("98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13"), lm_response, 'lm_response')
  end

  def test_ntlm_v1_response_with_ntlm_v2_session_security
    nt_response, lm_response = ntlm_v1_response(@server_challenge, @password, :ntlm_v2_session => true, :client_challenge => @client_challenge)
    assert_equal(hex_to_bin("75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8 1e 97 ed 26 83 26 72 32"), nt_response, 'nt_response')
    assert_equal(hex_to_bin("aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"), lm_response, 'lm_response')
  end

end
