# vim: set et sw=2 sts=2:

require 'openssl'
require 'iconv'

module NTLM
  module Util

    LM_MAGIC_TEXT = 'KGS!@#$%'

    module_function

    def decode_utf16(str)
      Iconv.conv('UTF-8', 'UTF-16LE', str)
    end

    def encode_utf16(str)
      Iconv.conv('UTF-16LE', 'UTF-8', str)
    end

    def create_des_keys(string)
      keys = []
      string = string.dup
      until (key = string.slice!(0, 7)).empty?
        # key is 56 bits
        key = key.unpack('B*').first
        str = ''
        until (bits = key.slice!(0, 7)).empty?
          str << bits
          str << (bits.count('1').even? ? '1' : '0')  # parity
        end
        keys << [str].pack('B*')
      end
      keys
    end

    def encrypt(plain_text, key, key_length)
      key = key.ljust(key_length, "\0")
      keys = create_des_keys(key[0, key_length])

      result = ''
      cipher = OpenSSL::Cipher::DES.new
      keys.each do |k|
        cipher.encrypt
        cipher.key = k
        result << cipher.update(plain_text)
      end

      result
    end

    # [MS-NLMP] 3.3.1
    def lm_v1_hash(password)
      encrypt(LM_MAGIC_TEXT, password.upcase, 14)
    end

    # [MS-NLMP] 3.3.1
    def nt_v1_hash(password)
      OpenSSL::Digest::MD4.digest(encode_utf16(password))
    end

    # [MS-NLMP] 3.3.1
    def ntlm_v1_response(challenge, password, options = {})
      if options[:ntlm_v2_session]
        client_challenge = options[:client_challenge] || OpenSSL::Random.random_bytes(8)
        hash = OpenSSL::Digest::MD5.digest(challenge + client_challenge)[0, 8]
        nt_response = encrypt(hash, nt_v1_hash(password), 21)
        lm_response = client_challenge + ("\0" * 16)
      else
        nt_response = encrypt(challenge, nt_v1_hash(password), 21)
        lm_response = encrypt(challenge, lm_v1_hash(password), 21)
      end

      [nt_response, lm_response]
    end


    # [MS-NLMP] 3.3.2
    def nt_v2_hash(user, password, domain)
      user_domain = encode_utf16(user.upcase + domain)
      OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, nt_v1_hash(password), user_domain)
    end

    # [MS-NLMP] 3.3.2
    def ntlm_v2_response(*)
      raise NotImplemnetedError
    end

  end # Util
end # NTLM
