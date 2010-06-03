# vim: set et sw=2 sts=2:

require 'test/unit'

$LOAD_PATH << File.dirname(__FILE__) + '/../lib'
require 'ntlm'

module NTLM
  module TestUtility

    def bin_to_hex(bin)
      bin.unpack('H*').first.gsub(/..(?=.)/, '\0 ')
    end

    def hex_to_bin(hex)
      [hex.delete(' ')].pack('H*')
    end

  end
end
