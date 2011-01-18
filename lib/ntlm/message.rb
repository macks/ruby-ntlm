# vim: set et sw=2 sts=2:

require 'ntlm/util'

module NTLM
  class Message

    include Util

    SSP_SIGNATURE  = "NTLMSSP\0"

    # [MS-NLMP] 2.2.2.5
    FLAGS = {
      :NEGOTIATE_UNICODE           => 0x00000001,  # Unicode character set encoding
      :NEGOTIATE_OEM               => 0x00000002,  # OEM character set encoding
      :REQUEST_TARGET              => 0x00000004,  # TargetName is supplied in challenge message
      :UNUSED10                    => 0x00000008,
      :NEGOTIATE_SIGN              => 0x00000010,  # Session key negotiation for message signatures
      :NEGOTIATE_SEAL              => 0x00000020,  # Session key negotiation for message confidentiality
      :NEGOTIATE_DATAGRAM          => 0x00000040,  # Connectionless authentication
      :NEGOTIATE_LM_KEY            => 0x00000080,  # LAN Manager session key computation
      :UNUSED9                     => 0x00000100,
      :NEGOTIATE_NTLM              => 0x00000200,  # NTLM v1 protocol
      :UNUSED8                     => 0x00000400,
      :ANONYMOUS                   => 0x00000800,  # Anonymous connection
      :OEM_DOMAIN_SUPPLIED         => 0x00001000,  # Domain field is present
      :OEM_WORKSTATION_SUPPLIED    => 0x00002000,  # Workstations field is present
      :UNUSED7                     => 0x00004000,
      :NEGOTIATE_ALWAYS_SIGN       => 0x00008000,
      :TARGET_TYPE_DOMAIN          => 0x00010000,  # TargetName is domain name
      :TARGET_TYPE_SERVER          => 0x00020000,  # TargetName is server name
      :UNUSED6                     => 0x00040000,
      :NEGOTIATE_EXTENDED_SECURITY => 0x00080000,  # NTLM v2 session security
      :NEGOTIATE_IDENTIFY          => 0x00100000,  # Requests identify level token
      :UNUSED5                     => 0x00200000,
      :REQUEST_NON_NT_SESSION_KEY  => 0x00400000,  # LM session key is used
      :NEGOTIATE_TARGET_INFO       => 0x00800000,  # Requests TargetInfo
      :UNUSED4                     => 0x01000000,
      :NEGOTIATE_VERSION           => 0x02000000,  # Version field is present
      :UNUSED3                     => 0x04000000,
      :UNUSED2                     => 0x08000000,
      :UNUSED1                     => 0x10000000,
      :NEGOTIATE_128               => 0x20000000,  # 128bit encryption
      :NEGOTIATE_KEY_EXCH          => 0x40000000,  # Explicit key exchange
      :NEGOTIATE_56                => 0x80000000,  # 56bit encryption
    }

    # [MS-NLMP] 2.2.2.1
    AV_PAIRS = {
      :AV_EOL               => 0,
      :AV_NB_COMPUTER_NAME  => 1,
      :AV_NB_DOMAIN_NAME    => 2,
      :AV_DNS_COMPUTER_NAME => 3,
      :AV_DNS_DOMAIN_NAME   => 4,
      :AV_DNS_TREE_NAME     => 5,
      :AV_FLAGS             => 6,
      :AV_TIMESTAMP         => 7,
      :AV_RESTRICTIONS      => 8,
      :AV_TARGET_NAME       => 9,
      :AV_CHANNEL_BINDINGS  => 10,
    }
    AV_PAIR_NAMES = AV_PAIRS.invert

    FLAGS.each do |name, val|
      const_set(name, val)
    end

    AV_PAIRS.each do |name, val|
      const_set(name, val)
    end

    class ParseError < StandardError; end

    attr_accessor :flag


    def self.parse(*args)
      new.parse(*args)
    end

    def initialize(args = {})
      @buffer = ''
      @offset  = 0
      @flag    = args[:flag] || self.class::DEFAULT_FLAGS

      self.class::ATTRIBUTES.each do |key|
        instance_variable_set("@#{key}", args[key]) if args[key]
      end
    end

    def to_s
      serialize
    end

    def serialize_to_base64
      [serialize].pack('m').delete("\r\n")
    end

    alias to_base64 serialize_to_base64

    def has_flag?(symbol)
      (@flag & FLAGS[symbol]) != 0
    end

    def set(symbol)
      @flag |= FLAGS[symbol]
    end

    def clear(symbol)
      @flag &= ~FLAGS[symbol]
    end

    def unicode?
      has_flag?(:NEGOTIATE_UNICODE)
    end

    def inspect_flags
      flags = []
      FLAGS.sort_by(&:last).each do |name, val|
        flags << name if (@flag & val).nonzero?
      end
      "[#{flags.join(', ')}]"
    end

    def inspect
      variables = (instance_variables.map(&:to_sym) - [:@offset, :@buffer, :@flag]).sort.map {|name| "#{name}=#{instance_variable_get(name).inspect}, " }.join
      "\#<#{self.class.name} #{variables}@flag=#{inspect_flags}>"
    end

    private

    def parse(string)
      @buffer = string
      signature, type = string.unpack('a8V')
      raise ParseError, 'Unknown signature' if signature != SSP_SIGNATURE
      raise ParseError, "Wrong type (expected #{self.class::TYPE}, but got #{type})" if type != self.class::TYPE
    end

    def append_payload(string, allocation_size = nil)
      size = string.size
      allocation_size ||= (size + 1) & ~1
      string = string.ljust(allocation_size, "\0")
      @buffer << string[0, allocation_size]
      result = [size, allocation_size, @offset].pack('vvV')
      @offset += allocation_size
      result
    end

    def fetch_payload(fields)
      size, allocated_size, offset = fields.unpack('vvV')
      return nil if size.zero?
      @buffer[offset, size]
    end

    def encode_version(array)
      array.pack('CCvx3C')   # major, minor, build, ntlm revision
    end

    def decode_version(string)
      string.unpack('CCvx3C')   # major, minor, build, ntlm revision
    end

    def decode_av_pair(string)
      result = []
      string = string.dup
      while true
        id, length = string.slice!(0, 4).unpack('vv')
        value = string.slice!(0, length)

        case sym = AV_PAIR_NAMES[id]
        when :AV_EOL
          break
        when :AV_NB_COMPUTER_NAME, :AV_NB_DOMAIN_NAME, :AV_DNS_COMPUTER_NAME, :AV_DNS_DOMAIN_NAME, :AV_DNS_TREE_NAME, :AV_TARGET_NAME
          value = decode_utf16(value)
        when :AV_FLAGS
          value = data.unpack('V').first
        end

        result << [sym, value]
      end
      result
    end

    def encode_av_pair(av_pair)
      result = ''
      av_pair.each do |(id, value)|
        case id
        when :AV_NB_COMPUTER_NAME, :AV_NB_DOMAIN_NAME, :AV_DNS_COMPUTER_NAME, :AV_DNS_DOMAIN_NAME, :AV_DNS_TREE_NAME, :AV_TARGET_NAME
          value = encode_utf16(value)
        when :AV_FLAGS
          value = [data].pack('V')
        end
        result << [AV_PAIRS[id], value.size, value].pack('vva*')
      end

      result << [AV_EOL, 0].pack('vv')
    end


    # [MS-NLMP] 2.2.1.1
    class Negotiate < Message

      TYPE          = 1
      ATTRIBUTES    = [:domain, :workstation, :version]
      DEFAULT_FLAGS = [NEGOTIATE_UNICODE, NEGOTIATE_OEM, REQUEST_TARGET, NEGOTIATE_NTLM, NEGOTIATE_ALWAYS_SIGN, NEGOTIATE_EXTENDED_SECURITY].inject(:|)

      attr_accessor *ATTRIBUTES

      def parse(string)
        super
        @flag, domain, workstation, version = string.unpack('x12Va8a8a8')
        @domain      = fetch_payload(domain) if has_flag?(:OEM_DOMAIN_SUPPLIED)
        @workstation = fetch_payload(workstation) if has_flag?(:OEM_WORKSTATION_SUPPLIED)
        @version     = decode_version(version)  if has_flag?(:NEGOTIATE_VERSION)
        self
      end

      def serialize
        @buffer = ''
        @offset = 40  # (8 + 4) + 4 + (8 * 3)

        if @domain
          set(:OEM_DOMAIN_SUPPLIED)
          domain = append_payload(@domain)
        end

        if @workstation
          set(:OEM_WORKSTATION_SUPPLIED)
          workstation = append_payload(@workstation)
        end

        if @version
          set(:NEGOTIATE_VERSION)
          version = encode_version(@version)
        end

        [SSP_SIGNATURE, TYPE, @flag, domain, workstation, version].pack('a8VVa8a8a8') + @buffer
      end

    end # Negotiate


    # [MS-NLMP] 2.2.1.2
    class Challenge < Message

      TYPE          = 2
      ATTRIBUTES    = [:target_name, :challenge, :target_info, :version]
      DEFAULT_FLAGS = 0

      attr_accessor *ATTRIBUTES

      def parse(string)
        super
        target_name, @flag, @challenge, target_info, version = string.unpack('x12a8Va8x8a8a8')
        @target_name = fetch_payload(target_name) if has_flag?(:REQUEST_TARGET)
        @target_info = fetch_payload(target_info) if has_flag?(:NEGOTIATE_TARGET_INFO)
        @version     = decode_version(version)  if has_flag?(:NEGOTIATE_VERSION)

        @target_name &&= decode_utf16(@target_name) if unicode?
        @target_info &&= decode_av_pair(@target_info)

        self
      end

      def serialize
        @buffer = ''
        @offset = 56  # (8 + 4) + 8 + 4 + (8 * 4)

        @challenge ||= OpenSSL::Random.random_bytes(8)

        if @target_name
          set(:REQUEST_TARGET)
          if unicode?
            target_name = append_payload(encode_utf16(@target_name))
          else
            target_name = append_payload(@target_name)
          end
        end

        if @target_info
          set(:NEGOTIATE_TARGET_INFO)
          target_info = append_payload(encode_av_pair(@target_info))
        end

        if @version
          set(:NEGOTIATE_VERSION)
          version = encode_version(@version)
        end

        [SSP_SIGNATURE, TYPE, target_name, @flag, @challenge, target_info, version].pack('a8Va8Va8x8a8a8') + @buffer
      end

    end # Challenge


    # [MS-NLMP] 2.2.1.3
    class Authenticate < Message

      TYPE          = 3
      ATTRIBUTES    = [:lm_response, :nt_response, :domain, :user, :workstation, :session_key, :version, :mic]
      DEFAULT_FLAGS = [NEGOTIATE_UNICODE, REQUEST_TARGET, NEGOTIATE_NTLM, NEGOTIATE_ALWAYS_SIGN, NEGOTIATE_EXTENDED_SECURITY].inject(:|)

      attr_accessor *ATTRIBUTES

      def parse(string)
        super
        lm_response, nt_response, domain, user, workstation, session_key, @flag, version, mic = \
          string.unpack('x12a8a8a8a8a8a8Va8a16')

        @lm_response = fetch_payload(lm_response)
        @nt_response = fetch_payload(nt_response)
        @domain      = fetch_payload(domain)
        @user        = fetch_payload(user)
        @workstation = fetch_payload(workstation)
        @session_key = fetch_payload(session_key) if has_flag?(:NEGOTIATE_KEY_EXCH)
        @version     = decode_version(version) if has_flag?(:NEGOTIATE_VERSION)
        @mic         = mic

        if unicode?
          @domain      = decode_utf16(@domain)
          @user        = decode_utf16(@user)
          @workstation = decode_utf16(@workstation)
        end

        self
      end

      def serialize
        @buffer = ''
        @offset = 88  # (8 + 4) + (8 * 6) + 4 + 8 + 16

        lm_response = append_payload(@lm_response)
        nt_response = append_payload(@nt_response)

        if unicode?
          domain      = append_payload(encode_utf16(@domain))
          user        = append_payload(encode_utf16(@user))
          workstation = append_payload(encode_utf16(@workstation))
        else
          domain      = append_payload(@domain)
          user        = append_payload(@user)
          workstation = append_payload(@workstation)
        end

        if @session_key
          set(:NEGOTIATE_KEY_EXCH)
          session_key = append_payload(@session_key)
        end

        if @version
          set(:NEGOTIATE_VERSION)
          version = encode_version(@version)
        end

        [SSP_SIGNATURE, TYPE, lm_response, nt_response, domain, user, workstation, session_key, @flag, version, @mic].pack('a8Va8a8a8a8a8a8Va8a16') + @buffer
      end

    end # Authenticate

  end # Message
end # NTLM
