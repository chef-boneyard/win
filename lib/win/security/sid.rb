module Win
  module Security
    class SID
      def initialize(pointer)
        # TODO I think we're leaking this
        @pointer = pointer
      end

      attr_reader :pointer

      def account
        # Figure out how big the buffer needs to be
        name_size = FFI::Buffer.new(:long).write_long(0)
        referenced_domain_name_size = FFI::Buffer.new(:long).write_long(0)
        if Win::Security.LookupAccountSid(nil, pointer, nil, name_size, nil, referenced_domain_name_size, nil)
          raise "Expected error from LookupAccountSid!"
        elsif Win::Error.GetLastError() != Win::Error::ERROR_INSUFFICIENT_BUFFER
          raise "Expected ERROR_INSUFFICIENT_BUFFER from LookupAccountSid!"
        end

        name = FFI::MemoryPointer.new :char, name_size.read_long
        referenced_domain_name = FFI::MemoryPointer.new :char, referenced_domain_name_size.read_long
        use = FFI::Buffer.new(:long).write_long(0)
        unless Win::Security.LookupAccountSid(nil, pointer, name, name_size, referenced_domain_name, referenced_domain_name_size, use)
          Win::Security::raise_last_error
        end

        [ referenced_domain_name.read_string, name.read_string, use.read_long ]
      end

      def account_name
        domain, name, use = account
        domain ? "#{domain}\\#{name}" : name
      end
    end
  end
end