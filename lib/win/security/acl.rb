require 'win/security'
require 'win/security/ace'
require 'ffi'

module Win
  module Security
    class ACL
      include Enumerable

      def initialize(pointer)
        @struct = Win::Security::ACLStruct.new pointer
      end

      attr_reader :struct

      def length
        struct[:AceCount]
      end

      def [](index)
        ace = FFI::Buffer.new :pointer
        unless Win::Security.GetAce(struct.pointer, index, ace)
          Win::Security.raise_last_error
        end
        Win::Security::ACE.new(ace.read_pointer)
      end

      def each
        0.upto(length-1) { |i| yield self[i] }
      end
    end
  end
end
