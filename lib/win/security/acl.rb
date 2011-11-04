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

      def pointer
        struct.pointer
      end

      def length
        struct[:AceCount]
      end

      def [](index)
        Win::Security::get_ace(pointer, index)
      end

      def each
        0.upto(length-1) { |i| yield self[i] }
      end
    end
  end
end
