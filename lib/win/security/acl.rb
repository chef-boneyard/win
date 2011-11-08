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

      # Create an ACL with all free slots, passing in the list of sids
      # you plan to allow, deny or audit access to.
      def self.create_uninitialized(sids, &block)
        aces_size = sids.inject(0) { |sum,sid| sum + Win::Security::ACE.size_with_sid(sid) }
        puts ACLStruct.size
        acl_size = align_dword(ACLStruct.size + aces_size + 1094) # What the heck is 94???
        Win::Security.initialize_acl(acl_size, &block)
      end

      def self.create(aces, &block)
        create_uninitialized(aces.map { |ace| ace.sid }) do |acl|
#        aces_size = aces.inject(0) { |sum,ace| sum + ace.size }
#        acl_size = align_dword(ACLStruct.size + aces_size)
#        Win::Security.initialize_acl(acl_size) do |acl|
          aces.each { |ace| Win::Security.add_ace(acl, ace) }
          yield acl
        end
      end

      attr_reader :struct

      def pointer
        struct.pointer
      end

      def [](index)
        Win::Security::get_ace(self, index)
      end

      def delete_at(index)
        Win::Security.delete_ace(self, index)
      end

      def each
        0.upto(length-1) { |i| yield self[i] }
      end

      def insert(index, *aces)
        aces.reverse_each { |ace| Win::Security.add_ace(self, ace, index) }
      end

      def length
        struct[:AceCount]
      end

      def push(*aces)
        aces.each { |ace| Win::Security.add_ace(self, ace) }
      end

      def push_access_allowed(sid, access_mask, flags = 0)
        Win::Security.add_access_allowed_ace_ex(self, sid, access_mask, flags)
      end

      def unshift(*aces)
        aces.each { |ace| Win::Security.add_ace(self, ace, 0) }
      end

      def valid?
        Win::Security.is_valid_acl(self)
      end

      private

      def self.align_dword(size)
        (size + 4 - 1) & 0xfffffffc
      end
    end
  end
end
