module Win
  module Security
    class SID
      def initialize(pointer, owner = nil)
        @pointer = pointer
        # Keep a reference to the actual owner of this memory so we don't get freed
        @owner = owner
      end

      def self.from_account(name)
        domain, sid, use = Win::Security::lookup_account_name(name)
        sid
      end

      attr_reader :pointer

      def account
        Win::Security::lookup_account_sid(self)
      end

      def account_name
        domain, name, use = account
        (domain != nil && domain.length > 0) ? "#{domain}\\#{name}" : name
      end

      def size
        Win::Security::get_length_sid(self)
      end

      def valid?
        Win::Security::is_valid_sid(self)
      end
    end
  end
end