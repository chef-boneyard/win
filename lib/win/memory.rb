require 'win/library'
require 'win/error'

module Win
  module Memory
    extend Win::Library

    LMEM_FIXED          = 0x0000
    LMEM_MOVEABLE       = 0x0002
    LMEM_NOCOMPACT      = 0x0010
    LMEM_NODISCARD      = 0x0020
    LMEM_ZEROINIT       = 0x0040
    LMEM_MODIFY         = 0x0080
    LMEM_DISCARDABLE    = 0x0F00
    LMEM_VALID_FLAGS    = 0x0F72
    LMEM_INVALID_HANDLE = 0x8000
    LHND                = LMEM_MOVEABLE | LMEM_ZEROINIT
    LPTR                = LMEM_FIXED | LMEM_ZEROINIT
    NONZEROLHND         = LMEM_MOVEABLE
    NONZEROLPTR         = LMEM_FIXED
    LMEM_DISCARDED      = 0x4000
    LMEM_LOCKCOUNT      = 0x00FF

    function :LocalAlloc, [ :UINT, :SIZE_T ], :pointer
    def self.local_alloc(length, flags = LPTR, &block)
      result = LocalAlloc(flags, length)
      if result.null?
        Win::Error.raise_last_error
      end
      # If a block is passed, handle freeing the memory at the end
      if block != nil
        begin
          yield result
        ensure
          local_free(result)
        end
      else
        result
      end
    end

    # This is a macro 
    def LocalDiscard(pointer)
      LocalReAlloc(pointer, 0, LMEM_MOVEABLE)
    end
    def local_discard(pointer)
      local_realloc(pointer, 0, LMEM_MOVEABLE)
    end

    function :LocalFlags, [ :pointer ], :UINT
    def self.local_flags(pointer)
      result = LocalFlags(pointer)
      if result == LMEM_INVALID_HANDLE
        Win::Error.raise_last_error
      end
      [ result & ~LMEM_LOCKCOUNT, result & LMEM_LOCKCOUNT ]
    end

    function :LocalFree, [ :pointer ], :pointer
    def self.local_free(pointer)
      result = LocalFree(pointer)
      if !result.null?
        Win::Error.raise_last_error
      end
    end

    function :LocalReAlloc, [ :pointer, :SIZE_T, :UINT ], :pointer
    def self.local_realloc(pointer, size, flags = LMEM_MOVEABLE | LMEM_ZEROINIT)
      result = LocalReAlloc(pointer, size, flags)
      if result.null?
        Win::Error.raise_last_error
      end
      result
    end

    function :LocalSize, [ :pointer ], :SIZE_T
    def self.local_size(pointer)
      result = LocalSize(pointer)
      if result == 0
        Win::Error.raise_last_error
      end
      result
    end

    # memory allocators
    function :malloc, [:size_t], :pointer, :dll => FFI::Library::LIBC
    function :calloc, [:size_t], :pointer, :dll => FFI::Library::LIBC
    try_function :valloc, [:size_t], :pointer, :dll => FFI::Library::LIBC
    function :realloc, [:pointer, :size_t], :pointer, :dll => FFI::Library::LIBC
    function :free, [:pointer], :void, :dll => FFI::Library::LIBC
    
    # memory movers
    function :memcpy, [:pointer, :pointer, :size_t], :pointer, :dll => FFI::Library::LIBC
    try_function :bcopy, [:pointer, :pointer, :size_t], :void, :dll => FFI::Library::LIBC
  end
end