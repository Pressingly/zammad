# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

module Zammad
  module MpassEdgeTrust
    HEADER            = 'HTTP_X_MPASS_EDGE_SECRET'.freeze
    MIN_SECRET_LENGTH = 32
    PLACEHOLDER_PREFIX = 'CHANGE_ME_'.freeze

    module_function

    def configured(value)
      text = value.to_s.strip
      text.start_with?(PLACEHOLDER_PREFIX) ? '' : text
    end

    def usable_secret?(secret)
      secret.to_s.length >= MIN_SECRET_LENGTH
    end

    # Without a usable secret a direct call on the backend network is
    # indistinguishable from one that passed mPass ForwardAuth, so nothing is trusted.
    def from_edge?(env, secret)
      return false if !usable_secret?(secret)

      ActiveSupport::SecurityUtils.secure_compare(secret, env[HEADER].to_s)
    end
  end
end
