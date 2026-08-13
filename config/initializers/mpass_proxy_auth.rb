# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

if ENV['MPASS_PROXY_AUTH_ENABLED'].present? # rubocop:disable Rails/EnvironmentVariableAccess
  require 'zammad/mpass_proxy_auth'

  Rails
    .application
    .config
    .middleware
    .use Zammad::MpassProxyAuth
end
