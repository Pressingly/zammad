# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

if ENV['AUTH_TYPE'] == 'SSO' # rubocop:disable Rails/EnvironmentVariableAccess
  require 'zammad/mpass_proxy_auth'
  require 'zammad/mpass_auth_lockdown'

  Rails
    .application
    .config
    .middleware
    .use Zammad::MpassProxyAuth

  Rails.application.config.after_initialize do
    begin
      next unless ActiveRecord::Base.connection_pool.with_connection { ActiveRecord::Base.connection.table_exists?('settings') }
    rescue ActiveRecord::ConnectionNotEstablished, ActiveRecord::NoDatabaseError, ActiveRecord::StatementInvalid
      next
    end

    # Under SSO the local credential UI is dead weight, and the guided-setup
    # wizard is actively harmful: its router guard redirects every route to
    # /guided-setup while system_init_done is false, so an already
    # SSO-authenticated user lands on the create-admin sign-up screen instead
    # of the helpdesk. There is no wizard to click through under SSO, so mark
    # the system initialised. The first admin is granted out of band by the
    # bundle's provision-workspaces-admin.sh.
    forced = {
      'user_show_password_login' => false,
      'user_lost_password'       => false,
      'user_create_account'      => false,
      'system_init_done'         => true,
    }

    # Skipping the wizard means nothing else would ever set these. Guided setup
    # is the only in-product writer of fqdn/http_type, and db/seeds.rb early
    # returns once the instance has users, so an already-seeded deployment never
    # picks them up from the environment either. Left alone they stay at the
    # 'zammad.example.com' seed default and every backend-generated URL --
    # notification emails, webhook payloads, OAuth callbacks, the CSP base-uri --
    # points at a dead host.
    fqdn      = ENV['ZAMMAD_FQDN'] # rubocop:disable Rails/EnvironmentVariableAccess
    http_type = ENV['ZAMMAD_HTTP_TYPE'] # rubocop:disable Rails/EnvironmentVariableAccess
    forced['fqdn']      = fqdn if fqdn.present?
    forced['http_type'] = http_type if http_type.present?

    forced.each do |name, value|
      next unless Setting.exists?(name: name)
      next if Setting.get(name) == value

      Setting.set(name, value)
    end
  end

  Rails.application.config.to_prepare do
    User.include(Zammad::MpassAuthLockdown::UserEmailImmutable)
    Service::User::ChangePassword.prepend(Zammad::MpassAuthLockdown::RejectPasswordChange)
  end
end
