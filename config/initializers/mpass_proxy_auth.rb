# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

# Zammad::MpassLogout is autoloaded from lib (config.autoload_lib), no require needed.
# Deliberately outside of the AUTH_TYPE guard: the settings must also be synced
# (back to "off") when a deployment stops using SSO, otherwise a stale portal
# URL would keep hijacking the sign out control.
Rails.application.config.after_initialize do
  Zammad::MpassLogout.sync_settings!
end

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
    {
      'user_show_password_login' => false,
      'user_lost_password'       => false,
      'user_create_account'      => false,
      'system_init_done'         => true,
    }.each do |name, value|
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
