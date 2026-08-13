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

    %w[user_show_password_login user_lost_password user_create_account].each do |name|
      Setting.set(name, false) if Setting.exists?(name: name)
    end
  end

  Rails.application.config.to_prepare do
    User.include(Zammad::MpassAuthLockdown::UserEmailImmutable)
    Service::User::ChangePassword.prepend(Zammad::MpassAuthLockdown::RejectPasswordChange)
  end
end
