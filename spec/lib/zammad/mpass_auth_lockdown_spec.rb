# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'rails_helper'

RSpec.describe Zammad::MpassAuthLockdown do
  before do
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('MPASS_PROXY_AUTH_ENABLED').and_return('true')
  end

  describe Zammad::MpassAuthLockdown::UserEmailImmutable do
    before do
      User.include(described_class) unless User.ancestors.include?(described_class)
    end

    context 'when SSO is active' do
      let(:user) { create(:agent, email: 'original@example.com') }

      it 'prevents email change by non-system users' do
        user.email = 'changed@example.com'
        expect(user.save).to be(false)
        expect(user.errors[:email]).to include(match(/SSO/))
      end

      it 'allows email change by system user (user_id=1)' do
        UserInfo.current_user_id = 1
        user.email = 'changed@example.com'
        expect(user.save).to be(true)
      ensure
        UserInfo.current_user_id = nil
      end
    end

    context 'when SSO is not active' do
      before do
        allow(ENV).to receive(:[]).with('MPASS_PROXY_AUTH_ENABLED').and_return(nil)
      end

      let(:user) { create(:agent, email: 'original@example.com') }

      it 'allows email change' do
        user.email = 'changed@example.com'
        expect(user.save).to be(true)
      end
    end
  end

  describe Zammad::MpassAuthLockdown::RejectPasswordChange do
    before do
      Service::User::ChangePassword.prepend(described_class) unless Service::User::ChangePassword.ancestors.include?(described_class)
    end

    context 'when SSO is active' do
      let(:user) { create(:user, password: 'password') }

      it 'raises Forbidden' do
        expect do
          described_class.with_current_user(user).execute(
            current_password: 'password',
            new_password:     'Test1234!new',
          )
        end.to raise_error(Exceptions::Forbidden, /SSO/)
      end
    end

    context 'when SSO is not active' do
      before do
        allow(ENV).to receive(:[]).with('MPASS_PROXY_AUTH_ENABLED').and_return(nil)
        Setting.set('user_show_password_login', true)
      end

      let(:user) { create(:user, password: 'password') }

      it 'allows password change' do
        expect do
          described_class.with_current_user(user).execute(
            current_password: 'password',
            new_password:     'ITest1234!changed',
          )
        end.not_to raise_error
      end
    end
  end
end
