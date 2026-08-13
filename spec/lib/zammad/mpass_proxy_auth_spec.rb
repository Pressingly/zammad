# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'rails_helper'

RSpec.describe Zammad::MpassProxyAuth do
  let(:app)        { double('app') } # rubocop:disable RSpec/VerifiedDoubles
  let(:middleware)  { described_class.new(app) }
  let(:session)     { {} }
  let(:env) do
    {
      'rack.session' => session,
    }
  end

  before do
    allow(app).to receive(:call).and_return([200, {}, ['OK']])
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('DEFAULT_EMAIL_DOMAIN').and_return('arbisoft.com')
    allow(ENV).to receive(:[]).with('SMB_CORPORATE_ID').and_return(nil)
    allow(ENV).to receive(:[]).with('MPASS_PROXY_AUTH_ENABLED').and_return('true')
  end

  describe '#call' do
    context 'when no email header is present' do
      it 'passes through to the app' do
        middleware.call(env)
        expect(app).to have_received(:call).with(env)
      end
    end

    context 'when email header contains a full email' do
      before { env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'test.user@arbisoft.com' }

      it 'creates a user and establishes a session' do
        middleware.call(env)

        user = User.find_by(login: 'test.user@arbisoft.com')
        expect(user).to be_present
        expect(session[:user_id]).to eq(user.id)
        expect(session[:persistent]).to be(true)
        expect(session[:authentication_type]).to eq('SSO')
      end

      it 'assigns Agent role to corporate email users' do
        middleware.call(env)

        user = User.find_by(login: 'test.user@arbisoft.com')
        expect(user.role?('Agent')).to be(true)
      end
    end

    context 'when email header contains a bare username' do
      before { env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'test.user' }

      it 'appends DEFAULT_EMAIL_DOMAIN and creates the user' do
        middleware.call(env)

        user = User.find_by(login: 'test.user@arbisoft.com')
        expect(user).to be_present
      end
    end

    context 'when bare username arrives without DEFAULT_EMAIL_DOMAIN' do
      before do
        env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'test.user'
        allow(ENV).to receive(:[]).with('DEFAULT_EMAIL_DOMAIN').and_return(nil)
      end

      it 'returns 403' do
        status, _headers, _body = middleware.call(env)
        expect(status).to eq(403)
      end

      it 'does not call the app' do
        middleware.call(env)
        expect(app).not_to have_received(:call)
      end
    end

    context 'when user already exists in session' do
      let(:user) { create(:agent, login: 'existing@arbisoft.com', email: 'existing@arbisoft.com') }

      before do
        env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'existing@arbisoft.com'
        session[:user_id] = user.id
      end

      it 'passes through without re-establishing session' do
        middleware.call(env)

        expect(app).to have_received(:call)
        expect(session[:user_id]).to eq(user.id)
      end
    end

    context 'when session has a different user (re-key)' do
      let(:old_user) { create(:agent, login: 'old@arbisoft.com', email: 'old@arbisoft.com') }

      before do
        env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'new.user@arbisoft.com'
        session[:user_id] = old_user.id
        session[:switched_from_user_id] = 999
      end

      it 're-keys the session to the new user' do
        middleware.call(env)

        new_user = User.find_by(login: 'new.user@arbisoft.com')
        expect(session[:user_id]).to eq(new_user.id)
      end

      it 'clears switched_from_user_id' do
        middleware.call(env)
        expect(session[:switched_from_user_id]).to be_nil
      end
    end

    context 'when user is inactive' do
      let!(:user) { create(:agent, login: 'inactive@arbisoft.com', email: 'inactive@arbisoft.com', active: false) }

      before { env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'inactive@arbisoft.com' }

      it 'returns 403' do
        status, _headers, _body = middleware.call(env)
        expect(status).to eq(403)
      end
    end

    context 'with non-corporate email' do
      before do
        env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'external@gmail.com'
      end

      it 'assigns signup role (Customer) instead of Agent' do
        middleware.call(env)

        user = User.find_by(login: 'external@gmail.com')
        expect(user.role?('Agent')).to be(false)
        expect(user.role?('Customer')).to be(true)
      end
    end

    context 'when a Customer with corporate email logs in' do
      let!(:customer) { create(:customer, login: 'promoted@arbisoft.com', email: 'promoted@arbisoft.com') }

      before { env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'promoted@arbisoft.com' }

      it 'promotes to Agent' do
        expect(customer.role?('Agent')).to be(false)

        middleware.call(env)

        customer.reload
        expect(customer.role?('Agent')).to be(true)
      end
    end

    context 'when maintenance mode is enabled' do
      let!(:agent) { create(:agent, login: 'maint.agent@arbisoft.com', email: 'maint.agent@arbisoft.com') }

      before do
        Setting.set('maintenance_mode', true)
        env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'maint.agent@arbisoft.com'
      end

      after { Setting.set('maintenance_mode', false) }

      it 'returns 403 for non-admin users' do
        status, _headers, _body = middleware.call(env)
        expect(status).to eq(403)
      end
    end

    context 'when maintenance mode is enabled for admin' do
      let!(:admin) { create(:admin, login: 'maint.admin@arbisoft.com', email: 'maint.admin@arbisoft.com') }

      before do
        Setting.set('maintenance_mode', true)
        env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'maint.admin@arbisoft.com'
      end

      after { Setting.set('maintenance_mode', false) }

      it 'allows admin users through' do
        middleware.call(env)
        expect(session[:user_id]).to eq(admin.id)
      end
    end
  end

  describe 'corporate-ID enforcement' do
    before do
      allow(ENV).to receive(:[]).with('SMB_CORPORATE_ID').and_return('corp-123')
      env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'test@arbisoft.com'
    end

    context 'when no access token header is present' do
      it 'returns 403' do
        status, _headers, _body = middleware.call(env)
        expect(status).to eq(403)
      end
    end

    context 'when access token has matching corporate_id' do
      before do
        payload = { 'custom:is_corporate' => 'true', 'custom:corporate_id' => 'corp-123' }
        token = "header.#{Base64.urlsafe_encode64(JSON.generate(payload))}.signature"
        env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = token
      end

      it 'allows the request through' do
        middleware.call(env)
        expect(app).to have_received(:call)
      end
    end

    context 'when access token has mismatched corporate_id' do
      before do
        payload = { 'custom:is_corporate' => 'true', 'custom:corporate_id' => 'wrong-corp' }
        token = "header.#{Base64.urlsafe_encode64(JSON.generate(payload))}.signature"
        env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = token
      end

      it 'returns 403' do
        status, _headers, _body = middleware.call(env)
        expect(status).to eq(403)
      end
    end

    context 'when access token has is_corporate=false' do
      before do
        payload = { 'custom:is_corporate' => 'false', 'custom:corporate_id' => 'corp-123' }
        token = "header.#{Base64.urlsafe_encode64(JSON.generate(payload))}.signature"
        env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = token
      end

      it 'returns 403' do
        status, _headers, _body = middleware.call(env)
        expect(status).to eq(403)
      end
    end

    context 'when access token is malformed' do
      before do
        env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = 'not-a-jwt'
      end

      it 'returns 403' do
        status, _headers, _body = middleware.call(env)
        expect(status).to eq(403)
      end
    end
  end

  describe 'email normalization' do
    before { env['HTTP_X_AUTH_REQUEST_EMAIL'] = '  Test.User@Arbisoft.COM  ' }

    it 'lowercases and trims the email' do
      middleware.call(env)
      user = User.find_by(login: 'test.user@arbisoft.com')
      expect(user).to be_present
    end
  end
end
