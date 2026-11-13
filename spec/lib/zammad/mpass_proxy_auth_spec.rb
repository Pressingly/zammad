# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'rails_helper'

RSpec.describe Zammad::MpassProxyAuth, :aggregate_failures, :mpass_token do
  let(:edge_secret)  { 'e' * 64 }
  let(:corporate_id) { '' }
  let(:app)          { double('app') } # rubocop:disable RSpec/VerifiedDoubles
  let(:middleware)   { described_class.new(app, edge_secret: edge_secret, corporate_id: corporate_id, token_verifier: mpass_test_verifier) }
  let(:session)      { {} }
  let(:env) do
    {
      'rack.session'             => session,
      'PATH_INFO'                => '/api/v1/users/me',
      'REMOTE_ADDR'              => '172.18.0.9',
      'HTTP_X_MPASS_EDGE_SECRET' => edge_secret,
    }
  end

  before do
    allow(app).to receive(:call).and_return([200, {}, ['OK']])
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('DEFAULT_EMAIL_DOMAIN').and_return('arbisoft.com')
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

      it 'creates a user and establishes a session', :aggregate_failures do
        middleware.call(env)

        user = User.find_by(login: 'test.user@arbisoft.com')
        expect(user).to be_present
        expect(session[:user_id]).to eq(user.id)
        expect(session[:persistent]).to be(true)
        expect(session[:authentication_type]).to eq('SSO')
      end

      it 'assigns the signup role, never Agent, regardless of email domain', :aggregate_failures do
        middleware.call(env)

        user = User.find_by(login: 'test.user@arbisoft.com')
        expect(user.role?('Agent')).to be(false)
        expect(user.role?('Customer')).to be(true)
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

      it 'passes through without re-establishing session', :aggregate_failures do
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
      before do
        create(:agent, login: 'inactive@arbisoft.com', email: 'inactive@arbisoft.com', active: false)
        env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'inactive@arbisoft.com'
      end

      it 'returns 403' do
        status, _headers, _body = middleware.call(env)
        expect(status).to eq(403)
      end
    end

    context 'with an email outside DEFAULT_EMAIL_DOMAIN' do
      before do
        env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'external@gmail.com'
      end

      it 'assigns signup role (Customer) instead of Agent', :aggregate_failures do
        middleware.call(env)

        user = User.find_by(login: 'external@gmail.com')
        expect(user.role?('Agent')).to be(false)
        expect(user.role?('Customer')).to be(true)
      end
    end

    context 'when an existing Customer logs in again' do
      let!(:customer) { create(:customer, login: 'promoted@arbisoft.com', email: 'promoted@arbisoft.com') }

      before { env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'promoted@arbisoft.com' }

      it 'never auto-promotes to Agent', :aggregate_failures do
        expect(customer.role?('Agent')).to be(false)

        middleware.call(env)

        # Anchor the non-transition: without this the example would still pass
        # if the middleware started rejecting the request outright.
        expect(session[:user_id]).to eq(customer.id)

        customer.reload
        expect(customer.role?('Agent')).to be(false)
        expect(customer.role?('Customer')).to be(true)
      end
    end

    context 'when maintenance mode is enabled' do
      before do
        create(:agent, login: 'maint.agent@arbisoft.com', email: 'maint.agent@arbisoft.com')
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

  describe 'edge trust' do
    let(:agent) { create(:agent, login: 'victim@arbisoft.com', email: 'victim@arbisoft.com') }

    before do
      env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'victim@arbisoft.com'
      env['HTTP_X_AUTH_REQUEST_USER'] = '1234567890123456'
      allow(Rails.logger).to receive(:warn)
    end

    shared_examples 'ignores the identity headers' do
      it 'does not sign anyone in' do
        middleware.call(env)
        expect(session[:user_id]).to be_nil
      end

      it 'does not create the asserted user' do
        middleware.call(env)
        expect(User.find_by(login: 'victim@arbisoft.com')).to be_nil
      end

      it 'passes the request on without the identity headers' do
        middleware.call(env)
        expect(app).to have_received(:call).with(hash_excluding('HTTP_X_AUTH_REQUEST_EMAIL', 'HTTP_X_AUTH_REQUEST_USER'))
      end

      it 'keeps an existing session instead of re-keying or ending it' do
        session[:user_id] = agent.id
        middleware.call(env)
        expect(session[:user_id]).to eq(agent.id)
      end

      it 'logs the mPass id, path and remote address, never the email' do
        middleware.call(env)
        expect(Rails.logger).to have_received(:warn).with(
          a_string_including('identity headers ignored', 'mpass_id=1234567890123456', 'path=/api/v1/users/me', 'remote_addr=172.18.0.9')
            .and(satisfy { |line| line.exclude?('victim@arbisoft.com') })
        )
      end
    end

    context 'without the edge secret header' do
      before { env.delete('HTTP_X_MPASS_EDGE_SECRET') }

      it_behaves_like 'ignores the identity headers'
    end

    context 'with a wrong edge secret' do
      before { env['HTTP_X_MPASS_EDGE_SECRET'] = 'x' * 64 }

      it_behaves_like 'ignores the identity headers'
    end

    context 'with a secret that is a prefix of the real one' do
      before { env['HTTP_X_MPASS_EDGE_SECRET'] = edge_secret[0, 32] }

      it_behaves_like 'ignores the identity headers'
    end

    context 'when the configured secret is shorter than 32 characters' do
      let(:edge_secret) { 'short-secret' }

      it_behaves_like 'ignores the identity headers'

      it 'logs a startup error' do
        allow(Rails.logger).to receive(:error)
        middleware
        expect(Rails.logger).to have_received(:error).with(a_string_including('MPASS_EDGE_SECRET'))
      end
    end

    context 'when no secret is configured' do
      let(:edge_secret) { '' }

      before { env['HTTP_X_MPASS_EDGE_SECRET'] = '' }

      it_behaves_like 'ignores the identity headers'
    end

    context 'with the correct edge secret' do
      it 'signs the asserted user in' do
        middleware.call(env)
        expect(session[:user_id]).to eq(User.find_by(login: 'victim@arbisoft.com').id)
      end
    end

    it 'never passes the edge secret on to the app' do
      middleware.call(env)
      expect(app).to have_received(:call).with(hash_excluding('HTTP_X_MPASS_EDGE_SECRET'))
    end
  end

  describe 'API token and session requests' do
    let(:agent) { create(:agent) }

    it 'leaves a token-only request untouched' do
      env.delete('HTTP_X_MPASS_EDGE_SECRET')
      env['HTTP_AUTHORIZATION'] = 'Token token=minted-by-zammad-mcp'
      middleware.call(env)
      expect(app).to have_received(:call).with(hash_including('HTTP_AUTHORIZATION' => 'Token token=minted-by-zammad-mcp'))
      expect(session).to be_empty
    end

    it 'leaves a cookie session without identity headers untouched' do
      env.delete('HTTP_X_MPASS_EDGE_SECRET')
      session[:user_id] = agent.id
      middleware.call(env)
      expect(session[:user_id]).to eq(agent.id)
    end
  end

  describe 'corporate-ID enforcement' do
    let(:corporate_id) { 'corp-123' }

    before do
      env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'test@arbisoft.com'
      env['HTTP_X_AUTH_REQUEST_USER'] = '1234567890123456'
      allow(Rails.logger).to receive(:warn)
    end

    shared_examples 'refuses the login' do |reason|
      it 'returns 403 without calling the app' do
        status, _headers, body = middleware.call(env)
        expect([status, body]).to eq([403, ['{"error":"access_denied"}']])
        expect(app).not_to have_received(:call)
      end

      it "logs reason=#{reason} without the email or the expected corporate id" do
        middleware.call(env)
        expect(Rails.logger).to have_received(:warn).with(
          a_string_including("reason=#{reason}", 'mpass_id=1234567890123456')
            .and(satisfy { |line| line.exclude?('test@arbisoft.com') && line.exclude?('corp-123') })
        )
      end

      it 'does not create the user' do
        middleware.call(env)
        expect(User.find_by(login: 'test@arbisoft.com')).to be_nil
      end
    end

    context 'when no access token header is present' do
      it_behaves_like 'refuses the login', 'missing_token'
    end

    context 'when the session already holds the asserted user' do
      let(:user) { create(:agent, login: 'test@arbisoft.com', email: 'test@arbisoft.com') }

      before do
        session[:user_id] = user.id
        env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token(mpass_access_claims('iat' => Time.now.to_i - 7200, 'exp' => Time.now.to_i - 3600))
      end

      it 'passes through without re-checking the token' do
        middleware.call(env)
        expect(app).to have_received(:call)
        expect(session[:user_id]).to eq(user.id)
      end
    end

    context 'when the session holds another user' do
      let(:other) { create(:agent, login: 'other@arbisoft.com', email: 'other@arbisoft.com') }

      before do
        session[:user_id] = other.id
        env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token(mpass_access_claims('iat' => Time.now.to_i - 7200, 'exp' => Time.now.to_i - 3600))
      end

      it_behaves_like 'refuses the login', 'expired'

      it 'keeps the existing session' do
        middleware.call(env)
        expect(session[:user_id]).to eq(other.id)
      end
    end

    context 'when an existing user without a session presents an expired token' do
      before do
        create(:agent, login: 'test@arbisoft.com', email: 'test@arbisoft.com')
        env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token(mpass_access_claims('iat' => Time.now.to_i - 7200, 'exp' => Time.now.to_i - 3600))
      end

      it 'refuses to open a session' do
        status, _headers, _body = middleware.call(env)
        expect(status).to eq(403)
        expect(session[:user_id]).to be_nil
      end
    end

    context 'when the token is valid and matches the corporate id' do
      before { env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token }

      it 'signs the user in' do
        middleware.call(env)
        expect(session[:user_id]).to eq(User.find_by(login: 'test@arbisoft.com').id)
      end
    end

    context 'when the token names another organization' do
      before { env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token(mpass_access_claims('custom:corporate_id' => 'wrong-corp')) }

      it_behaves_like 'refuses the login', 'wrong_organization'
    end

    context 'when the token says is_corporate=false' do
      before { env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token(mpass_access_claims('custom:is_corporate' => 'false')) }

      it_behaves_like 'refuses the login', 'not_corporate'
    end

    context 'when the token is unsigned base64 with the right claims' do
      before do
        payload = Base64.urlsafe_encode64(JSON.generate(mpass_access_claims), padding: false)
        env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.#{payload}.#{Base64.urlsafe_encode64(SecureRandom.bytes(256), padding: false)}"
      end

      it_behaves_like 'refuses the login', 'bad_signature'
    end

    context 'when the token is signed by another key' do
      before { env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token(key: OpenSSL::PKey::RSA.generate(2048)) }

      it_behaves_like 'refuses the login', 'bad_signature'
    end

    context 'when the token has expired' do
      before { env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token(mpass_access_claims('iat' => Time.now.to_i - 7200, 'exp' => Time.now.to_i - 3600)) }

      it_behaves_like 'refuses the login', 'expired'
    end

    context 'when the token comes from another issuer' do
      before { env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token(mpass_access_claims('iss' => 'https://evil.example.test')) }

      it_behaves_like 'refuses the login', 'untrusted_issuer'
    end

    context 'when the token was issued to another client' do
      before { env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token(mpass_access_claims('client_id' => 'other')) }

      it_behaves_like 'refuses the login', 'wrong_audience'
    end

    context 'when the token is HS256' do
      before { env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token(key: 'shared-secret', algorithm: 'HS256') }

      it_behaves_like 'refuses the login', 'invalid'
    end

    context 'when the token is malformed' do
      before { env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = 'not-a-jwt' }

      it_behaves_like 'refuses the login', 'malformed'
    end

    context 'when the JWKS cannot be fetched' do
      let(:middleware) do
        failing = Zammad::MpassJwksCache.new(fetcher: ->(_url) { raise Errno::ECONNREFUSED })
        described_class.new(app, edge_secret: edge_secret, corporate_id: corporate_id, token_verifier: mpass_test_verifier(jwks_cache: failing))
      end

      before { env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token }

      it_behaves_like 'refuses the login', 'jwks_unavailable'
    end

    context 'when the verifier has no issuer or client id' do
      let(:middleware) do
        described_class.new(app, edge_secret: edge_secret, corporate_id: corporate_id, token_verifier: mpass_test_verifier(client_ids: []))
      end

      before { env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = mpass_token }

      it_behaves_like 'refuses the login', 'verifier_unconfigured'

      it 'logs a startup error' do
        allow(Rails.logger).to receive(:error)
        middleware
        expect(Rails.logger).to have_received(:error).with(a_string_including('SMB_CORPORATE_ID is set'))
      end
    end
  end

  describe 'with the corporate gate off' do
    let(:jwks_fetcher) { ->(_url) { raise 'JWKS must not be fetched' } }
    let(:middleware) do
      verifier = mpass_test_verifier(jwks_cache: Zammad::MpassJwksCache.new(fetcher: jwks_fetcher))
      described_class.new(app, edge_secret: edge_secret, corporate_id: '', token_verifier: verifier)
    end

    before do
      env['HTTP_X_AUTH_REQUEST_EMAIL'] = 'nogate@arbisoft.com'
      env['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'] = 'not-a-jwt'
    end

    it 'signs the user in without reading the token or fetching the JWKS' do
      middleware.call(env)
      expect(session[:user_id]).to eq(User.find_by(login: 'nogate@arbisoft.com').id)
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
