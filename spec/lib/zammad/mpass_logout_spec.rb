# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'rails_helper'

RSpec.describe Zammad::MpassLogout do
  let(:auth_type)   { 'SSO' }
  let(:portal_url)  { 'https://foss.example.com' }

  before do
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('AUTH_TYPE').and_return(auth_type)
    allow(ENV).to receive(:[]).with(described_class::ENV_NAME).and_return(portal_url)
  end

  describe '.configured_url' do
    context 'when SSO is active' do
      it 'returns the configured URL' do
        expect(described_class.configured_url).to eq(portal_url)
      end

      context 'when the variable is unset' do
        let(:portal_url) { nil }

        it 'returns an empty string' do
          expect(described_class.configured_url).to eq('')
        end
      end

      context 'when the variable is blank' do
        let(:portal_url) { '   ' }

        it 'returns an empty string' do
          expect(described_class.configured_url).to eq('')
        end
      end

      context 'when the variable is not an absolute http(s) URL' do
        it 'rejects relative values' do
          allow(ENV).to receive(:[]).with(described_class::ENV_NAME).and_return('/portal')
          expect(described_class.configured_url).to eq('')
        end

        it 'rejects non-http schemes' do
          allow(ENV).to receive(:[]).with(described_class::ENV_NAME).and_return('javascript:alert(1)')
          expect(described_class.configured_url).to eq('')
        end

        it 'rejects malformed values' do
          allow(ENV).to receive(:[]).with(described_class::ENV_NAME).and_return('https://exa mple.com')
          expect(described_class.configured_url).to eq('')
        end
      end
    end

    context 'when SSO is not active' do
      let(:auth_type) { nil }

      it 'returns an empty string even if the variable is set' do
        expect(described_class.configured_url).to eq('')
      end
    end
  end

  describe '.sync_settings!' do
    it 'creates both settings and stores the portal URL' do
      expect(described_class.sync_settings!).to be(true)

      expect(Setting.get(described_class::SSO_SETTING_NAME)).to be(true)
      expect(Setting.get(described_class::REDIRECT_SETTING_NAME)).to eq(portal_url)
    end

    it 'exposes both settings to the frontend' do
      described_class.sync_settings!

      expect(Setting.where(name: [described_class::SSO_SETTING_NAME, described_class::REDIRECT_SETTING_NAME]).pluck(:frontend)).to all(be(true))
    end

    it 'is idempotent and does not write again when unchanged' do
      described_class.sync_settings!

      allow(Setting).to receive(:set)
      described_class.sync_settings!

      expect(Setting).not_to have_received(:set)
    end

    context 'when SSO is not active' do
      let(:auth_type) { nil }

      it 'clears a previously stored portal URL' do
        allow(ENV).to receive(:[]).with('AUTH_TYPE').and_return('SSO')
        described_class.sync_settings!
        allow(ENV).to receive(:[]).with('AUTH_TYPE').and_return(nil)

        described_class.sync_settings!

        expect(Setting.get(described_class::SSO_SETTING_NAME)).to be(false)
        expect(Setting.get(described_class::REDIRECT_SETTING_NAME)).to eq('')
      end
    end
  end
end
