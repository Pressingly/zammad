# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'rails_helper'

RSpec.describe 'HTTP access log header redaction', type: :request do
  let(:logged_request) { HttpLog.where(facility: 'cti').last.request[:content] }

  before do
    Setting.set('cti_integration', true)
    post "/api/v1/cti/#{Setting.get('cti_token')}",
         params:  { event: 'newCall', direction: 'in', from: '4912347114711', to: '4930600000000', call_id: '1', user: 'user 1' },
         headers: {
           'X-Mpass-Edge-Secret'         => 'edge-secret-value',
           'X-Auth-Request-Access-Token' => 'access-token-value',
           'X-Custom-Header'             => 'kept-value',
         }
  end

  it 'masks the edge secret and the forwarded access token' do
    expect(logged_request).to include('HTTP_X_MPASS_EDGE_SECRET: [FILTERED]', 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN: [FILTERED]')
      .and(satisfy { |content| content.exclude?('edge-secret-value') && content.exclude?('access-token-value') })
  end

  it 'still logs other headers' do
    expect(logged_request).to include('HTTP_X_CUSTOM_HEADER: kept-value')
  end
end
