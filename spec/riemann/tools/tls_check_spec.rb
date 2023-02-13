# frozen_string_literal: true

require 'riemann/tools/tls_check'

RSpec.describe Riemann::Tools::TLSCheck do
  describe '#test_uri' do
    before do
      allow(subject).to receive(:report)
      subject.test_uri(uri)
    end

    context 'with an expired certificate' do
      let(:uri) { 'https://expired.badssl.com/' }

      it { is_expected.to have_received(:report).with(hash_including({ service: %r{\ATLS certificate https://expired\.badssl\.com/ .*:443 not after\z}, state: 'critical' })) }
    end

    context 'with a self-signed certificate' do
      let(:uri) { 'https://self-signed.badssl.com/' }

      it { is_expected.to have_received(:report).with(hash_including({ service: %r{\ATLS certificate https://self-signed\.badssl\.com/ .*:443 trust\z}, state: 'critical' })) }
    end

    context 'with a wrong host certificate' do
      let(:uri) { 'https://wrong.host.badssl.com/' }

      it { is_expected.to have_received(:report).with(hash_including({ service: %r{\ATLS certificate https://wrong\.host\.badssl\.com/ .*:443 identity\z}, state: 'critical' })) }
    end
  end
end
