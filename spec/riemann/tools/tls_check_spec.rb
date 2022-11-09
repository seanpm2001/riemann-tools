# frozen_string_literal: true

require 'active_support'
require 'active_support/core_ext/numeric'

require 'riemann/tools/tls_check'

def gen_certificate(not_before = Time.now, validity_duration_days = 90)
  certificate = OpenSSL::X509::Certificate.new
  certificate.not_before = not_before
  certificate.not_after = certificate.not_before + validity_duration_days.days
  certificate
end

RSpec.describe Riemann::Tools::TLSCheck do
  let(:certificate) do
    gen_certificate(not_before, validity_duration_days)
  end

  let(:not_before) { Time.now }
  let(:validity_duration_days) { 90 }

  describe('#validity_duration') do
    subject { described_class.new.validity_duration(certificate) }

    it { is_expected.to eq(90.days) }
  end

  describe('#renewal_duration') do
    subject { described_class.new.renewal_duration(certificate) }

    context 'with short-lived certificates' do
      it { is_expected.to eq(30.days) }
    end

    context 'with short-lived certificates' do
      let(:validity_duration_days) { 730 }

      it { is_expected.to eq(90.days) }
    end
  end

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
