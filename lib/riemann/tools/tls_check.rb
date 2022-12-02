# frozen_string_literal: true

require 'net/http'
require 'resolv'

require 'riemann/tools'
require 'riemann/tools/utils'

module URI
  {
    'IMAP'     => 143,
    'IMAPS'    => 993,
    'MYSQL'    => 3306,
    'POSTGRES' => 5432,
  }.each do |scheme, port|
    klass = Class.new(Generic)
    klass.const_set('DEFAULT_PORT', port)

    if Gem::Version.new(RUBY_VERSION.dup) < Gem::Version.new('3.1.0')
      @@schemes[scheme] = klass
    else
      register_scheme(scheme, klass)
    end
  end
end

module Riemann
  module Tools
    class TLSCheck
      include Riemann::Tools
      include Riemann::Tools::Utils

      opt :uri, 'URI to check', short: :none, type: :strings
      opt :checks, 'A list of checks to run.', short: :none, type: :strings, default: %w[identity not-after not-before ocsp trust]

      opt :renewal_duration_days, 'Number of days before certificate expiration it is considered renewalable', short: :none, type: :integer, default: 90
      opt :renewal_duration_ratio, 'Portion of the certificate lifespan it is considered renewalable', short: :none, type: :float, default: 1.0 / 3

      opt :trust, 'Additionnal CA to trust', short: :none, type: :strings, default: []

      def tick
        opts[:uri].each do |uri|
          test_uri(uri)
        end
      end

      def test_uri(uri)
        uri = URI(uri)

        with_each_address(uri.host) do |address|
          test_uri_address(uri, address)
        end
      end

      def test_uri_address(uri, address)
        socket = tls_socket(uri, address)
        return unless socket.peer_cert

        report_not_before(uri, address, socket) if opts[:checks].include?('not-before')
        report_not_after(uri, address, socket) if opts[:checks].include?('not-after')
        report_identity(uri, address, socket) if opts[:checks].include?('identity')
        report_trust(uri, address, socket) if opts[:checks].include?('trust')
        report_ocsp(uri, address, socket) if opts[:checks].include?('ocsp')
      end

      def report_not_after(uri, address, socket)
        report(
          service: "TLS certificate #{uri} #{endpoint_name(IPAddr.new(address), uri.port)} not after",
          state: not_after_state(socket.peer_cert),
          metric: socket.peer_cert.not_after - now,
          description: when_from_now(socket.peer_cert.not_after),

          hostname: uri.host,
          address: address,
          port: uri.port,
        )
      end

      def report_not_before(uri, address, socket)
        report(
          service: "TLS certificate #{uri} #{endpoint_name(IPAddr.new(address), uri.port)} not before",
          state: not_before_state(socket.peer_cert),
          metric: socket.peer_cert.not_before - now,
          description: when_from_now(socket.peer_cert.not_before),

          hostname: uri.host,
          address: address,
          port: uri.port,
        )
      end

      def report_identity(uri, address, socket)
        report(
          service: "TLS certificate #{uri} #{endpoint_name(IPAddr.new(address), uri.port)} identity",
          state: OpenSSL::SSL.verify_certificate_identity(socket.peer_cert, uri.host) ? 'ok' : 'critical',
          description: "Valid for:\n#{acceptable_identities(socket.peer_cert).join("\n")}",

          hostname: uri.host,
          address: address,
          port: uri.port,
        )
      end

      def report_trust(uri, address, socket)
        report(
          service: "TLS certificate #{uri} #{endpoint_name(IPAddr.new(address), uri.port)} trust",
          state: store.verify(socket.peer_cert, socket.peer_cert_chain) ? 'ok' : 'critical',
          description: "Certificate chain:\n#{socket.peer_cert_chain.map { |cert| cert.subject.to_s }.join("\n")}",

          hostname: uri.host,
          address: address,
          port: uri.port,
        )
      end

      def report_ocsp(uri, address, socket)
        subject = socket.peer_cert
        issuer = socket.peer_cert_chain[1]

        return unless issuer

        digest = OpenSSL::Digest.new('SHA1')
        certificate_id = OpenSSL::OCSP::CertificateId.new(subject, issuer, digest)

        request = OpenSSL::OCSP::Request.new
        request.add_certid(certificate_id)

        request.add_nonce

        authority_info_access = subject.extensions.find do |extension|
          extension.oid == 'authorityInfoAccess'
        end

        descriptions = authority_info_access.value.split("\n")
        ocsp = descriptions.find do |description|
          description.start_with? 'OCSP'
        end

        ocsp_uri = URI(ocsp[/URI:(.*)/, 1])

        http_response = ::Net::HTTP.start(ocsp_uri.hostname, ocsp_uri.port) do |http|
          ocsp_uri.path = '/' if ocsp_uri.path.empty?
          http.post(ocsp_uri.path, request.to_der, 'content-type' => 'application/ocsp-request')
        end

        response = OpenSSL::OCSP::Response.new http_response.body
        response_basic = response.basic

        return unless response_basic&.verify([issuer], store)

        report(
          service: "TLS certificate #{uri} #{endpoint_name(IPAddr.new(address), uri.port)} OCSP status",
          state: response.status_string == 'successful' ? 'ok' : 'critical',
          description: response.status_string,

          hostname: uri.host,
          address: address,
          port: uri.port,
        )
      end

      def acceptable_identities(certificate)
        res = []

        certificate.extensions.each do |ext|
          next unless ext.oid == 'subjectAltName'

          ostr = OpenSSL::ASN1.decode(ext.to_der).value.last
          sequence = OpenSSL::ASN1.decode(ostr.value)
          res = sequence.value.map(&:value)
        end

        res << certificate.subject.to_s unless res.any?

        res
      end

      def renewal_duration(certificate)
        [validity_duration(certificate) * opts[:renewal_duration_ratio], opts[:renewal_duration_days] * 3600 * 24].min
      end

      #      not_before                      not_after
      #          |<----------------------------->|         validity_duration
      # …ccccccccoooooooooooooooooooooooooooooooooooooo…   not_before_state
      #
      #       time --->>>>
      def not_before_state(certificate)
        not_valid_yet?(certificate) ? 'critical' : 'ok'
      end

      #      not_before                      not_after
      #          |<----------------------------->|         validity_duration
      #                              |<--------->|         renewal_duration
      #                              | ⅓ | ⅓ | ⅓ |
      # …oooooooooooooooooooooooooooooooowwwwcccccccccc…   not_after_state
      #
      #       time --->>>>
      def not_after_state(certificate)
        if expired_or_expire_soon?(certificate)
          'critical'
        elsif expire_soonish?(certificate)
          'warning'
        else
          'ok'
        end
      end

      def not_valid_yet?(certificate)
        now < certificate.not_before
      end

      def expired_or_expire_soon?(certificate)
        now + renewal_duration(certificate) / 3 > certificate.not_after
      end

      def expired?(certificate)
        now > certificate.not_after
      end

      def expire_soonish?(certificate)
        now + 2 * renewal_duration(certificate) / 3 > certificate.not_after
      end

      def validity_duration(certificate)
        certificate.not_after - certificate.not_before
      end

      def tls_socket(uri, address)
        case uri.scheme
        when 'smtp'
          smtp_tls_socket(uri, address)
        when 'imap'
          imap_tls_socket(uri, address)
        when 'ldap'
          ldap_tls_socket(uri, address)
        when 'mysql'
          mysql_tls_socket(uri, address)
        when 'postgres'
          postgres_tls_socket(uri, address)
        else
          raw_tls_socket(uri, address)
        end
      end

      def mysql_tls_socket(uri, address)
        socket = TCPSocket.new(address, uri.port)
        length = "#{socket.read(3)}\0".unpack1('L*')
        _sequence = socket.read(1)
        body = socket.read(length)
        initial_handshake_packet = body.unpack('cZ*La8aScSS')

        capabilities = initial_handshake_packet[5] | (initial_handshake_packet[8] << 16)

        ssl_flag = 1 << 11
        raise 'No TLS support' if (capabilities & ssl_flag).zero?

        socket.write(['2000000185ae7f0000000001210000000000000000000000000000000000000000000000'].pack('H*'))
        tls_handshake(socket, uri.host)
      end

      def postgres_tls_socket(uri, address)
        socket = TCPSocket.new(address, uri.port)
        socket.write(['0000000804d2162f'].pack('H*'))
        raise 'Unexpected reply' unless socket.read(1) == 'S'

        tls_handshake(socket, uri.host)
      end

      def smtp_tls_socket(uri, address)
        socket = TCPSocket.new(address, uri.port)
        until socket.gets =~ /^220 /
        end
        socket.puts("EHLO #{my_hostname}")
        until socket.gets =~ /^250 /
        end
        socket.puts('STARTTLS')
        socket.gets

        tls_handshake(socket, uri.host)
      end

      def my_hostname
        Addrinfo.tcp(Socket.gethostname, 8023).getnameinfo.first
      rescue SocketError
        Socket.gethostname
      end

      def imap_tls_socket(uri, address)
        socket = TCPSocket.new(address, uri.port)
        until socket.gets =~ /^\* OK/
        end
        socket.puts('. CAPABILITY')
        until socket.gets =~ /^\. OK/
        end
        socket.puts('. STARTTLS')
        until socket.gets =~ /^\. OK/
        end

        tls_handshake(socket, uri.host)
      end

      def ldap_tls_socket(uri, address)
        socket = TCPSocket.new(address, uri.port)
        socket.write(['301d02010177188016312e332e362e312e342e312e313436362e3230303337'].pack('H*'))
        expected_res = ['300c02010178070a010004000400'].pack('H*')
        res = socket.read(expected_res.length)

        return nil unless res == expected_res

        tls_handshake(socket, uri.host)
      end

      def raw_tls_socket(uri, address)
        raise "No default port for #{uri.scheme} scheme" unless uri.port

        socket = TCPSocket.new(address, uri.port)
        tls_handshake(socket, uri.host)
      end

      def tls_handshake(raw_socket, hostname)
        tls_socket = OpenSSL::SSL::SSLSocket.new(raw_socket)
        tls_socket.hostname = hostname
        begin
          tls_socket.connect
        rescue OpenSSL::SSL::SSLError
          # This may fail for example if a client certificate is required
        end
        tls_socket
      end

      def ssl_context
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.set_params(tls_options)
        ssl_context
      end

      def tls_options
        {
          verify_mode: OpenSSL::SSL::VERIFY_PEER,
        }
      end

      def store
        @store ||= begin
          store = OpenSSL::X509::Store.new
          store.set_default_paths
          opts[:trust].each do |path|
            if File.directory?(path)
              store.add_path(path)
            else
              store.add_file(path)
            end
          end
          store
        end
      end
    end
  end
end
