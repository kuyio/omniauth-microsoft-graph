# frozen_string_literal: true

require 'omniauth/strategies/oauth2'

# https://docs.microsoft.com/en-us/graph/tutorials/ruby?tutorial-step=3
module OmniAuth
  module Strategies
    # Implements an OmniAuth strategy to get a Microsoft Graph
    # compatible token from Azure AD
    class MicrosoftGraph < OmniAuth::Strategies::OAuth2
      option :name, 'microsoft_graph'

      BASE_SCOPE_URL  = 'https://graph.microsoft.com/'
      BASE_SCOPES     = 'offline_access openid email profile'
      DEFAULT_SCOPE   = 'offline_access openid email profile User.Read'

      # Authenticate Home, and Work accounts by default
      # Valid option values are:
      #   'common' for both Microsoft accounts and work or school accounts
      #   'organizations' for work or school accounts only
      #   'consumers' for Microsoft accounts only
      #   'tenant' identifiers such as the tenant ID or domain name.
      option :tenant, 'common'

      # Configure the Microsoft identity platform endpoints
      option :client_options, site: 'https://login.microsoftonline.com'

      # Authorization options sent to Graph
      option :authorize_options, %i[scope state callback_url access_type auth_type prompt response_mode]

      # Authorize additional client_id beyond the one configured for the strategy to exchange access_tokens
      option :authorized_client_ids, []

      # See https://learn.microsoft.com/en-us/graph/permissions-overview?tabs=http#permissions-naming-pattern
      option :scope, DEFAULT_SCOPE

      # Unique ID for the user is the id field
      uid { raw_info['id'] }

      # Get user information from graph
      info do
        {
          'email' => raw_info['mail'] || raw_info['userPrincipalName'],
          'first_name' => raw_info['givenName'],
          'last_name' => raw_info['surname'],
          'fullname' => [raw_info['givenName'], raw_info['surname']].join(' '),
          'name' => raw_info['displayName']
        }
      end

      # Get additional information after token is retrieved
      extra do
        {
          'raw_info' => raw_info,
          'params' => access_token.params,
          'aud' => options.client_id
        }
      end

      def client
        ::OAuth2::Client.new(
          options.client_id,
          options.client_secret,
          deep_symbolize(options.client_options).merge(
            authorize_url: "/#{options.tenant}/oauth2/v2.0/authorize",
            token_url: "/#{options.tenant}/oauth2/v2.0/token"
          )
        )
      end

      # rubocop:disable Metrics/AbcSize
      # rubocop:disable Metrics/MethodLength
      # rubocop:disable Metrics/CyclomaticComplexity
      # rubocop:disable Metrics/PerceivedComplexity
      def get_access_token(request)
        # The OAuth2 provider can transmit a `code` or an `access_token` param, or both
        # when sending the user to our callback_url.
        verifier = request.params['code']
        redirect_uri = request.params['redirect_uri']
        access_token = request.params['access_token']

        if verifier && request.xhr?
          # `code` and it's an AJAX request
          client_get_token(verifier, redirect_uri || '/auth/microsoft_graph/callback')
        elsif verifier
          # `code` and backend request
          client_get_token(verifier, redirect_uri || callback_url)
        elsif access_token && verify_access_token(access_token)
          # `access_token` received, and we verified it was for our client_id
          ::OAuth2::AccessToken.from_hash(client, request.params.dup)
        elsif request.content_type =~ /json/i
          # JSON request may also contain `code`, or `access_token`, or both
          # so follow same flow as above
          begin
            body = JSON.parse(request.body.read)
            request.body.rewind # rewind request body for downstream middlewares
            verifier = body && body['code']
            access_token = body && body['access_token']
            redirect_uri ||= body && body['redirect_uri']
            if verifier
              client_get_token(verifier, redirect_uri || '/auth/microsoft_graph/callback')
            elsif verify_access_token(access_token)
              ::OAuth2::AccessToken.from_hash(client, body.dup)
            end
          rescue JSON::ParserError => e
            warn "[omniauth microsoft-graph] JSON parse error=#{e}"
          end
        end
      end
      # rubocop:enable Metrics/PerceivedComplexity
      # rubocop:enable Metrics/CyclomaticComplexity
      # rubocop:enable Metrics/MethodLength
      # rubocop:enable Metrics/AbcSize

      # Overrides for default OAuth2 strategy
      def custom_build_access_token
        access_token = get_access_token(request)
        access_token
      end

      alias build_access_token custom_build_access_token

      def raw_info
        # Get user profile information from the /me endpoint
        @raw_info ||= access_token.get("#{BASE_SCOPE_URL}/v1.0/me").parsed
      end

      # rubocop:disable Metrics/AbcSize
      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |k|
            params[k] = request.params[k.to_s] unless [nil, ''].include?(request.params[k.to_s])
          end

          params[:scope] = get_scope(params)
          params[:access_type] = 'offline' if params[:access_type].nil?

          session['omniauth.state'] = params[:state] if params[:state]
        end
      end
      # rubocop:enable Metrics/AbcSize

      # Override callback URL
      # OmniAuth by default passes the entire URL of the callback, including
      # query parameters. Azure fails validation because that doesn't match the
      # registered callback.
      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      private

      def get_scope(params)
        raw_scope = params[:scope] || DEFAULT_SCOPE
        scope_list = raw_scope.split(' ').map { |item| item.split(',') }.flatten
        scope_list.join(' ')
      end

      def client_get_token(verifier, redirect_uri)
        client.auth_code.get_token(verifier, get_token_options(redirect_uri), get_token_params)
      end

      def get_token_options(redirect_uri = '')
        { redirect_uri: redirect_uri }.merge(token_params.to_hash(symbolize_keys: true))
      end

      def get_token_params
        deep_symbolize(options.auth_token_params || {})
      end

      def verify_access_token(access_token)
        return false unless access_token

        # Do not blindly call `access_token.get('https://graph.microsoft.com/v1.0/me').parsed`
        # We have to validate that the token was meant for us, or our authorized_client_ids first!
        raw_response = client.request(
          :get,
          "https://#{BASE_SCOPE_URL}/v1.0/me",
          params: { access_token: access_token }
        ).parsed
        (raw_response['aud'] == options.client_id) || options.authorized_client_ids.include?(raw_response['aud'])
      end
    end
  end
end
