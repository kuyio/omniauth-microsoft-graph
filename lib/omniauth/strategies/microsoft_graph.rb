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

      option :tenant, 'common'

      # Configure the Microsoft identity platform endpoints
      option :client_options, site: 'https://login.microsoftonline.com'

      option :authorize_options, %i[scope state callback_url access_type auth_type prompt response_mode]

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
    end
  end
end
