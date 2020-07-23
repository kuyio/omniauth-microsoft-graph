# frozen_string_literal: true

require 'omniauth/strategies/oauth2'

# https://docs.microsoft.com/en-us/graph/tutorials/ruby?tutorial-step=3
module OmniAuth
  module Strategies
    # Implements an OmniAuth strategy to get a Microsoft Graph
    # compatible token from Azure AD
    class MicrosoftGraph < OmniAuth::Strategies::OAuth2
      option :name, 'microsoft_graph'

      DEFAULT_SCOPE = 'openid email profile User.Read'

      option :tenant, 'common'

      # Configure the Microsoft identity platform endpoints
      option :client_options,
             site: 'https://login.microsoftonline.com'

      # Send the scope parameter during authorize
      option :authorize_options, [:scope]

      # Unique ID for the user is the id field
      uid { raw_info['id'] }

      # Get additional information after token is retrieved
      extra do
        {
          'raw_info' => raw_info
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
        @raw_info ||= access_token.get('https://graph.microsoft.com/v1.0/me').parsed
      end

      def authorize_params
        super.tap do |params|
          params['scope'.to_sym] = request.params['scope'] if request.params['scope']
          params[:scope] ||= DEFAULT_SCOPE
        end
      end

      # Override callback URL
      # OmniAuth by default passes the entire URL of the callback, including
      # query parameters. Azure fails validation because that doesn't match the
      # registered callback.
      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end
    end
  end
end
