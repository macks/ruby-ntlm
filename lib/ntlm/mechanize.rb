require 'mechanize'
require 'ntlm/http'

class Mechanize
  class Chain
    class AuthHeaders

      unless method_defined?(:handle_without_ntlm)
        alias handle_without_ntlm handle
      end

      def handle(ctx, params)
        if @auth_hash[params[:uri].host] == :ntlm && @user && @password
          if @user.index('\\')
            domain, user = @user.split('\\', 2)
          end
          params[:request].ntlm_auth(user, domain, @password)
        end
        handle_without_ntlm(ctx, params)
      end
    end
  end

  unless private_method_defined?(:fetch_page_without_ntlm)
    alias fetch_page_without_ntlm fetch_page
  end

  private

  def fetch_page(params)
    begin
      fetch_page_without_ntlm(params)
    rescue Mechanize::ResponseCodeError => e
      if e.response_code == '401' && e.page.header['www-authenticate'] =~ /NTLM/ && @auth_hash[e.page.uri.host] != :ntlm
        @auth_hash[e.page.uri.host] = :ntlm
        fetch_page_without_ntlm(params)
      else
        raise
      end
    end
  end
end
