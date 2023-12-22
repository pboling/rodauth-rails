require "test_helper"

Rails.application.load_tasks

class RakeTest < ActiveSupport::TestCase
  test "rodauth:routes prints routes" do
    stdout, _ = capture_io do
      Rake::Task["rodauth:routes"].invoke
    end

    expected_output = <<~EOS
      Routes handled by RodauthApp:

        GET|POST  /login                   rodauth.login_path
        GET|POST  /create-account          rodauth.create_account_path
        GET|POST  /verify-account-resend   rodauth.verify_account_resend_path
        GET|POST  /verify-account          rodauth.verify_account_path
        GET|POST  /remember                rodauth.remember_path
        GET|POST  /logout                  rodauth.logout_path
        GET|POST  /reset-password-request  rodauth.reset_password_request_path
        GET|POST  /reset-password          rodauth.reset_password_path
        GET|POST  /change-password         rodauth.change_password_path
        GET|POST  /change-login            rodauth.change_login_path
        GET|POST  /close-account           rodauth.close_account_path
        POST      /unlock-account-request  rodauth.unlock_account_request_path
        GET|POST  /unlock-account          rodauth.unlock_account_path
        GET       /multifactor-manage      rodauth.two_factor_manage_path
        GET       /multifactor-auth        rodauth.two_factor_auth_path
        GET|POST  /multifactor-disable     rodauth.two_factor_disable_path
        GET|POST  /recovery-auth           rodauth.recovery_auth_path
        GET|POST  /recovery-codes          rodauth.recovery_codes_path

        GET|POST  /admin/login                rodauth(:admin).login_path
        GET       /admin/multifactor-manage   rodauth(:admin).two_factor_manage_path
        GET       /admin/multifactor-auth     rodauth(:admin).two_factor_auth_path
        GET|POST  /admin/multifactor-disable  rodauth(:admin).two_factor_disable_path
        GET|POST  /admin/webauthn-auth        rodauth(:admin).webauthn_auth_path
        GET|POST  /admin/webauthn-setup       rodauth(:admin).webauthn_setup_path
        GET|POST  /admin/webauthn-remove      rodauth(:admin).webauthn_remove_path
        POST      /admin/webauthn-login       rodauth(:admin).webauthn_login_path

        GET|POST  /multi/tenant//login                   rodauth(:multi_tenant).login_path
        GET|POST  /multi/tenant//create-account          rodauth(:multi_tenant).create_account_path
        GET|POST  /multi/tenant//verify-account-resend   rodauth(:multi_tenant).verify_account_resend_path
        GET|POST  /multi/tenant//verify-account          rodauth(:multi_tenant).verify_account_path
        GET|POST  /multi/tenant//remember                rodauth(:multi_tenant).remember_path
        GET|POST  /multi/tenant//logout                  rodauth(:multi_tenant).logout_path
        GET|POST  /multi/tenant//reset-password-request  rodauth(:multi_tenant).reset_password_request_path
        GET|POST  /multi/tenant//reset-password          rodauth(:multi_tenant).reset_password_path
        GET|POST  /multi/tenant//change-password         rodauth(:multi_tenant).change_password_path
        GET|POST  /multi/tenant//change-email            rodauth(:multi_tenant).change_login_path
        GET|POST  /multi/tenant//close-account           rodauth(:multi_tenant).close_account_path
        POST      /multi/tenant//unlock-account-request  rodauth(:multi_tenant).unlock_account_request_path
        GET|POST  /multi/tenant//unlock-account          rodauth(:multi_tenant).unlock_account_path
        GET|POST  /multi/tenant//multifactor-manage      rodauth(:multi_tenant).two_factor_manage_path
        GET|POST  /multi/tenant//multifactor-auth        rodauth(:multi_tenant).two_factor_auth_path
        GET|POST  /multi/tenant//multifactor-disable     rodauth(:multi_tenant).two_factor_disable_path
        GET|POST  /multi/tenant//recovery-auth           rodauth(:multi_tenant).recovery_auth_path
        GET|POST  /multi/tenant//recovery-codes          rodauth(:multi_tenant).recovery_codes_path

        POST  /jwt/login                  rodauth(:jwt).login_path
        POST  /jwt/create-account         rodauth(:jwt).create_account_path
        POST  /jwt/verify-account-resend  rodauth(:jwt).verify_account_resend_path
        POST  /jwt/verify-account         rodauth(:jwt).verify_account_path

        POST  /json/login                  rodauth(:json).login_path
        POST  /json/create-account         rodauth(:json).create_account_path
        POST  /json/verify-account-resend  rodauth(:json).verify_account_resend_path
        POST  /json/verify-account         rodauth(:json).verify_account_path
        POST  /json/multifactor-manage     rodauth(:json).two_factor_manage_path
        POST  /json/multifactor-auth       rodauth(:json).two_factor_auth_path
        POST  /json/multifactor-disable    rodauth(:json).two_factor_disable_path
    EOS

    if RUBY_ENGINE == "jruby"
      expected_output.gsub!(/^.+webauthn.+$\n/, "")
    end

    assert_equal expected_output, stdout
  end
end
